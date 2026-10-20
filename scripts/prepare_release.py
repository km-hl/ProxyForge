"""准备并校验固定 Controller 候选发布；不创建 tag、上传或部署。"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tarfile

if __package__:
    from . import agent_artifacts as artifacts
    from . import check_repository_privacy as privacy
else:
    import agent_artifacts as artifacts
    import check_repository_privacy as privacy


ROOT = Path(__file__).resolve().parents[1]
MAX_NOTES = 128 * 1024
SECTIONS = ('新增功能', '修复', '安全变更', '数据格式变化', '升级步骤',
            'Agent 与 helper', '验证与已知限制', '回滚方式')


def release_version(value):
    if value is None:
        raise ValueError('An explicit release version is required')
    version = artifacts.require_controller_release_version(value)
    try:
        subprocess.run(['git', 'check-ref-format', 'refs/tags/v' + version], check=True,
                       capture_output=True, timeout=30)
    except subprocess.CalledProcessError:
        raise ValueError('Version cannot form a Git release tag') from None
    return version


def validate_notes(encoded, version):
    if len(encoded) > MAX_NOTES:
        raise ValueError('Release notes exceed size limit')
    text = encoded.decode('utf-8-sig').replace('\r\n', '\n')
    if not text.startswith(f'# ProxyForge Controller {version} 发布说明\n'):
        raise ValueError('Release notes title/version mismatch')
    if any(marker in text for marker in ('待填写', '<<<<<<<', '=======', '>>>>>>>')):
        raise ValueError('Release notes contain unfinished content')
    headings = list(re.finditer(r'^## (.+)$', text, re.M))
    if tuple(match[1] for match in headings) != SECTIONS:
        raise ValueError('Release notes sections mismatch')
    for index, match in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[match.end():end].strip()
        if not body or not re.search(r'[\u3400-\u9fff]', body):
            raise ValueError('Every release notes section needs Chinese content')
    return encoded


def notes_from_git(repo, commit, version):
    path = f'docs/releases/{version}.md'
    entries = artifacts.git(repo, 'ls-tree', '-rz', commit, '--', path).split(b'\0')
    entries = [entry for entry in entries if entry]
    if len(entries) != 1:
        raise ValueError('Committed release notes are required')
    metadata, found = entries[0].split(b'\t', 1)
    mode, kind, oid = metadata.split()
    if found.decode('utf-8') != path or kind != b'blob' or mode not in (b'100644', b'100755'):
        raise ValueError('Release notes must be a regular committed file')
    if int(artifacts.git(repo, 'cat-file', '-s', oid.decode())) > MAX_NOTES:
        raise ValueError('Release notes exceed size limit')
    return validate_notes(artifacts.git(repo, 'cat-file', 'blob', oid.decode()), version)


def check_source_privacy(repo, commit):
    """Check selected Git objects, not the possibly different working tree."""
    for entry in artifacts.git(repo, 'ls-tree', '-rz', commit).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        path = name.decode('utf-8')
        if (path in privacy.FORBIDDEN_TRACKED_FILES or path.startswith(privacy.FORBIDDEN_TRACKED_PREFIXES)
                or kind != b'blob' or mode not in (b'100644', b'100755')):
            raise ValueError('Private or unsupported source member')
        if int(artifacts.git(repo, 'cat-file', '-s', oid.decode())) > artifacts.MAX_FILE:
            raise ValueError('Source member exceeds release scan limit')
        try:
            text = artifacts.git(repo, 'cat-file', 'blob', oid.decode()).decode('utf-8')
        except UnicodeDecodeError:
            continue
        for label, pattern in privacy.SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                if label != 'literal secret URL parameter' or not privacy.is_placeholder(match.group(1)):
                    raise ValueError('Possible private content in release source')


def metadata_for(commit, version, agent_manifest, digest, notes):
    return {
        'format': 1, 'controller_version': version, 'tag': 'v' + version,
        'source_commit': commit, 'agent_version': agent_manifest['agent_version'],
        'compatibility': agent_manifest['compatibility'],
        'agent_manifest': {'name': f'proxyforge-agent-{commit}.manifest.json', 'sha256': digest},
        'agent_archive': agent_manifest['archive'],
        'notes': {'name': 'RELEASE_NOTES.zh-CN.md', 'size': len(notes), 'sha256': artifacts.sha256(notes)},
    }


def checksums(files):
    return ''.join(f'{artifacts.sha256(content)}  {name}\n' for name, content in sorted(files.items())).encode('ascii')


def prepare(repo, commit, version, destination):
    artifacts.require_hex(commit, 40)
    version = release_version(version)
    # All notes must come from the same immutable Git objects as the code.
    # Fail before creating output for a missing, linked or unfinished document.
    notes = notes_from_git(repo, commit, version)
    check_source_privacy(repo, commit)
    archive, manifest, digest = artifacts.build(repo, commit, destination,
                                               controller_release_version=version)
    agent = artifacts.verify(archive, manifest, commit, digest, controller_release_version=version)
    metadata = artifacts.canonical_json(metadata_for(commit, version, agent, digest, notes))
    destination = Path(destination)
    files = {archive.name: archive.read_bytes(), manifest.name: manifest.read_bytes(),
             'RELEASE_NOTES.zh-CN.md': notes, 'release.json': metadata}
    for name in ('RELEASE_NOTES.zh-CN.md', 'release.json'):
        with (destination / name).open('xb') as output:
            output.write(files[name])
    with (destination / 'SHA256SUMS').open('xb') as output:
        output.write(checksums(files))
    digest = artifacts.sha256(metadata)
    verify(destination, commit, version, digest)
    return digest


def verify(destination, commit, version, metadata_sha256):
    artifacts.require_hex(commit, 40)
    artifacts.require_hex(metadata_sha256, 64)
    version = release_version(version)
    destination = Path(destination)
    if (destination / 'release.json').is_symlink():
        raise ValueError('Release metadata must be a regular file')
    encoded = artifacts.read_bounded(destination / 'release.json', artifacts.MAX_MANIFEST)
    # Pin metadata before interpreting any names or checksums from it.
    if artifacts.sha256(encoded) != metadata_sha256:
        raise ValueError('Release metadata SHA256 mismatch')
    metadata = json.loads(encoded)
    if not isinstance(metadata, dict):
        raise ValueError('Invalid release metadata')
    expected_names = {f'proxyforge-agent-{commit}.tar', f'proxyforge-agent-{commit}.manifest.json',
                      'RELEASE_NOTES.zh-CN.md', 'release.json', 'SHA256SUMS'}
    if {path.name for path in destination.iterdir()} != expected_names:
        raise ValueError('Unexpected or missing release assets')
    if any(not path.is_file() or path.is_symlink() for path in destination.iterdir()):
        raise ValueError('Release assets must be regular files')
    manifest_path = destination / f'proxyforge-agent-{commit}.manifest.json'
    manifest_digest = metadata.get('agent_manifest', {}).get('sha256') if isinstance(metadata.get('agent_manifest'), dict) else None
    agent = artifacts.verify(destination / f'proxyforge-agent-{commit}.tar', manifest_path,
                             commit, manifest_digest, controller_release_version=version)
    notes = validate_notes(artifacts.read_bounded(destination / 'RELEASE_NOTES.zh-CN.md', MAX_NOTES), version)
    expected = artifacts.canonical_json(metadata_for(commit, version, agent, manifest_digest, notes))
    if encoded != expected:
        raise ValueError('Release metadata mismatch')
    files = {name: artifacts.read_bounded(destination / name, artifacts.MAX_ARCHIVE)
             for name in expected_names - {'SHA256SUMS'}}
    if artifacts.read_bounded(destination / 'SHA256SUMS', 4096) != checksums(files):
        raise ValueError('Release asset checksums mismatch')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for operation in ('build', 'verify'):
        command = commands.add_parser(operation)
        command.add_argument('--commit', required=True)
        command.add_argument('--version', required=True)
        command.add_argument('--directory', required=True, type=Path)
        if operation == 'verify':
            command.add_argument('--metadata-sha256', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            digest = prepare(ROOT, args.commit, args.version, args.directory)
            print('Release metadata SHA256:', digest)
        else:
            verify(args.directory, args.commit, args.version, args.metadata_sha256)
            print('Candidate release assets verified; nothing published.')
    except (ValueError, OSError, SyntaxError, RecursionError, tarfile.TarError, subprocess.SubprocessError):
        parser.exit(1, 'Release preparation failed; nothing published or deployed.\n')


if __name__ == '__main__':
    main()
