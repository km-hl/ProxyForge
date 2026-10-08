"""Build and verify fixed-commit Agent packages. See docs/AGENT_ARTIFACTS.md."""

import argparse
import ast
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_FILE = 1024 * 1024
AGENT_FILES = (
    "__init__.py", "chain_spec.py", "client.py", "deployment_spec.py",
    "install-runtime.sh", "install.sh", "job_lease.py", "jobs.py",
    "landing_spec.py", "main.py", "proxyforge-agent.service",
    "proxyforge-runtime.service", "proxyforge-runtime.socket",
    "proxyforge-singbox.service", "README.md", "README.zh-CN.md",
    "runtime_client.py", "runtime_download.py", "runtime_engine.py",
    "runtime_helper.py", "runtime_spec.py", "singbox-release.json",
    "system_info.py", "install-compatibility.json",
)
DOC_FILES = (
    "AGENT_ARTIFACTS.md", "AGENT_INSTALL.md", "AGENT_INSTALL_HELP.md", "AGENT_B1.md", "AGENT_B2.md", "AGENT_B3.md",
    "AGENT_B4.md", "AGENT_B5_LANDING.md", "AGENT_B5_CHAIN.md",
    "RELEASE_ACCEPTANCE.md", "PYTHON_RUNTIME.md", "DEPENDENCIES.md",
    "CONTAINER_PERMISSIONS.md",
)
FILES = tuple(sorted(["agent/" + name for name in AGENT_FILES]
                     + ["docs/" + name for name in DOC_FILES]))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def require_hex(value, length):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
        raise ValueError("Expected a full lowercase hexadecimal identity")
    return value


def read_bounded(path, limit):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Artifact exceeds size limit")
    return data


def git(repo, *args):
    return subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    ).stdout


def source_files(repo, commit):
    require_hex(commit, 40)
    if git(repo, "cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("Source identity is not a commit")
    entries = {}
    for entry in git(repo, "ls-tree", "-rz", commit, "--", "agent", "docs").split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        entries[path.decode("utf-8")] = (mode, kind, oid)
    files = {}
    for path in FILES:
        mode, kind, oid = entries.get(path, (None, None, None))
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError("Required package member missing or not a regular Git file: " + path)
        if int(git(repo, "cat-file", "-s", oid.decode())) > MAX_FILE:
            raise ValueError("Source file exceeds size limit")
        files[path] = git(repo, "cat-file", "blob", oid.decode())
    return files


def package_metadata(files):
    # Parse literals without importing or executing the selected commit's code.
    values = {}
    for node in ast.parse(files["agent/__init__.py"].decode("utf-8")).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ("VERSION", "PROTOCOL_VERSION"):
                values[target.id] = ast.literal_eval(node.value)
    version = values.get("VERSION")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid Agent software version")
    compatibility = json.loads(files["agent/install-compatibility.json"])
    # This contract describes the current installer, not a promise about future
    # or older Controllers. Changing support requires reviewing this verifier.
    expected = {
        "python_minimum": "3.9", "controller_schema_baseline": 5,
        "protocols": {name: 1 for name in ("inventory", "jobs", "runtime", "deployment", "landing", "chain")},
        "platforms": {"debian": ["12", "13"], "ubuntu": ["22.04", "24.04"]},
        "architectures": ["amd64", "arm64"], "service_manager": "systemd",
        "runtime_helper_enabled_by_default": False,
    }
    if canonical_json(compatibility) != canonical_json(expected) or values.get("PROTOCOL_VERSION") != 1:
        raise ValueError("Unsupported installation compatibility contract")
    return version, compatibility


def canonical_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def archive_bytes(files):
    output = io.BytesIO()
    # Uncompressed USTAR avoids gzip timestamps and compressor-version drift.
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in FILES:
            info = tarfile.TarInfo(path)
            info.size = len(files[path])
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(files[path]))
    result = output.getvalue()
    if len(result) > MAX_ARCHIVE:
        raise ValueError("Package exceeds size limit")
    return result


def manifest_for(commit, files, archive):
    version, compatibility = package_metadata(files)
    return {
        "format": 1, "source_commit": commit,
        "agent_version": version, "controller_release_version": None,
        "controller_source_commit": commit, "compatibility": compatibility,
        "archive": {"name": "proxyforge-agent-" + commit + ".tar",
                    "size": len(archive), "sha256": sha256(archive)},
        "files": {path: {"size": len(files[path]), "sha256": sha256(files[path]), "mode": "0644"}
                  for path in FILES},
    }


def build(repo, commit, destination):
    files = source_files(repo, commit)
    archive = archive_bytes(files)
    manifest = manifest_for(commit, files, archive)
    encoded = canonical_json(manifest)
    # A new directory is required: never replace another build or installation.
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    archive_path = destination / manifest["archive"]["name"]
    manifest_path = destination / ("proxyforge-agent-" + commit + ".manifest.json")
    with archive_path.open("xb") as output:
        output.write(archive)
    with manifest_path.open("xb") as output:
        output.write(encoded)
    return archive_path, manifest_path, sha256(encoded)


def verify(archive_path, manifest_path, commit, manifest_sha256):
    require_hex(commit, 40)
    require_hex(manifest_sha256, 64)
    encoded = read_bounded(manifest_path, MAX_MANIFEST)
    # Pin the manifest before parsing it or interpreting any archive metadata.
    if sha256(encoded) != manifest_sha256:
        raise ValueError("Manifest SHA256 mismatch")
    manifest = json.loads(encoded)
    if not isinstance(manifest, dict) or manifest.get("source_commit") != commit:
        raise ValueError("Manifest source commit mismatch")
    archive = read_bounded(archive_path, MAX_ARCHIVE)
    descriptor = manifest.get("archive")
    if not isinstance(descriptor, dict) or descriptor.get("sha256") != sha256(archive):
        raise ValueError("Archive SHA256 mismatch")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for member in source:
            # Never extract: reject links, devices, directories, duplicate names,
            # traversal and unknown files before reading any member content.
            if (member.name not in FILES or member.name in files or not member.isfile()
                    or member.type != tarfile.REGTYPE or member.pax_headers
                    or member.linkname or not 0 <= member.size <= MAX_FILE):
                raise ValueError("Invalid archive member")
            with source.extractfile(member) as content:
                files[member.name] = content.read(MAX_FILE + 1)
            if len(files[member.name]) != member.size:
                raise ValueError("Truncated archive member")
    if set(files) != set(FILES):
        raise ValueError("Incomplete Agent package")
    # Enforce exactly one canonical tar, including modes, owners, ordering and
    # end padding. This also rejects hidden extension headers/trailing payloads.
    if archive_bytes(files) != archive:
        raise ValueError("Noncanonical archive")
    expected = canonical_json(manifest_for(commit, files, archive))
    if expected != encoded:
        raise ValueError("Manifest metadata or member checksums mismatch")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build", help="Build exclusively from Git objects")
    builder.add_argument("--commit", required=True)
    builder.add_argument("--output-dir", required=True, type=Path)
    verifier = commands.add_parser("verify", help="Verify only; does not extract or install")
    verifier.add_argument("--commit", required=True)
    verifier.add_argument("--manifest-sha256", required=True)
    verifier.add_argument("--archive", required=True, type=Path)
    verifier.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "build":
            archive, manifest, digest = build(ROOT, args.commit, args.output_dir)
            print("Archive:", archive)
            print("Manifest:", manifest)
            print("Manifest SHA256:", digest)
        else:
            manifest = verify(args.archive, args.manifest, args.commit, args.manifest_sha256)
            print("Verified Agent", manifest["agent_version"], "commit", manifest["source_commit"])
    except (ValueError, OSError, SyntaxError, tarfile.TarError, subprocess.SubprocessError):
        # Do not echo arbitrary JSON, tar member names or external command errors.
        parser.exit(1, "Agent artifact operation failed; no extraction or installation performed.\n")


if __name__ == "__main__":
    main()
