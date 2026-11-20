"""Pinned, bounded HTTPS downloads; extract only verified regular binaries."""
import hashlib
import os
from pathlib import Path
import tarfile
import time
import urllib.parse
import urllib.request

from .runtime_spec import CADDY_RELEASE, GOST_RELEASE, RELEASE

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 160 * 1024 * 1024
DOWNLOAD_SECONDS = 300
TRUSTED_RELEASE_HOSTS = (
    'github.com',
    'release-assets.githubusercontent.com',
    'objects.githubusercontent.com',
)


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts=TRUSTED_RELEASE_HOSTS):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != 'https' or (self.allowed_hosts is not None and parsed.hostname not in self.allowed_hosts) or
                parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise ValueError('Untrusted release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


MIRROR_CONFIG_FILENAME = 'gh-proxy'


def normalize_mirror_prefix(mirror_prefix):
    if not mirror_prefix:
        return None
    if not isinstance(mirror_prefix, str):
        raise ValueError('Invalid mirror URL')
    raw = mirror_prefix.strip()
    if not raw:
        return None
    if any(ord(c) <= 32 for c in raw) or '@' in raw or '?' in raw or '#' in raw:
        raise ValueError('Mirror URL must be a plain https:// URL')
    if '://' not in raw:
        if raw.startswith('/') or ':' in raw.split('/', 1)[0]:
            raise ValueError('Mirror URL must be a plain https:// URL')
        raw = 'https://' + raw
    parsed = urllib.parse.urlsplit(raw)
    if (parsed.scheme != 'https' or not parsed.hostname or '.' not in parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Mirror URL must be a plain https:// URL')
    return raw.rstrip('/')


def read_configured_mirror(root):
    """Read optional root-owned GitHub mirror prefix from <runtime_root>/gh-proxy."""
    if root is not None:
        path = Path(root) / MIRROR_CONFIG_FILENAME
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if path.is_symlink() or not path.is_file():
                raise ValueError('Invalid mirror config file')
            if os.name == 'posix' and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError('Mirror config file must be root-owned and not group/world writable')
            for line in path.read_text(encoding='utf-8').splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    return normalize_mirror_prefix(stripped)
            return None
    env_mirror = os.environ.get('PROXYFORGE_GH_PROXY', '').strip()
    return normalize_mirror_prefix(env_mirror) if env_mirror else None


def _resolve_mirror_url(url, mirror_prefix):
    prefix = normalize_mirror_prefix(mirror_prefix)
    if not prefix:
        return url, TRUSTED_RELEASE_HOSTS
    return prefix + '/' + url, None


def verify_sha256(archive, expected_sha256):
    checksum = hashlib.sha256()
    with Path(archive).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            checksum.update(block)
    if checksum.hexdigest() != expected_sha256:
        raise ValueError('Release checksum mismatch')


def extract_release_binary(archive, destination, expected_sha256, member_names):
    verify_sha256(archive, expected_sha256)
    expected = (member_names,) if isinstance(member_names, str) else tuple(member_names)
    if not expected:
        raise ValueError('Missing expected binary path')
    with tarfile.open(archive, 'r:gz') as package:
        found = False
        for count, member in enumerate(package):
            if count > 64:
                raise ValueError('Unexpected archive layout')
            if member.name not in expected:
                continue
            if found or not member.isfile() or not 0 < member.size <= MAX_BINARY:
                raise ValueError('Invalid release binary')
            found = True
            with package.extractfile(member) as source, Path(destination).open('xb') as output:
                remaining = member.size
                while remaining:
                    data = source.read(min(1024 * 1024, remaining))
                    if not data:
                        raise ValueError('Truncated binary')
                    output.write(data)
                    remaining -= len(data)
                output.flush()
                os.fsync(output.fileno())
        if not found:
            raise ValueError('Missing release binary')
    Path(destination).chmod(0o755)


def download_release_binary(directory, url, expected_sha256, member_names, binary_name, guard=lambda: None, *, mirror_prefix=None):
    target_url, allowed_hosts = _resolve_mirror_url(url, mirror_prefix)
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme != 'https' or (allowed_hosts is not None and parsed.hostname not in allowed_hosts):
        raise ValueError('Untrusted release URL')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect(allowed_hosts))
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    archive = Path(directory) / 'release.tar.gz'
    try:
        request = urllib.request.Request(target_url, headers={'User-Agent': 'ProxyForge-runtime'})
        with opener.open(request, timeout=15) as response, archive.open('xb') as output:
            total = 0
            while True:
                guard()
                if time.monotonic() >= deadline:
                    raise TimeoutError('Release download exceeded deadline')
                # read1 returns available data instead of waiting to fill the
                # whole block, so liveness/deadline checks also run on slow streams.
                data = response.read1(128 * 1024)
                if not data:
                    break
                total += len(data)
                if total > MAX_ARCHIVE:
                    raise ValueError('Release exceeds limit')
                output.write(data)
        guard()
        extract_release_binary(archive, Path(directory) / binary_name, expected_sha256, member_names)
    finally:
        archive.unlink(missing_ok=True)


def extract_binary(archive, destination, arch):
    asset = RELEASE['assets'][arch]
    expected = 'sing-box-' + RELEASE['version'] + '-linux-' + arch + '/sing-box'
    extract_release_binary(archive, destination, asset['sha256'], expected)


def download_binary(directory, arch, guard=lambda: None, *, mirror_prefix=None):
    asset = RELEASE['assets'][arch]
    url = 'https://github.com/SagerNet/sing-box/releases/download/v' + RELEASE['version'] + '/' + asset['name']
    expected = 'sing-box-' + RELEASE['version'] + '-linux-' + arch + '/sing-box'
    download_release_binary(directory, url, asset['sha256'], expected, 'sing-box', guard, mirror_prefix=mirror_prefix)


def extract_caddy_binary(archive, destination, arch):
    asset = CADDY_RELEASE['assets'][arch]
    extract_release_binary(archive, destination, asset['sha256'], ('caddy', './caddy'))


def download_caddy_binary(directory, arch, guard=lambda: None, *, mirror_prefix=None):
    asset = CADDY_RELEASE['assets'][arch]
    url = 'https://github.com/caddyserver/caddy/releases/download/v' + CADDY_RELEASE['version'] + '/' + asset['name']
    download_release_binary(directory, url, asset['sha256'], ('caddy', './caddy'), 'caddy', guard, mirror_prefix=mirror_prefix)


def extract_gost_binary(archive, destination, arch):
    asset = GOST_RELEASE['assets'][arch]
    extract_release_binary(archive, destination, asset['sha256'], ('gost', './gost'))


def download_gost_binary(directory, arch, guard=lambda: None, *, mirror_prefix=None):
    asset = GOST_RELEASE['assets'][arch]
    url = 'https://github.com/go-gost/gost/releases/download/v' + GOST_RELEASE['version'] + '/' + asset['name']
    download_release_binary(directory, url, asset['sha256'], ('gost', './gost'), 'gost', guard, mirror_prefix=mirror_prefix)
