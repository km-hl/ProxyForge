"""Pinned, bounded HTTPS downloads; extract only verified regular binaries."""
import hashlib
import os
from pathlib import Path
import tarfile
import time
import urllib.parse
import urllib.request

from .runtime_spec import CADDY_RELEASE, RELEASE

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 160 * 1024 * 1024
DOWNLOAD_SECONDS = 300
TRUSTED_RELEASE_HOSTS = (
    'github.com',
    'release-assets.githubusercontent.com',
    'objects.githubusercontent.com',
)


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != 'https' or parsed.hostname not in TRUSTED_RELEASE_HOSTS or
                parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise ValueError('Untrusted release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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


def download_release_binary(directory, url, expected_sha256, member_names, binary_name, guard=lambda: None):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in TRUSTED_RELEASE_HOSTS:
        raise ValueError('Untrusted release URL')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    archive = Path(directory) / 'release.tar.gz'
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'ProxyForge-runtime'})
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


def download_binary(directory, arch, guard=lambda: None):
    asset = RELEASE['assets'][arch]
    url = 'https://github.com/SagerNet/sing-box/releases/download/v' + RELEASE['version'] + '/' + asset['name']
    expected = 'sing-box-' + RELEASE['version'] + '-linux-' + arch + '/sing-box'
    download_release_binary(directory, url, asset['sha256'], expected, 'sing-box', guard)


def extract_caddy_binary(archive, destination, arch):
    asset = CADDY_RELEASE['assets'][arch]
    extract_release_binary(archive, destination, asset['sha256'], ('caddy', './caddy'))


def download_caddy_binary(directory, arch, guard=lambda: None):
    asset = CADDY_RELEASE['assets'][arch]
    url = 'https://github.com/caddyserver/caddy/releases/download/v' + CADDY_RELEASE['version'] + '/' + asset['name']
    download_release_binary(directory, url, asset['sha256'], ('caddy', './caddy'), 'caddy', guard)
