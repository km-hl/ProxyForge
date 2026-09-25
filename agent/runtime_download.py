"""Pinned, bounded HTTPS downloads; extract only the regular sing-box binary."""
import hashlib
import os
from pathlib import Path
import tarfile
import time
import urllib.parse
import urllib.request

from .runtime_spec import RELEASE

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 160 * 1024 * 1024
DOWNLOAD_SECONDS = 300


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != 'https' or parsed.hostname not in ('github.com', 'release-assets.githubusercontent.com') or
                parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise ValueError('Untrusted release redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def extract_binary(archive, destination, arch):
    asset = RELEASE['assets'][arch]
    checksum = hashlib.sha256()
    with Path(archive).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            checksum.update(block)
    if checksum.hexdigest() != asset['sha256']:
        raise ValueError('Release checksum mismatch')
    expected = 'sing-box-' + RELEASE['version'] + '-linux-' + arch + '/sing-box'
    with tarfile.open(archive, 'r:gz') as package:
        found = False
        for count, member in enumerate(package):
            if count > 64:
                raise ValueError('Unexpected archive layout')
            if member.name != expected:
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


def download_binary(directory, arch, guard=lambda: None):
    asset = RELEASE['assets'][arch]
    url = 'https://github.com/SagerNet/sing-box/releases/download/v' + RELEASE['version'] + '/' + asset['name']
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
        extract_binary(archive, Path(directory) / 'sing-box', arch)
    finally:
        archive.unlink(missing_ok=True)
