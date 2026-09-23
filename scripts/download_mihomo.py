"""Download the pinned official Linux amd64 CI binary (standard library only)."""

import argparse
import gzip
import hashlib
import json
import shutil
import tempfile
import urllib.request
from pathlib import Path


RELEASE_FILE = Path(__file__).resolve().parents[1] / "tests/mihomo/release.json"


def verify_archive(archive, expected):
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError("Mihomo archive SHA256 mismatch; refusing to extract")


def download(destination):
    release = json.loads(RELEASE_FILE.read_text(encoding="utf-8"))
    url = ("https://github.com/MetaCubeX/mihomo/releases/download/"
           f"{release['version']}/{release['asset']}")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Extract only after checksum verification; publish atomically so failed
    # downloads never leave a partial executable at the requested destination.
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        archive = Path(directory) / "mihomo.gz"
        request = urllib.request.Request(url, headers={"User-Agent": "ProxyForge-CI"})
        with urllib.request.urlopen(request, timeout=60) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
        verify_archive(archive, release["sha256"])
        binary = Path(directory) / "mihomo"
        with gzip.open(archive, "rb") as source, binary.open("wb") as output:
            shutil.copyfileobj(source, output)
        binary.chmod(0o755)
        binary.replace(destination)
    print(f"Verified {release['asset']} SHA256 {release['sha256']}")
    print(f"Installed {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    download(parser.parse_args().output)
