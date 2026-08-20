"""Fail CI when private runtime files or common secret formats enter a commit."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_TRACKED_FILES = {
    ".env",
    "HANDOFF.md",
    "AGENTS.md",
    "CLAUDE.md",
    "custom_nodes.yaml",
    "template.yaml",
}
FORBIDDEN_TRACKED_PREFIXES = ("data/",)
TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".service",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
ALLOWED_PLACEHOLDER_VALUES = {
    "<token>",
    "changeme",
    "example",
    "integration-test-token",
    "my_secret_token",
    "redacted",
    "test-token",
    "your_token",
}
SECRET_PATTERNS = {
    "private key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "GitHub token": re.compile(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "OpenAI-style secret": re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"),
    "literal secret URL parameter": re.compile(
        r"https?://[^\s\"'<>]+[?&](?:token|secret|api_key|apikey|key)=([^&\s\"'<>]+)",
        re.IGNORECASE,
    ),
}


def git_paths(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]


def is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    return (
        normalized in ALLOWED_PLACEHOLDER_VALUES
        or normalized.startswith("${")
        or normalized.startswith("{{")
        or normalized.startswith("your_")
        or re.fullmatch(r"\{[a-z_][a-z0-9_]*\}", normalized) is not None
    )


def main() -> int:
    tracked = set(git_paths("ls-files"))
    candidates = set(git_paths("ls-files", "--cached", "--others", "--exclude-standard"))
    findings: list[str] = []

    for path in sorted(tracked):
        if path in FORBIDDEN_TRACKED_FILES or path.startswith(FORBIDDEN_TRACKED_PREFIXES):
            findings.append(f"forbidden runtime/private path is tracked: {path}")

    for relative in sorted(candidates):
        path = ROOT / relative
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for label, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                if label == "literal secret URL parameter" and is_placeholder(match.group(1)):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: possible {label}")

    if findings:
        print("Repository privacy check failed:", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1

    print(
        "Repository privacy check passed "
        f"({len(tracked)} tracked paths and {len(candidates - tracked)} untracked candidates checked)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
