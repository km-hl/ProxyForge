"""Check positive and negative fixtures with the pinned real Mihomo parser."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[1] / "tests/mihomo"


def load_cases(directory):
    cases = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("Fixture manifest must be a non-empty list")
    names = []
    for case in cases:
        name = case["file"]
        if not isinstance(name, str) or Path(name).name != name or not name.endswith(".yaml"):
            raise ValueError("Fixture paths must be YAML basenames")
        if type(case["exit_code"]) is not int or case["exit_code"] not in (0, 1):
            raise ValueError(f"Invalid expected exit code: {name}")
        if case["exit_code"] == 1 and not case.get("error_contains"):
            raise ValueError(f"Negative fixture needs an expected diagnostic: {name}")
        names.append(name)
    if len(set(names)) != len(names):
        raise ValueError("Duplicate fixtures in manifest")
    if set(names) != {path.name for path in directory.glob("*.yaml")}:
        raise ValueError("Manifest must list every YAML fixture exactly once")
    return cases


def invoke(command, cwd, timeout):
    # A developer's CLASH_CONFIG_STRING or overrides must not replace a fixture.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CLASH_", "MIHOMO_"))}
    try:
        result = subprocess.run(command, cwd=cwd, env=env, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", check=False)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return None, output + f"\nTIMEOUT after {timeout} seconds\n"
    except OSError as exc:
        return None, f"Unable to launch Mihomo: {exc}\n"


def matches(case, code, output):
    if code != case["exit_code"]:
        return False
    if code == 0:
        return "test is successful" in output
    # A crash, download failure or unrelated parser error is not a passing
    # negative test, even if it happens to return exit status 1.
    return "test failed" in output and case["error_contains"] in output


def check(binary, fixtures, log_dir, timeout):
    release = json.loads((FIXTURES / "release.json").read_text(encoding="utf-8"))
    cases = load_cases(fixtures)
    binary, log_dir = binary.resolve(), log_dir.resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="proxyforge-mihomo-") as directory:
        root = Path(directory)
        code, version = invoke([str(binary), "-v"], root, timeout)
        (log_dir / "version.log").write_text(version, encoding="utf-8")
        expected = rf"Mihomo Meta {re.escape(release['version'])}(?:\s|$)"
        if code != 0 or not re.search(expected, version):
            print(f"FAIL: expected Mihomo {release['version']}\n{version}")
            return 1
        print(version.strip())
        for case in cases:
            fixture = (fixtures / case["file"]).resolve()
            # Each process gets an empty home; no downloaded geodata/provider
            # cache from a previous case can hide an accidental dependency.
            home = root / fixture.stem
            home.mkdir()
            command = [str(binary), "-t", "-d", str(home), "-f", str(fixture)]
            code, output = invoke(command, home, timeout)
            passed = matches(case, code, output)
            (log_dir / (fixture.stem + ".log")).write_text(
                f"command: {json.dumps(command)}\nexit_code: {code}\n{output}", encoding="utf-8")
            results.append({"file": case["file"], "expected_exit_code": case["exit_code"],
                            "actual_exit_code": code, "passed": passed})
            print(f"{'PASS' if passed else 'FAIL'} {case['file']} (exit={code}, expected={case['exit_code']})")
            if not passed:
                print(output)
    (log_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    failures = sum(not result["passed"] for result in results)
    print(f"Mihomo: {len(results) - failures}/{len(results)} fixture expectations passed")
    return int(bool(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    parser.add_argument("--log-dir", type=Path, default=Path("test-results/mihomo"))
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be between 0 (exclusive) and 300 seconds")
    try:
        return check(args.binary, args.fixtures, args.log_dir, args.timeout)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Mihomo test setup failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
