"""Isolated real-TTY preflight regression; never downloads or installs anything."""
import os
from pathlib import Path
import pty
import pwd
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts import agent_bootstrap as bootstrap


def check():
    # Only host inventory is simulated. Keep the preflight and /dev/tty open real.
    with patch.object(bootstrap.os, "geteuid", return_value=0), \
            patch.object(bootstrap.platform, "system", return_value="Linux"), \
            patch.object(bootstrap.platform, "machine", return_value="x86_64"), \
            patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
            patch.object(Path, "is_dir", return_value=True), \
            patch.object(bootstrap, "trusted_directory"), \
            patch.object(bootstrap.os.path, "lexists", return_value=False), \
            patch.object(pwd, "getpwnam", side_effect=KeyError), \
            patch.object(bootstrap.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"not-found\n")):
        bootstrap.preflight("install", "https://controller.example")


if sys.argv[1] == "no-tty":
    try:
        check()
    except OSError:
        print("preflight rejected absent TTY")
    else:
        raise AssertionError("missing controlling TTY accepted")
else:
    child, master = pty.fork()
    if child == 0:
        try:
            check()
            print("preflight accepted real TTY", flush=True)
        except BaseException:
            import traceback
            traceback.print_exc()
            os._exit(1)
        os._exit(0)
    try:
        while True:
            try:
                block = os.read(master, 4096)
            except OSError:
                break
            if not block:
                break
            sys.stdout.buffer.write(block)
    finally:
        os.close(master)
    _, status = os.waitpid(child, 0)
    sys.exit(os.waitstatus_to_exitcode(status))
