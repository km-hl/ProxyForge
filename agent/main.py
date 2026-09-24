"""python3 -m agent.main --config /etc/proxyforge-agent/config.json register|run"""
import argparse
import json
import os
from pathlib import Path
import random
import re
import secrets
import sys
import time
import uuid

from .client import Client, AgentConnectionError, CredentialRejected
from .system_info import collect


def save_config(path, config):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(config, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
            directory = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def load_config(path):
    path = Path(path)
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("Agent config must have mode 0600")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid Agent configuration")
    return value


def register(path, server, registration_token, allow_insecure=False, ca_file=None):
    if Path(path).exists() and load_config(path).get("token"):
        raise ValueError("Already registered; revoke the old Agent before replacing its local config")
    if not re.fullmatch(r"pfreg_[A-Za-z0-9_-]{43}", registration_token):
        raise ValueError("Invalid registration token format")
    client = Client(server, allow_insecure, ca_file)
    instance_id = uuid.uuid4().hex
    pending = {"controller": client.server, "instance_id": instance_id,
               "allow_insecure": allow_insecure, "ca_file": ca_file}
    save_config(path, pending)
    payload = {**collect(instance_id), "registration_token": registration_token}
    # Deliberately no automatic retry: server may have consumed this token.
    result = client.post("/api/agent/register", payload)
    agent_id, agent_token = result.get("agent_id"), result.get("agent_token")
    if not isinstance(agent_id, str) or not isinstance(agent_token, str) or not re.fullmatch(
            r"[a-f0-9]{32}", agent_id) or not re.fullmatch(r"pfagt_[A-Za-z0-9_-]{43}", agent_token):
        raise AgentConnectionError("Invalid registration response; inspect the Controller and issue a new token")
    save_config(path, {**pending, "agent_id": result["agent_id"], "token": result["agent_token"]})


def run(path, once=False):
    config = load_config(path)
    if not config.get("token"):
        raise ValueError("Registration incomplete; remove any orphan Agent and issue a new registration token")
    client = Client(config["controller"], config.get("allow_insecure", False), config.get("ca_file"))
    failures = 0
    while True:
        try:
            result = client.post("/api/agent/heartbeat", collect(config["instance_id"]), config["token"])
            failures = 0
            if not result.get("compatible", False):
                print("Agent protocol incompatible; inventory only, update required", file=sys.stderr)
            if once:
                return 0
            time.sleep(30 + random.uniform(0, 3))
        except CredentialRejected:
            print("Agent credential revoked/rejected; synchronization stopped", file=sys.stderr)
            return 4
        except AgentConnectionError:
            if once:
                return 1
            failures = min(failures + 1, 6)
            print("Heartbeat unavailable; retrying with backoff", file=sys.stderr)
            time.sleep(min(300, 5 * 2 ** failures) + random.uniform(0, 3))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/proxyforge-agent/config.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    enrollment = commands.add_parser("register")
    enrollment.add_argument("--server", required=True)
    enrollment.add_argument("--token-stdin", action="store_true", required=True)
    enrollment.add_argument("--allow-insecure", action="store_true", help="HTTP for development only")
    enrollment.add_argument("--ca-file")
    runtime = commands.add_parser("run")
    runtime.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "register":
            if args.allow_insecure:
                print("WARNING: insecure HTTP is for development only", file=sys.stderr)
            token = sys.stdin.readline(256).strip()
            register(args.config, args.server, token, args.allow_insecure, args.ca_file)
            print("Agent registered; credentials saved privately")
            return 0
        return run(args.config, args.once)
    except (AgentConnectionError, ValueError, OSError, KeyError):
        # Avoid urllib errors, payloads, filenames and credentials in logs.
        print("Agent operation failed. If enrollment was attempted, inspect/remove any orphan "
              "Agent and issue a new token before retrying.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
