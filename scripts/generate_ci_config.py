"""Generate a public CI sample using the real application subscription builder.

Development-only, single-process helper. Import-time runtime storage is confined
to a temporary working directory; the developer's .env and data are never loaded.
"""

import argparse
import contextlib
import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "tests/mihomo/generation"
MODULE_NAME = "_proxyforge_ci_generator_main"


@contextlib.contextmanager
def isolated_application():
    """Load main.py normally, with only environment/storage isolation patched."""
    with tempfile.TemporaryDirectory(prefix="proxyforge-ci-generator-") as directory:
        runtime = Path(directory)
        (runtime / "static").mkdir()
        (runtime / "template.example.yaml").write_text("proxy-groups: []\nrules: []\n", encoding="utf-8")
        spec = importlib.util.spec_from_file_location(MODULE_NAME, ROOT / "main.py")
        module = importlib.util.module_from_spec(spec)
        previous_cwd = Path.cwd()
        previous_module = sys.modules.get(MODULE_NAME)
        try:
            os.chdir(runtime)
            sys.modules[MODULE_NAME] = module
            with patch.object(sys, "path", [str(ROOT), *sys.path]), \
                    patch.dict(os.environ, {"SECRET_TOKEN": "integration-test-token",
                                            "ADMIN_TOKEN": "integration-management-token"}), \
                    patch("dotenv.load_dotenv", return_value=False), \
                    contextlib.redirect_stdout(sys.stderr):
                spec.loader.exec_module(module)
                yield module
        finally:
            os.chdir(previous_cwd)
            if previous_module is None:
                sys.modules.pop(MODULE_NAME, None)
            else:
                sys.modules[MODULE_NAME] = previous_module


def managed_sample():
    from agent.deployment_spec import client_node
    # Public, deterministic parser fixture, never a deployed credential or private key.
    import base64
    return client_node('a' * 32, 'b' * 32, {
        'name': 'Managed Reality CI', 'server': 'vps.example.com',
        'server_name': 'www.example.com', 'listen_port': 443,
        'uuid': '11111111-1111-4111-8111-111111111111', 'short_id': '0123456789abcdef',
        'public_key': base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')})


def build_sample(application):
    template = yaml.safe_load((INPUTS / "sample-template.yaml").read_text(encoding="utf-8"))
    nodes = yaml.safe_load((INPUTS / "nodes.yaml").read_text(encoding="utf-8"))
    # Exercise the same client projection used after a managed deployment succeeds.
    nodes.append(managed_sample())
    # No airports: this sample cannot contain a subscription URL or real token.
    # Do not mock, copy or extract the builder or either static validation gate.
    return application.build_subscription_config(
        template, nodes, [], "https://proxyforge.example", "test-token")


def generate():
    with isolated_application() as application:
        config = build_sample(application)
        return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def main():
    # Keep redirected YAML and import-time diagnostics consistently UTF-8 on
    # Windows too; no locale-dependent bytes should enter CI artifacts/logs.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write UTF-8 YAML here; defaults to stdout")
    args = parser.parse_args()
    # Resolve relative output paths before entering the temporary working directory.
    output = args.output.resolve() if args.output else None
    content = generate()
    if output is None:
        sys.stdout.write(content)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
