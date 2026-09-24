"""Bounded HTTPS transport. Never include response bodies/URLs in errors."""
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request


class AgentConnectionError(Exception):
    pass


class CredentialRejected(AgentConnectionError):
    pass


class JobRejected(AgentConnectionError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def controller_url(value, allow_insecure=False):
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ({"https", "http"} if allow_insecure else {"https"}):
        raise ValueError("Controller requires HTTPS (HTTP is development-only)")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Invalid controller URL")
    if parsed.path not in ("", "/"):
        raise ValueError("Controller must be hosted at the origin root")
    if parsed.port == 0:
        raise ValueError("Invalid controller port")
    return value.rstrip("/")


class Client:
    def __init__(self, server, allow_insecure=False, ca_file=None):
        self.server = controller_url(server, allow_insecure)
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))

    def post(self, path, payload, token=None):
        if path not in ("/api/agent/register", "/api/agent/heartbeat", "/api/agent/jobs/claim") and not re.fullmatch(
                r'/api/agent/jobs/[a-f0-9]{32}/(start|result)', path):
            raise ValueError("Unsupported Agent endpoint")
        content = json.dumps(payload).encode("utf-8")
        if len(content) > 16384:
            raise AgentConnectionError("Agent request too large")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.server + path, data=content, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise AgentConnectionError("Controller response too large")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ValueError()
                return result
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise CredentialRejected("Credential rejected; register again with a new token") from None
            if exc.code in (404, 409):
                raise JobRejected("Job no longer available") from None
            raise AgentConnectionError("Controller request failed (HTTP %d)" % exc.code) from None
        except (OSError, ValueError, urllib.error.URLError):
            raise AgentConnectionError("Unable to contact Controller or invalid response") from None
