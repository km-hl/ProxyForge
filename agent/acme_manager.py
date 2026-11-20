"""Pure-stdlib ACME certificate issuance, DNS-01 credentials and redacted renewal."""
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone
import urllib.request

from .runtime_engine import sync_directory

ACME_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
DEFAULT_STATE_DIR = Path('/var/lib/proxyforge-runtime/acme')
DEFAULT_RENEWAL_WINDOW = 30 * 86400
MAX_CERT_BYTES = 256 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 1024
PROFILE_PATTERN = re.compile(r'(?:cf|alidns|dnspod)-[0-9a-f]{16}\Z')
CERT_NAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')

DNS_PROVIDERS = {
    'cloudflare': {
        'prefix': 'cf',
        'plugin': 'dns-cloudflare',
        'package_hint': 'python3-certbot-dns-cloudflare',
        'flag': '--dns-cloudflare',
        'cred_flag': '--dns-cloudflare-credentials',
        'prop_flag': '--dns-cloudflare-propagation-seconds',
        'ini_key': 'dns_cloudflare_api_token',
        'env_prefixes': ('CLOUDFLARE_', 'CF_'),
        'token_pattern': re.compile(r'[A-Za-z0-9_-]{20,256}\Z'),
        'zone_pattern': re.compile(r'[0-9a-fA-F]{32}\Z'),
    },
    'alidns': {
        'prefix': 'alidns',
        'plugin': 'dns-aliyun',
        'package_hint': 'certbot-dns-aliyun',
        'flag': '--dns-aliyun',
        'cred_flag': '--dns-aliyun-credentials',
        'prop_flag': '--dns-aliyun-propagation-seconds',
        'ini_key': 'dns_aliyun_access_key_secret',
        'env_prefixes': ('ALICLOUD_', 'ALIYUN_'),
        'token_pattern': re.compile(r'[A-Za-z0-9_=-]{16,256}\Z'),
        'zone_pattern': None,
    },
    'dnspod': {
        'prefix': 'dnspod',
        'plugin': 'dns-dnspod',
        'package_hint': 'certbot-dns-dnspod',
        'flag': '--dns-dnspod',
        'cred_flag': '--dns-dnspod-credentials',
        'prop_flag': '--dns-dnspod-propagation-seconds',
        'ini_key': 'dns_dnspod_api_token',
        'env_prefixes': ('DNSPOD_', 'DP_'),
        'token_pattern': re.compile(r'[A-Za-z0-9_,:-]{12,256}\Z'),
        'zone_pattern': None,
    },
}


class AcmeError(ValueError):
    """Sanitized certificate or ACME operation failure."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _RedactedStream:
    """Wrap stdout/stderr to scrub secret values before emission."""

    def __init__(self, stream, secrets):
        self.stream = stream
        self.secrets = tuple(s for s in secrets if s)

    def write(self, value):
        cleaned = value
        for secret in self.secrets:
            cleaned = cleaned.replace(secret, '[REDACTED]')
        return self.stream.write(cleaned)

    def flush(self):
        return self.stream.flush()

    def __getattr__(self, key):
        return getattr(self.stream, key)


def _private_dir(path):
    directory = Path(path)
    if directory.is_symlink():
        raise AcmeError('Refusing symlinked certificate directory')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'posix':
        os.chmod(directory, 0o700)
    return directory


def atomic_write_bytes(path, data, mode=0o600):
    """Write bytes atomically with fsync, strict permissions and symlink refusal."""
    target = Path(path)
    if target.is_symlink():
        raise AcmeError('Refusing symlink target file')
    _private_dir(target.parent)
    fd, name = tempfile.mkstemp(prefix='.tmp-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if os.name == 'posix':
            os.chmod(name, mode)
        os.replace(name, target)
        sync_directory(target.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_write_json(path, value, mode=0o600):
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    atomic_write_bytes(path, encoded, mode=mode)


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_domain(domain):
    if not isinstance(domain, str) or not domain or len(domain) > 253 or is_ip(domain):
        raise AcmeError('ACME requires a valid DNS domain name')
    normalized = domain.rstrip('.').lower()
    labels = normalized.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise AcmeError('Invalid ACME domain format')
    if normalized.endswith(('.local', '.localhost', '.invalid', '.test')):
        raise AcmeError('Local domains cannot use ACME')
    return normalized


def validate_email(email):
    if not isinstance(email, str) or len(email) > 254:
        raise AcmeError('Invalid ACME contact email')
    cleaned = email.strip()
    if cleaned and not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', cleaned):
        raise AcmeError('Invalid ACME contact email')
    return cleaned


def validate_cert_name(cert_name):
    if not isinstance(cert_name, str) or not CERT_NAME_PATTERN.fullmatch(cert_name) or cert_name in ('.', '..'):
        raise AcmeError('Invalid certificate lineage name')
    return cert_name


def _run_command(args, *, timeout=30, input_text=None):
    try:
        completed = subprocess.run(
            [str(a) for a in args],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AcmeError(f'Command failed or timed out: {args[0]} ({type(exc).__name__})') from None
    if completed.returncode != 0:
        raise AcmeError(f'{args[0]} exited with status {completed.returncode}')
    return completed.stdout.strip()


def _run_graceful_certbot(args, *, timeout):
    """Run certbot DNS plugin quietly and send SIGTERM on timeout so TXT cleanup can run."""
    process = subprocess.Popen([str(a) for a in args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        code = process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        if os.name == 'posix':
            process.send_signal(signal.SIGTERM)
        else:
            process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise AcmeError('ACME DNS-01 challenge timed out; inspect TXT records') from None
    if code != 0:
        raise AcmeError('ACME DNS-01 challenge failed')
    return ''


def _redact_text(value, secrets):
    result = str(value)
    for secret in secrets:
        if secret:
            result = result.replace(secret, '[REDACTED]')
    return result


def make_log_record_factory(secrets):
    original = logging.getLogRecordFactory()
    secret_list = tuple(s for s in secrets if s)

    def factory(*args, **kwargs):
        record = original(*args, **kwargs)
        record.msg = _redact_text(record.getMessage(), secret_list)
        record.args = ()
        if record.exc_info:
            formatted = ''.join(traceback.format_exception(*record.exc_info))
            record.exc_text = _redact_text(formatted, secret_list)
            record.exc_info = None
        if record.stack_info:
            record.stack_info = _redact_text(record.stack_info, secret_list)
        return record

    return factory


def isolate_provider_environment(directory, prefixes):
    os.environ['HOME'] = str(directory)
    for name in list(os.environ):
        if name.startswith(tuple(prefixes)):
            os.environ.pop(name, None)


def _read_credential_secret(path, provider):
    spec = DNS_PROVIDERS.get(provider)
    if spec is None:
        raise AcmeError('Unsupported DNS provider')
    cred_path = Path(path)
    if cred_path.is_symlink() or not cred_path.is_file():
        raise AcmeError('Missing or invalid DNS credential file')
    info = cred_path.stat()
    if info.st_size > MAX_CREDENTIAL_BYTES:
        raise AcmeError('DNS credential file exceeds size limit')
    if os.name == 'posix' and (info.st_mode & 0o777 != 0o600 or info.st_uid != os.geteuid()):
        raise AcmeError('DNS credential file must be 0600 owned by current user')
    text = cred_path.read_text(encoding='utf-8').strip()
    prefix = spec['ini_key'] + ' = '
    if not text.startswith(prefix):
        raise AcmeError('Invalid DNS credential file format')
    secret = text[len(prefix):]
    if not spec['token_pattern'].fullmatch(secret):
        raise AcmeError('Invalid DNS API token format')
    return secret


def _process_identity():
    try:
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip()
        start = Path('/proc/self/stat').read_text(encoding='utf-8').rsplit(')', 1)[1].split()[19]
        return [os.getpid(), boot_id, start]
    except (OSError, IndexError):
        return [os.getpid(), '', '']


def _owner_alive(owner):
    try:
        pid, boot, start = owner
        if type(pid) is not int or pid <= 0 or not boot or not start:
            raise ValueError()
        if Path('/proc/sys/kernel/random/boot_id').read_text(encoding='utf-8').strip() != boot:
            return False
        return Path(f'/proc/{pid}/stat').read_text(encoding='utf-8').rsplit(')', 1)[1].split()[19] == start
    except FileNotFoundError:
        return False
    except (OSError, ValueError, TypeError, IndexError):
        raise AcmeError('Cannot confirm pending credential owner') from None


def validate_dns_settings(settings):
    if not isinstance(settings, dict):
        raise AcmeError('Invalid DNS settings')
    provider = settings.get('provider', 'cloudflare')
    spec = DNS_PROVIDERS.get(provider)
    if spec is None:
        raise AcmeError('Unsupported DNS provider')
    credential_id = settings.get('credential_id', '')
    if not isinstance(credential_id, str) or not PROFILE_PATTERN.fullmatch(credential_id):
        raise AcmeError('Invalid DNS credential identifier')
    zone_pattern = spec.get('zone_pattern')
    zone_id = settings.get('zone_id', '')
    if zone_pattern is not None and (not isinstance(zone_id, str) or not zone_pattern.fullmatch(zone_id)):
        raise AcmeError('Invalid DNS Zone ID')
    seconds = settings.get('propagation_seconds', 60)
    if type(seconds) is not int or not 10 <= seconds <= 600:
        raise AcmeError('DNS propagation wait must be 10-600 seconds')
    return provider


def credential_path(state_dir, profile, *, pending=True, provider='cloudflare'):
    if not isinstance(profile, str) or not PROFILE_PATTERN.fullmatch(profile):
        raise AcmeError('Invalid DNS credential identifier')
    base = Path(state_dir) / 'credentials'
    if base.is_symlink():
        raise AcmeError('Refusing symlinked credential directory')
    active_path = base / (profile + '.ini')
    pending_dir = base / 'pending'
    staged_path = pending_dir / (profile + '.ini')
    target = active_path
    if pending and (staged_path.exists() or staged_path.is_symlink()):
        if active_path.exists() or pending_dir.is_symlink():
            raise AcmeError('Conflicting pending DNS credential state')
        target = staged_path
    if target.parent.is_symlink() or target.is_symlink() or not target.is_file():
        raise AcmeError('DNS credential file is missing')
    _read_credential_secret(target, provider)
    return target


def store_dns_token(state_dir, token, *, provider='cloudflare', pending=False, profile_id=None):
    """Store a DNS API token cleanly in an isolated 0600 INI profile."""
    spec = DNS_PROVIDERS.get(provider)
    if spec is None:
        raise AcmeError('Unsupported DNS provider')
    if not isinstance(token, str) or not spec['token_pattern'].fullmatch(token):
        raise AcmeError('Invalid DNS API token format')
    if profile_id is None:
        profile_id = spec['prefix'] + '-' + os.urandom(8).hex()
    elif not PROFILE_PATTERN.fullmatch(profile_id):
        raise AcmeError('Invalid DNS credential identifier')
    directory = _private_dir(Path(state_dir) / 'credentials')
    if pending:
        directory = _private_dir(directory / 'pending')
        atomic_write_json(directory / (profile_id + '.json'), {'schema': 1, 'provider': provider, 'owner': _process_identity()})
    atomic_write_bytes(directory / (profile_id + '.ini'), (spec['ini_key'] + ' = ' + token + '\n').encode('utf-8'), mode=0o600)
    return profile_id


def discard_pending_credential(state_dir, profile_id):
    if not PROFILE_PATTERN.fullmatch(profile_id):
        raise AcmeError('Invalid pending DNS credential ID')
    cred_root = Path(state_dir) / 'credentials'
    pending_dir = cred_root / 'pending'
    if cred_root.is_symlink() or pending_dir.is_symlink():
        raise AcmeError('Refusing symlinked credential directory')
    for suffix in ('.ini', '.json'):
        (pending_dir / (profile_id + suffix)).unlink(missing_ok=True)
    if pending_dir.exists():
        sync_directory(pending_dir)


def commit_dns_credential(state_dir, profile_id, *, provider='cloudflare'):
    source = credential_path(state_dir, profile_id, pending=True, provider=provider)
    cred_root = Path(state_dir) / 'credentials'
    destination = cred_root / (profile_id + '.ini')
    if source != destination:
        os.replace(source, destination)
        sync_directory(cred_root)
        marker = cred_root / 'pending' / (profile_id + '.json')
        marker.unlink(missing_ok=True)
        sync_directory(cred_root / 'pending')
    return destination


def recover_pending_credentials(state_dir, *, active_references=()):
    pending_dir = Path(state_dir) / 'credentials' / 'pending'
    if pending_dir.is_symlink():
        raise AcmeError('Refusing symlinked pending credential directory')
    if not pending_dir.exists():
        return []
    removed = []
    referenced = set(active_references)
    for ini_file in sorted(pending_dir.glob('*.ini')):
        profile_id = ini_file.stem
        if not PROFILE_PATTERN.fullmatch(profile_id):
            raise AcmeError('Unknown pending credential artifact')
        marker = pending_dir / (profile_id + '.json')
        if not marker.is_file() or marker.is_symlink():
            raise AcmeError('Missing pending credential marker')
        record = json.loads(marker.read_text(encoding='utf-8'))
        if record.get('schema') != 1:
            raise AcmeError('Unsupported pending credential schema')
        if _owner_alive(record.get('owner')) or profile_id in referenced:
            continue
        discard_pending_credential(state_dir, profile_id)
        removed.append(profile_id)
    return removed


def verify_cloudflare_zone(state_dir, settings, domain, *, opener=None):
    """Verify Cloudflare API token scope without leaking raw secrets or HTTP error payloads."""
    validate_dns_settings({**settings, 'provider': 'cloudflare'})
    domain_norm = validate_domain(domain)
    path = credential_path(state_dir, settings['credential_id'], provider='cloudflare')
    token = _read_credential_secret(path, 'cloudflare')
    url = 'https://api.cloudflare.com/client/v4/zones/' + settings['zone_id']
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token, 'User-Agent': 'ProxyForge-ACME/1'})
    try:
        http_opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with http_opener.open(request, timeout=10) as response:
            if hasattr(response, 'geturl') and response.geturl() != url:
                raise ValueError('redirect')
            data = response.read(65537)
        if len(data) > 65536:
            raise ValueError('size')
        payload = json.loads(data.decode('utf-8'))
        result = payload['result']
        zone_name = validate_domain(result['name'])
        if not payload.get('success') or result['id'].lower() != settings['zone_id'].lower():
            raise ValueError('zone')
        if domain_norm != zone_name and not domain_norm.endswith('.' + zone_name):
            raise ValueError('domain')
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        # Provider exceptions and HTTP bodies can contain credentials: never propagate raw details.
        raise AcmeError('Cloudflare Zone verification failed') from None
    return path


def stage_cloudflare_token(state_dir, token, settings, domain, *, verify=True, opener=None):
    """Validate and stage a Cloudflare DNS-01 credential cleanly without leaking secrets."""
    validate_dns_settings({**settings, 'provider': 'cloudflare', 'credential_id': 'cf-' + '0' * 16})
    profile_id = store_dns_token(state_dir, token, provider='cloudflare', pending=True)
    updated = {**settings, 'provider': 'cloudflare', 'credential_id': profile_id}
    if not verify:
        return updated
    try:
        verify_cloudflare_zone(state_dir, updated, domain, opener=opener)
    except Exception:
        discard_pending_credential(state_dir, profile_id)
        raise
    return updated


def audit_credentials(state_dir, active_references=()):
    cred_dir = Path(state_dir) / 'credentials'
    if cred_dir.is_symlink():
        raise AcmeError('Refusing symlinked credential directory')
    if not cred_dir.exists():
        return []
    referenced = set(active_references)
    records = []
    for path in sorted(cred_dir.glob('*.ini')):
        profile_id = path.stem
        provider = next((name for name, spec in DNS_PROVIDERS.items() if profile_id.startswith(spec['prefix'] + '-')), 'cloudflare')
        credential_path(state_dir, profile_id, pending=False, provider=provider)
        records.append({'id': profile_id, 'provider': provider, 'orphan': profile_id not in referenced})
    return records


def cleanup_orphan_credentials(state_dir, selected_ids, *, active_references=(), confirmed=False):
    if not confirmed:
        raise AcmeError('Explicit confirmation required to delete DNS credentials')
    inventory = {item['id']: item for item in audit_credentials(state_dir, active_references=active_references)}
    for profile_id in selected_ids:
        if profile_id not in inventory or not inventory[profile_id]['orphan']:
            raise AcmeError('Selected DNS credential is referenced or missing')
    for profile_id in selected_ids:
        path = credential_path(state_dir, profile_id, pending=False, provider=inventory[profile_id]['provider'])
        path.unlink()
    if selected_ids:
        sync_directory(Path(state_dir) / 'credentials')


def public_ips():
    found = {'ipv4': '', 'ipv6': ''}
    sources = {
        'ipv4': ('https://api4.ipify.org', 'https://ipv4.icanhazip.com'),
        'ipv6': ('https://api6.ipify.org', 'https://ipv6.icanhazip.com'),
    }
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for family, urls in sources.items():
        for url in urls:
            try:
                with opener.open(url, timeout=3) as response:
                    value = response.read(128).decode('utf-8').strip()
                ip = ipaddress.ip_address(value)
                if ip.is_global and ip.version == (4 if family == 'ipv4' else 6):
                    found[family] = str(ip)
                    break
            except (OSError, ValueError):
                continue
    return found


def dns_matches(domain, ips, *, resolver=socket.getaddrinfo):
    domain_norm = validate_domain(domain)
    try:
        answers = {entry[4][0] for entry in resolver(domain_norm, None, type=socket.SOCK_STREAM)}
    except OSError:
        raise AcmeError('Failed to resolve ACME domain DNS records') from None
    expected = {ip for ip in ips.values() if ip}
    if not answers or not expected or not answers.issubset(expected):
        raise AcmeError('Domain DNS A/AAAA records do not match host public IP addresses')
    if any(not ipaddress.ip_address(ip).is_global for ip in answers):
        raise AcmeError('HTTP-01 domain must resolve to global public IP addresses')
    return answers


def http01_bindings(answers):
    versions = {ipaddress.ip_address(ip).version for ip in answers}
    if not versions:
        raise AcmeError('No resolvable IP addresses for HTTP-01 validation')
    return [addr for version, addr in ((4, '0.0.0.0'), (6, '::')) if version in versions]


def http01_dual_stack_ready(bindv6only_path=Path('/proc/sys/net/ipv6/bindv6only')):
    if not socket.has_ipv6:
        raise AcmeError('IPv6 sockets unavailable for dual-stack HTTP-01')
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except OSError:
        raise AcmeError('Kernel disabled dual-stack IPv6 sockets for HTTP-01') from None
    try:
        value = bindv6only_path.read_text(encoding='utf-8').strip()
        if value not in {'0', '1'}:
            raise AcmeError('Unrecognized bindv6only state for HTTP-01')
    except OSError:
        pass
    return True


def check_port_free(listen, port, transport='tcp', v6only=False):
    address = ipaddress.ip_address(listen)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    kind = socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM
    try:
        with socket.socket(family, kind) as sock:
            if kind == socket.SOCK_STREAM:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(v6only))
            sock.bind((listen, port))
            if kind == socket.SOCK_STREAM:
                sock.listen(1)
    except OSError:
        raise AcmeError(f'Port {listen}:{port}/{transport} is already in use or unavailable') from None


def validate_pair(certificate_path, key_path, sni, *, runner=_run_command):
    cert, key = Path(certificate_path), Path(key_path)
    if cert.is_symlink() or key.is_symlink() or not cert.is_file() or not key.is_file():
        raise AcmeError('Certificate or private key missing or symlinked')
    if cert.stat().st_size == 0 or cert.stat().st_size > MAX_CERT_BYTES:
        raise AcmeError('Certificate file size is invalid')
    if key.stat().st_size == 0 or key.stat().st_size > MAX_KEY_BYTES:
        raise AcmeError('Private key file size is invalid')
    runner(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '0'])
    san_flag = '-checkip' if is_ip(sni) else '-checkhost'
    san_output = runner(['openssl', 'x509', '-in', cert, '-noout', san_flag, sni])
    if 'does NOT match' in san_output:
        raise AcmeError('Certificate SAN does not match domain')
    cert_pub = runner(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'])
    key_pub = runner(['openssl', 'pkey', '-in', key, '-pubout', '-passin', 'pass:'])
    if cert_pub != key_pub:
        raise AcmeError('Certificate and unencrypted private key do not match')


def is_due_for_renewal(certificate_path, *, window_seconds=DEFAULT_RENEWAL_WINDOW, runner=_run_command):
    cert = Path(certificate_path)
    if not cert.is_file() or cert.is_symlink():
        return True
    try:
        runner(['openssl', 'x509', '-in', cert, '-noout', '-checkend', str(int(window_seconds))])
        return False
    except AcmeError:
        return True


def reusable(certificate_path, key_path, sni, *, window_seconds=DEFAULT_RENEWAL_WINDOW, runner=_run_command):
    try:
        validate_pair(certificate_path, key_path, sni, runner=runner)
        return not is_due_for_renewal(certificate_path, window_seconds=window_seconds, runner=runner)
    except (AcmeError, OSError):
        return False


def create_selfsigned(certificate_path, key_path, domain, *, days=30, runner=_run_command):
    cert, key = Path(certificate_path), Path(key_path)
    _private_dir(cert.parent)
    _private_dir(key.parent)
    san = ('IP:' if is_ip(domain) else 'DNS:') + domain
    runner([
        'openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-days', str(int(days)), '-subj', '/CN=ProxyForge-TLS',
        '-addext', 'subjectAltName=' + san, '-keyout', key, '-out', cert,
    ])
    if os.name == 'posix':
        os.chmod(cert, 0o600)
        os.chmod(key, 0o600)


def certificate_info(certificate_path, *, state_dir=DEFAULT_STATE_DIR, cert_name='', runner=_run_command):
    result = {
        'status': 'unverified',
        'issuer': '',
        'expires': '',
        'days': None,
        'last_renewal': {'status': 'none'},
    }
    try:
        output = runner(['openssl', 'x509', '-in', certificate_path, '-noout', '-issuer', '-enddate', '-nameopt', 'RFC2253'])
        fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        expires = datetime.strptime(fields['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        days = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
        result.update(
            issuer=fields.get('issuer', ''),
            expires=expires.isoformat(),
            days=days,
            status='expired' if days < 0 else ('expiring' if days < 30 else 'valid'),
        )
    except (AcmeError, KeyError, ValueError):
        pass
    if cert_name:
        status_path = Path(state_dir) / 'certificate-status' / (cert_name + '.json')
        if status_path.is_file() and not status_path.is_symlink():
            try:
                result['last_renewal'] = json.loads(status_path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
    return result


def run_redacted_certbot(args):
    """Isolated certbot subprocess wrapper stripping DNS tokens from env and output."""
    provider = None
    cred_path = None
    secrets = []
    index = 0
    while index < len(args):
        if args[index] == '--proxyforge-dns-provider' and index + 1 < len(args):
            provider = args[index + 1]
            args = [*args[:index], *args[index + 2:]]
            continue
        index += 1
    try:
        if provider:
            spec = DNS_PROVIDERS.get(provider)
            if spec is None or spec['cred_flag'] not in args:
                raise AcmeError('Missing DNS provider credentials argument')
            cred_index = args.index(spec['cred_flag'])
            if cred_index + 1 >= len(args):
                raise AcmeError('Missing DNS credential file path')
            cred_path = Path(args[cred_index + 1])
            secrets.append(_read_credential_secret(cred_path, provider))
            isolate_provider_environment(cred_path.parent, spec['env_prefixes'])
        logging.setLogRecordFactory(make_log_record_factory(secrets))
        sys.stdout = _RedactedStream(sys.stdout, secrets)
        sys.stderr = _RedactedStream(sys.stderr, secrets)

        def interrupted(signum, frame):
            raise KeyboardInterrupt()

        signal.signal(signal.SIGTERM, interrupted)
        from certbot.main import main as certbot_main
        return certbot_main(args)
    except (AcmeError, OSError, ImportError, KeyboardInterrupt, ValueError):
        sys.stderr.write('ProxyForge ACME DNS-01 runner failed cleanly.\n')
        return 1


class AcmeManager:
    """Manage ACME HTTP-01 / DNS-01 issuance, staging and renewal under private helper state."""

    def __init__(
        self,
        state_dir=DEFAULT_STATE_DIR,
        *,
        runner=_run_command,
        graceful_runner=_run_graceful_certbot,
        ip_reader=public_ips,
        resolver=socket.getaddrinfo,
        port_checker=check_port_free,
        opener=None,
        which=shutil.which,
    ):
        self.state_dir = Path(state_dir)
        self.runner = runner
        self.graceful_runner = graceful_runner
        self.ip_reader = ip_reader
        self.resolver = resolver
        self.port_checker = port_checker
        self.opener = opener
        self.which = which

    def live_paths(self, cert_name):
        name = validate_cert_name(cert_name)
        live_dir = self.state_dir / 'live' / name
        return live_dir / 'fullchain.pem', live_dir / 'privkey.pem'

    def record_status(self, cert_name, domain, status):
        name = validate_cert_name(cert_name)
        directory = _private_dir(self.state_dir / 'certificate-status')
        atomic_write_json(
            directory / (name + '.json'),
            {'domain': domain, 'status': status, 'at': datetime.now(timezone.utc).isoformat()},
        )

    def _certbot_isolated_args(self, cert_name):
        base = _private_dir(self.state_dir / 'acme' / cert_name)
        config_file = base / 'cli.ini'
        if config_file.is_symlink():
            raise AcmeError('Refusing symlinked certbot configuration')
        atomic_write_bytes(config_file, b'# ProxyForge isolated certbot settings\n')
        return [
            '--config', config_file,
            '--config-dir', base / 'config',
            '--work-dir', base / 'work',
            '--logs-dir', base / 'logs',
        ]

    def _prepare_dns_auth(self, domain, dns_provider, dns_api_token, dns_zone_id, credential_id, propagation_seconds):
        spec = DNS_PROVIDERS.get(dns_provider)
        if spec is None:
            raise AcmeError('Unsupported ACME DNS provider')
        seconds = int(propagation_seconds)
        if not 10 <= seconds <= 600:
            raise AcmeError('DNS propagation wait must be 10-600 seconds')
        if dns_api_token:
            profile_id = store_dns_token(self.state_dir, dns_api_token, provider=dns_provider, pending=True)
            try:
                if dns_provider == 'cloudflare' and dns_zone_id:
                    verify_cloudflare_zone(
                        self.state_dir,
                        {'provider': 'cloudflare', 'credential_id': profile_id, 'zone_id': dns_zone_id, 'propagation_seconds': seconds},
                        domain,
                        opener=self.opener,
                    )
                cred_file = commit_dns_credential(self.state_dir, profile_id, provider=dns_provider)
            except Exception:
                discard_pending_credential(self.state_dir, profile_id)
                raise
        elif credential_id:
            profile_id = credential_id
            cred_file = credential_path(self.state_dir, profile_id, pending=False, provider=dns_provider)
        else:
            raise AcmeError('ACME DNS-01 requires a credential profile or API token')
        return profile_id, [spec['flag'], spec['cred_flag'], cred_file, spec['prop_flag'], str(seconds)]

    def _prepare_http01_auth(self, domain):
        bindings = http01_bindings(dns_matches(domain, self.ip_reader(), resolver=self.resolver))
        for address in bindings:
            self.port_checker(address, 80, 'tcp', v6only=True)
        if len(bindings) == 1:
            return ['--standalone', '--preferred-challenges', 'http', '--http-01-port', '80', '--http-01-address', bindings[0]]
        http01_dual_stack_ready()
        return ['--standalone', '--preferred-challenges', 'http', '--http-01-port', '80']

    def _run_certbot(self, cert_name, domain, tls_mode, *, email='', dns_provider='cloudflare', dns_api_token='', dns_zone_id='', credential_id='', propagation_seconds=60, renew=False):
        if not self.which('certbot'):
            raise AcmeError('certbot is required on the host for ACME issuance')
        isolated = self._certbot_isolated_args(cert_name)
        contact = ['--email', email] if email else ['--register-unsafely-without-email']
        if tls_mode == 'acme_dns':
            spec = DNS_PROVIDERS[dns_provider]
            plugins = self.runner(['certbot', 'plugins', *isolated], timeout=20)
            if spec['plugin'] not in plugins:
                raise AcmeError(f'Missing certbot plugin: {spec["plugin"]}')
            profile_id, authenticator = self._prepare_dns_auth(
                domain, dns_provider, dns_api_token, dns_zone_id, credential_id, propagation_seconds,
            )
            cmd = [sys.executable, '-m', 'agent.acme_manager', '--proxyforge-dns-provider', dns_provider]
            args = [
                *cmd, 'certonly', *authenticator, '--non-interactive', '--agree-tos', *contact,
                *isolated, '--server', ACME_DIRECTORY, '--cert-name', cert_name,
                '--force-renewal' if renew else '--keep-until-expiring', '-d', domain,
            ]
            self.graceful_runner(args, timeout=240 + int(propagation_seconds))
        elif tls_mode == 'acme_http':
            profile_id = ''
            authenticator = self._prepare_http01_auth(domain)
            args = [
                'certbot', 'certonly', *authenticator, '--non-interactive', '--agree-tos', *contact,
                *isolated, '--server', ACME_DIRECTORY, '--cert-name', cert_name,
                '--force-renewal' if renew else '--keep-until-expiring', '-d', domain,
            ]
            self.runner(args, timeout=240)
        else:
            raise AcmeError('Unsupported ACME mode')
        lineage_root = self.state_dir / 'acme' / cert_name / 'config'
        lineage = lineage_root / 'live' / cert_name
        return profile_id, lineage_root, lineage / 'fullchain.pem', lineage / 'privkey.pem'

    def _save_manifest(self, cert_name, metadata):
        manifest_dir = _private_dir(self.state_dir / 'managed')
        atomic_write_json(manifest_dir / (cert_name + '.json'), metadata)

    def ensure_certificate(
        self,
        cert_name,
        domain,
        *,
        tls_mode='acme_http',
        email='',
        dns_provider='cloudflare',
        dns_api_token='',
        dns_zone_id='',
        credential_id='',
        propagation_seconds=60,
        renew=False,
    ):
        """Ensure valid, non-expiring TLS cert & key exist in live/<cert_name>/ and return their paths."""
        name = validate_cert_name(cert_name)
        domain_norm = validate_domain(domain)
        email_clean = validate_email(email)
        live_cert, live_key = self.live_paths(name)
        profile_id = credential_id

        if tls_mode == 'selfsigned':
            if renew or not reusable(live_cert, live_key, domain_norm, runner=self.runner):
                _private_dir(live_cert.parent)
                create_selfsigned(live_cert, live_key, domain_norm, runner=self.runner)
                self.record_status(name, domain_norm, 'selfsigned_ready')
            return live_cert, live_key

        if tls_mode not in ('acme_http', 'acme_dns'):
            raise AcmeError('Unsupported TLS mode for ACME manager')

        if renew or not reusable(live_cert, live_key, domain_norm, runner=self.runner):
            try:
                profile_id, lineage_root, src_cert, src_key = self._run_certbot(
                    name,
                    domain_norm,
                    tls_mode,
                    email=email_clean,
                    dns_provider=dns_provider,
                    dns_api_token=dns_api_token,
                    dns_zone_id=dns_zone_id,
                    credential_id=credential_id,
                    propagation_seconds=propagation_seconds,
                    renew=renew,
                )
                # Certbot writes live/<name>/*.pem as relative symlinks into ../../archive/<name>/*.
                confined_root = lineage_root.resolve(strict=True)
                resolved_cert = Path(src_cert).resolve(strict=True)
                resolved_key = Path(src_key).resolve(strict=True)
                if not resolved_cert.is_relative_to(confined_root) or not resolved_key.is_relative_to(confined_root):
                    raise AcmeError('Certbot certificate resolves outside isolated lineage root')
                validate_pair(resolved_cert, resolved_key, domain_norm, runner=self.runner)
                atomic_write_bytes(live_cert, resolved_cert.read_bytes(), mode=0o600)
                atomic_write_bytes(live_key, resolved_key.read_bytes(), mode=0o600)
                self.record_status(name, domain_norm, 'issued_or_renewed')
            except (AcmeError, OSError, RuntimeError):
                self.record_status(name, domain_norm, 'renewal_failed')
                raise

        validate_pair(live_cert, live_key, domain_norm, runner=self.runner)
        self._save_manifest(
            name,
            {
                'cert_name': name,
                'domain': domain_norm,
                'tls_mode': tls_mode,
                'email': email_clean,
                'dns_provider': dns_provider if tls_mode == 'acme_dns' else '',
                'dns_zone_id': dns_zone_id if tls_mode == 'acme_dns' else '',
                'credential_id': profile_id if tls_mode == 'acme_dns' else '',
                'propagation_seconds': int(propagation_seconds),
            },
        )
        return live_cert, live_key

    def renew_due_certificates(self, *, window_seconds=DEFAULT_RENEWAL_WINDOW, force=False):
        manifest_dir = self.state_dir / 'managed'
        if not manifest_dir.is_dir():
            return []
        results = []
        for path in sorted(manifest_dir.glob('*.json')):
            if path.is_symlink():
                continue
            try:
                record = json.loads(path.read_text(encoding='utf-8'))
                name = validate_cert_name(record['cert_name'])
                domain = validate_domain(record['domain'])
                live_cert, _ = self.live_paths(name)
                if not force and not is_due_for_renewal(live_cert, window_seconds=window_seconds, runner=self.runner):
                    results.append({'cert_name': name, 'domain': domain, 'status': 'valid', 'renewed': False, 'error': None})
                    continue
                self.ensure_certificate(
                    name,
                    domain,
                    tls_mode=record.get('tls_mode', 'acme_http'),
                    email=record.get('email', ''),
                    dns_provider=record.get('dns_provider') or 'cloudflare',
                    dns_zone_id=record.get('dns_zone_id', ''),
                    credential_id=record.get('credential_id', ''),
                    propagation_seconds=record.get('propagation_seconds', 60),
                    renew=True,
                )
                results.append({'cert_name': name, 'domain': domain, 'status': 'renewed', 'renewed': True, 'error': None})
            except (AcmeError, KeyError, ValueError, OSError) as exc:
                results.append({
                    'cert_name': path.stem,
                    'domain': '',
                    'status': 'failed',
                    'renewed': False,
                    'error': str(exc) if isinstance(exc, AcmeError) else type(exc).__name__,
                })
        return results


if __name__ == '__main__':
    raise SystemExit(run_redacted_certbot(sys.argv[1:]))
