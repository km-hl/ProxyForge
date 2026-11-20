"""Shared standard-library schemas for the narrowly scoped runtime protocol."""
import hashlib
import json
from pathlib import Path
import re
from .deployment_spec import DEPLOYMENT_ACTIONS, validate_reference, validate_spec, spec_hash
from .landing_spec import LANDING_ACTIONS, validate_spec as validate_landing_spec
from .chain_spec import CHAIN_ACTIONS, validate_spec as validate_chain_spec
from .gost_manager import GOST_CONFIG_ACTIONS, validate_spec as validate_gost_spec

SERVICE_SINGBOX = 'sing-box'
SERVICE_CADDY = 'caddy'
SERVICE_GOST = 'go-gost'
MANAGED_SERVICES = (SERVICE_SINGBOX, SERVICE_CADDY, SERVICE_GOST)

RELEASE = json.loads(Path(__file__).with_name('singbox-release.json').read_text(encoding='utf-8'))
CADDY_RELEASE = json.loads(Path(__file__).with_name('caddy-release.json').read_text(encoding='utf-8'))
GOST_RELEASE = json.loads(Path(__file__).with_name('gost-release.json').read_text(encoding='utf-8'))
CONFIG_ACTIONS = (*DEPLOYMENT_ACTIONS, *LANDING_ACTIONS, *CHAIN_ACTIONS, *GOST_CONFIG_ACTIONS)
CADDY_CONFIG_ACTIONS = ('caddy.apply', 'caddy.remove')
CADDY_ACTIONS = ('caddy.install', 'caddy.start', 'caddy.stop', 'caddy.restart', 'caddy.rollback', *CADDY_CONFIG_ACTIONS)
GOST_ACTIONS = ('gost.install', 'gost.start', 'gost.stop', 'gost.restart', 'gost.rollback', *GOST_CONFIG_ACTIONS)
SINGBOX_ACTIONS = ('singbox.install', 'singbox.start', 'singbox.stop', 'singbox.restart', 'singbox.rollback')
RUNTIME_ACTIONS = (*SINGBOX_ACTIONS, *CADDY_ACTIONS, *GOST_ACTIONS, *DEPLOYMENT_ACTIONS, *LANDING_ACTIONS, *CHAIN_ACTIONS)
RUNTIME_ERRORS = (
    'runtime_unavailable',
    'runtime_failed',
    'runtime_cancelled',
    'rollback_failed',
    'acme_certbot_missing',
    'acme_dns_plugin_missing',
    'acme_port80_in_use',
    'acme_dns_mismatch',
    'acme_failed',
    'port_conflict',
    'caddy_failed',
    'config_check_failed',
    'health_check_failed',
    'download_failed',
)


def job_service(action):
    """Map an allowlisted runtime action to its owning managed runtime service."""
    if action in CADDY_ACTIONS:
        return SERVICE_CADDY
    if action in GOST_ACTIONS:
        return SERVICE_GOST
    if action in RUNTIME_ACTIONS:
        return SERVICE_SINGBOX
    raise ValueError('Unsupported runtime action')


def validate_action(action, payload):
    if action not in RUNTIME_ACTIONS or not isinstance(payload, dict):
        raise ValueError('Unsupported runtime action')
    if action in CONFIG_ACTIONS:
        validate_reference(payload)
    elif action == 'caddy.apply':
        if set(payload) != {'caddyfile'} or not isinstance(payload['caddyfile'], str) or len(payload['caddyfile']) > 128 * 1024:
            raise ValueError('Invalid Caddy payload')
    elif action == 'singbox.install':
        if payload != {'version': RELEASE['version']}:
            raise ValueError('Only the pinned release is allowed')
    elif action == 'caddy.install':
        if payload != {'version': CADDY_RELEASE['version']}:
            raise ValueError('Only the pinned Caddy release is allowed')
    elif action == 'gost.install':
        if payload != {'version': GOST_RELEASE['version']}:
            raise ValueError('Only the pinned go-gost release is allowed')
    elif payload:
        raise ValueError('Runtime action takes no arguments')


def revision(job_id, action, payload):
    return hashlib.sha256(json.dumps([job_id, action, payload], sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def validate_runtime_job(job):
    if not isinstance(job, dict) or not isinstance(job.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', job['id']):
        raise ValueError('Invalid runtime identity')
    validate_action(job.get('type'), job.get('payload'))
    if job.get('deployment_revision') != revision(job['id'], job['type'], job['payload']):
        raise ValueError('Invalid runtime revision')
    if job['type'] in CONFIG_ACTIONS:
        if job['type'] in LANDING_ACTIONS:
            validator = validate_landing_spec
        elif job['type'] in CHAIN_ACTIONS:
            validator = validate_chain_spec
        elif job['type'] in GOST_CONFIG_ACTIONS:
            validator = validate_gost_spec
        else:
            validator = validate_spec
        validator(job['type'], job.get('deployment'))
        if spec_hash(job['deployment']) != job['payload']['spec_hash']:
            raise ValueError('Deployment snapshot changed')


def valid_output(output):
    return (isinstance(output, dict) and set(output) == {'installed', 'running', 'version', 'status'} and
            type(output['installed']) is bool and type(output['running']) is bool and
            isinstance(output['version'], str) and len(output['version']) <= 128 and
            output['status'] in ('not_installed', 'running', 'stopped', 'unknown'))
