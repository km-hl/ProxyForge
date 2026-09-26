"""Shared standard-library schemas for the narrowly scoped runtime protocol."""
import hashlib
import json
from pathlib import Path
import re
from .deployment_spec import DEPLOYMENT_ACTIONS, validate_reference, validate_spec, spec_hash
from .landing_spec import LANDING_ACTIONS, validate_spec as validate_landing_spec

RELEASE = json.loads(Path(__file__).with_name('singbox-release.json').read_text(encoding='utf-8'))
CONFIG_ACTIONS = (*DEPLOYMENT_ACTIONS, *LANDING_ACTIONS)
RUNTIME_ACTIONS = ('singbox.install', 'singbox.start', 'singbox.stop', 'singbox.restart', 'singbox.rollback', *CONFIG_ACTIONS)
RUNTIME_ERRORS = ('runtime_unavailable', 'runtime_failed', 'runtime_cancelled', 'rollback_failed')


def validate_action(action, payload):
    if action not in RUNTIME_ACTIONS or not isinstance(payload, dict):
        raise ValueError('Unsupported runtime action')
    if action in CONFIG_ACTIONS:
        validate_reference(payload)
    elif action == 'singbox.install':
        if payload != {'version': RELEASE['version']}:
            raise ValueError('Only the pinned release is allowed')
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
        validator = validate_landing_spec if job['type'] in LANDING_ACTIONS else validate_spec
        validator(job['type'], job.get('deployment'))
        if spec_hash(job['deployment']) != job['payload']['spec_hash']:
            raise ValueError('Deployment snapshot changed')


def valid_output(output):
    return (isinstance(output, dict) and set(output) == {'installed', 'running', 'version', 'status'} and
            type(output['installed']) is bool and type(output['running']) is bool and
            isinstance(output['version'], str) and len(output['version']) <= 128 and
            output['status'] in ('not_installed', 'running', 'stopped', 'unknown'))
