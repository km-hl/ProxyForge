"""Read-only allowlist runner with a bounded, durable result replay journal."""
import contextlib
import json
import os
from pathlib import Path
import re

from .client import AgentConnectionError, JobRejected
from .system_info import singbox_status


@contextlib.contextmanager
def runner_lock(config_path):
    """Only one daemon/--once invocation may use this Agent configuration."""
    lock_path = Path(config_path).with_suffix('.lock')
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('Another Agent process holds this configuration') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def validate_job(job):
    if (not isinstance(job, dict) or job.get('job_protocol_version') != 1 or
            job.get('type') != 'singbox.status' or job.get('payload') != {} or
            job.get('deployment_revision') is not None or
            not isinstance(job.get('id'), str) or not re.fullmatch(r'[a-f0-9]{32}', job['id']) or
            not isinstance(job.get('lease_token'), str) or
            not re.fullmatch(r'[A-Za-z0-9_-]{43}', job['lease_token'])):
        raise AgentConnectionError('Unsupported job schema')


def validate_journal(journal, binding):
    """Reject malformed replay records before claiming any work."""
    if (set(journal) != {'binding', 'entries'} or journal['binding'] != binding or
            not isinstance(journal['entries'], list) or len(journal['entries']) > 128):
        raise ValueError('Job journal identity or schema mismatch')
    seen = set()
    for entry in journal['entries']:
        if not isinstance(entry, dict) or set(entry) != {'identity', 'result'}:
            raise ValueError('Invalid job journal entry')
        identity, result = entry['identity'], entry['result']
        if (not isinstance(identity, dict) or set(identity) != {'id', 'type', 'deployment_revision'} or
                not isinstance(identity['id'], str) or not re.fullmatch(r'[a-f0-9]{32}', identity['id']) or
                identity['type'] != 'singbox.status' or identity['deployment_revision'] is not None or
                identity['id'] in seen):
            raise ValueError('Invalid job journal identity')
        seen.add(identity['id'])
        if not isinstance(result, dict) or set(result) != {'status', 'output', 'error'}:
            raise ValueError('Invalid job journal result')
        if result['status'] == 'failed':
            if result['output'] is not None or result['error'] != 'probe_failed':
                raise ValueError('Invalid job journal failure')
        elif result['status'] == 'success':
            output = result['output']
            if (result['error'] is not None or not isinstance(output, dict) or
                    set(output) != {'installed', 'running', 'version', 'status'} or
                    type(output['installed']) is not bool or type(output['running']) is not bool or
                    not isinstance(output['version'], str) or len(output['version']) > 128 or
                    output['status'] not in ('not_installed', 'running', 'stopped', 'unknown')):
                raise ValueError('Invalid job journal output')
        else:
            raise ValueError('Invalid job journal status')


def process_job(client, config, config_path):
    from .main import load_config, save_config
    journal_path = Path(config_path).with_name('job-results.json')
    binding = {key: config[key] for key in ('controller', 'agent_id', 'instance_id')}
    journal = {'binding': binding, 'entries': []}
    if journal_path.exists():
        if journal_path.stat().st_size > 262144:
            raise ValueError('Job journal exceeds limit')
        journal = load_config(journal_path)
        validate_journal(journal, binding)
    try:
        job = client.post('/api/agent/jobs/claim', {'instance_id': config['instance_id']}, config['token']).get('job')
        if job is None:
            return
        validate_job(job)
        endpoint = '/api/agent/jobs/' + job['id']
        lease = {'lease_token': job['lease_token']}
        client.post(endpoint + '/start', lease, config['token'])
        identity = {key: job[key] for key in ('id', 'type', 'deployment_revision')}
        previous = next((e for e in journal['entries'] if e.get('identity') == identity), None)
        if previous is not None:
            result = previous['result']
        else:
            try:
                output = singbox_status()
                result = {'status': 'success', 'output': output, 'error': None}
            except (OSError, ValueError):
                result = {'status': 'failed', 'output': None, 'error': 'probe_failed'}
            journal['entries'] = (journal['entries'] + [{'identity': identity, 'result': result}])[-128:]
            # Durability before uploading; never persist the per-attempt lease credential.
            if len(json.dumps(journal).encode('utf-8')) > 262144:
                raise ValueError('Job journal exceeds limit')
            save_config(journal_path, journal)
        client.post(endpoint + '/result', {**lease, 'result': result}, config['token'])
    except JobRejected:
        # Cancellation, stale lease or capability change: next heartbeat/claim reconciles.
        return
