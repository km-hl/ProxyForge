"""一次性安装 CI：只读等待同一 Agent 的新能力心跳，超时仅输出白名单摘要。"""
import json
import math
import subprocess
import time

from scripts.installation_diagnostics import service_summary


CAPABILITIES = ('runtime_protocol_version', 'deployment_protocol_version',
                'landing_protocol_version', 'chain_protocol_version')
RUNTIME_STATES = ('not_installed', 'running', 'stopped', 'unknown')


def heartbeat_diagnostics(metadata, *, present, changed, polls, seconds):
    info = metadata.get('singbox')
    info = info if isinstance(info, dict) else {}
    state = info.get('status')
    summary = {
        'expected_agent_present': present, 'new_heartbeat_observed': changed,
        'polls': polls, 'seconds': round(seconds, 3),
        'capabilities': {name: metadata.get(name) if type(metadata.get(name)) is int
                         and metadata[name] in (0, 1) else None for name in CAPABILITIES},
        'installed': info.get('installed') if type(info.get('installed')) is bool else None,
        'running': info.get('running') if type(info.get('running')) is bool else None,
        'runtime_status': state if isinstance(state, str) and state in RUNTIME_STATES else 'unknown',
    }
    print('Helper heartbeat diagnostics: ' + json.dumps(summary, sort_keys=True), flush=True)
    # Emit the snapshot first, so a later diagnostic timeout cannot hide it.
    summary['services'] = {name: service_summary(name, subprocess.run) for name in
                           ('proxyforge-agent.service', 'proxyforge-runtime.service', 'proxyforge-singbox.service')}
    print('Helper heartbeat service diagnostics: ' + json.dumps(summary['services'], sort_keys=True), flush=True)
    return summary


def wait_for_helper_heartbeat(client, headers, agent_id, *, budget=90):
    """Allow normal heartbeat cycles; never mutate Agent state or accept a stale snapshot."""
    if not 0 < budget <= 90:
        raise ValueError('Helper heartbeat observation budget must be within 90 seconds')
    started = time.monotonic()
    deadline = started + budget
    unset = object()
    first_seen = unset
    changed = present = False
    metadata = {}
    polls = 0
    while time.monotonic() < deadline:
        response = client.get('/api/agents', headers=headers)
        response.raise_for_status()
        payload = response.json()
        agents = payload.get('agents') if isinstance(payload, dict) else None
        if not isinstance(agents, list):
            raise ValueError('Invalid Agent inventory response')
        polls += 1
        item = next((item for item in agents if isinstance(item, dict) and item.get('id') == agent_id), None)
        present = item is not None
        if present:
            metadata = item.get('metadata')
            if not isinstance(metadata, dict):
                raise ValueError('Invalid Agent metadata response')
            seen = item.get('last_seen')
            if seen is not None and (type(seen) not in (int, float) or not math.isfinite(seen)):
                raise ValueError('Invalid Agent heartbeat timestamp')
            if first_seen is unset:
                first_seen = seen
            elif seen is not None and seen != first_seen:
                changed = True
            info = metadata.get('singbox')
            if (changed and isinstance(info, dict) and info.get('running') is True
                    and all(type(metadata.get(name)) is int and metadata[name] == 1 for name in CAPABILITIES)
                    and time.monotonic() < deadline):
                return metadata
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1.0, remaining))
    heartbeat_diagnostics(metadata, present=present, changed=changed, polls=polls,
                          seconds=time.monotonic() - started)
    raise AssertionError('No helper capability/runtime heartbeat received')
