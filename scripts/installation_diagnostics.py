"""一次性安装 CI 的只读 helper 故障摘要；不打印配置、进程输出或异常正文。"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


PROPERTIES = ('ActiveState', 'SubState', 'Result', 'MainPID', 'NRestarts', 'ExecMainCode', 'ExecMainStatus')
STATES = frozenset(('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading',
                    'running', 'dead', 'exited', 'start', 'start-pre', 'start-post', 'stop',
                    'stop-sigterm', 'stop-sigkill', 'auto-restart', 'success', 'exit-code',
                    'signal', 'core-dump', 'timeout', 'watchdog', 'start-limit-hit',
                    'resources', 'protocol', 'oom-kill'))
ERRORS = frozenset(('runtime_unavailable', 'runtime_failed', 'runtime_cancelled', 'rollback_failed'))
ACTIONS = frozenset(('singbox.install', 'singbox.restart', 'singbox.rollback', 'singbox.stop', 'singbox.start'))


def process_summary(args, *, timeout, run, **options):
    started = time.monotonic()
    try:
        result = run(args, capture_output=True, text=True, timeout=timeout, **options)
        return {'returncode': result.returncode, 'timed_out': False,
                'seconds': round(time.monotonic() - started, 3)}, result.stdout
    except subprocess.TimeoutExpired:
        return {'timed_out': True, 'seconds': round(time.monotonic() - started, 3)}, ''
    except OSError:
        return {'unavailable': True, 'seconds': round(time.monotonic() - started, 3)}, ''


def service_summary(unit, run):
    result, output = process_summary(
        ['/usr/bin/systemctl', 'show', unit, '--property=' + ','.join(PROPERTIES)], timeout=10, run=run)
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        if separator and key in PROPERTIES:
            if key in ('MainPID', 'NRestarts', 'ExecMainCode', 'ExecMainStatus'):
                values[key] = int(value) if re.fullmatch(r'[0-9]{1,12}', value) else 'unknown'
            else:
                values[key] = value if value in STATES else 'unknown'
    return {**result, 'properties': values}


def current_binary_summary(root, run, account):
    """Check the retained current generation as its user, without changing it."""
    try:
        target = os.readlink(root / 'current')
        if not re.fullmatch(r'releases/[a-f0-9]{32}', target):
            return {'valid_pointer': False}
        release = root / target
        if release.is_symlink() or not release.is_dir():
            return {'valid_pointer': False}
        for path in (release / 'sing-box', release / 'config.json'):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return {'valid_pointer': True, 'trusted_files': False}
        uid, gid = account()
        options = {'user': uid, 'group': gid, 'extra_groups': []}
        version, _ = process_summary([str(release / 'sing-box'), 'version'],
                                     timeout=5, run=run, **options)
        check, _ = process_summary([str(release / 'sing-box'), 'check', '-c', str(release / 'config.json')],
                                   timeout=20, run=run, **options)
        return {'valid_pointer': True, 'trusted_files': True, 'version_probe': version, 'config_probe': check}
    except (OSError, KeyError):
        return {'unavailable': True}


def helper_failure_summary(action, result, *, root=Path('/var/lib/proxyforge-runtime'), run=None, account=None):
    """Only accept fixed actions/errors into the public CI log."""
    if run is None:
        run = subprocess.run
    if account is None:
        def account():
            import pwd
            user = pwd.getpwnam('proxyforge-singbox')
            return user.pw_uid, user.pw_gid
    error = result.get('error') if isinstance(result, dict) else None
    summary = {'action': action if isinstance(action, str) and action in ACTIONS else 'unknown',
               'error': error if isinstance(error, str) and error in ERRORS else 'unknown',
               'transaction_present': (root / 'transaction.json').exists(),
               'previous_pointer_present': (root / 'previous').is_symlink(),
               'services': {name: service_summary(name, run) for name in
                            ('proxyforge-runtime.service', 'proxyforge-singbox.service')},
               'current_binary': current_binary_summary(root, run, account)}
    print('Helper failure diagnostics: ' + json.dumps(summary, sort_keys=True), flush=True)
    return summary
