"""Renew a live attempt while a bounded local runtime operation is in progress."""
import threading
import time

from .client import Client, AgentConnectionError
from .system_info import collect


class JobLease:
    def __init__(self, config, job):
        self.config, self.job = config, job
        self.stop = threading.Event()
        self.error = None
        self.last_success = time.monotonic()
        self.thread = threading.Thread(target=self.maintain, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.guard

    def guard(self):
        if self.error is not None:
            raise self.error
        if time.monotonic() - self.last_success >= 40:
            raise AgentConnectionError('Job lease no longer confirmed')

    def maintain(self):
        try:
            client = Client(self.config['controller'], self.config.get('allow_insecure', False), self.config.get('ca_file'))
            while not self.stop.wait(10):
                client.post('/api/agent/jobs/' + self.job['id'] + '/renew',
                            {'lease_token': self.job['lease_token']}, self.config['token'])
                self.last_success = time.monotonic()
                # Inventory stays live during downloads. Failure also fences further changes.
                client.post('/api/agent/heartbeat', collect(self.config['instance_id']), self.config['token'])
        except AgentConnectionError as exc:
            self.error = exc
        except Exception:
            self.error = AgentConnectionError('Job lease renewal failed')

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(35)
