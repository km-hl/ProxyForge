"""机场出站时间预算；系统 DNS 的迟到结果只释放容量，不触发连接。"""
import math
import socket
import threading
import time

import requests


DEFAULT_TOTAL_TIMEOUT = 60.0
DNS_TIMEOUT = 10.0
DNS_WORKERS = 8
_dns_slots = threading.BoundedSemaphore(DNS_WORKERS)
_STOP_POLL = 0.05


class OutboundTimeout(requests.Timeout):
    pass


class OutboundCancelled(requests.RequestException):
    pass


class OutboundCapacityError(requests.RequestException):
    pass


def check_outbound_deadline(deadline=None, stop_event=None):
    if stop_event is not None and stop_event.is_set():
        raise OutboundCancelled("订阅请求已停止")
    if deadline is not None and time.monotonic() >= deadline:
        raise OutboundTimeout("订阅请求超过总耗时限制")


def _positive_seconds(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be finite and positive")
    return float(value)


class RequestBudget:
    def __init__(self, total_timeout, *, deadline=None, stop_event=None):
        end = time.monotonic() + _positive_seconds(total_timeout)
        if deadline is not None:
            if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
                raise ValueError("deadline must be a finite monotonic timestamp")
            end = min(end, deadline)
        self.deadline = end
        self.stop_event = stop_event
        self._sockets = set()
        self._lock = threading.Lock()
        self._finished = threading.Event()
        self._closed = False

    def check(self):
        check_outbound_deadline(self.deadline, self.stop_event)

    def remaining(self):
        self.check()
        return max(self.deadline - time.monotonic(), 0.000001)

    def wait(self, event, limit=None):
        end = self.deadline if limit is None else min(self.deadline, time.monotonic() + limit)
        while True:
            self.check()
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise OutboundTimeout("订阅 DNS 等待超时")
            interval = min(remaining, _STOP_POLL) if self.stop_event is not None else remaining
            if event.wait(interval):
                self.check()
                if time.monotonic() >= end:
                    raise OutboundTimeout("订阅 DNS 等待超时")
                return

    @staticmethod
    def _shutdown(sock):
        try:
            # Interrupt blocked headers/body reads, including makefile readers.
            # The owning request thread remains responsible for close().
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def watch_socket(self, sock):
        with self._lock:
            self._sockets.add(sock)
            try:
                self.check()
            except (OutboundTimeout, OutboundCancelled):
                self._shutdown(sock)
                raise

    def _watch(self):
        while True:
            remaining = max(0, self.deadline - time.monotonic())
            interval = min(remaining, _STOP_POLL) if self.stop_event is not None else remaining
            if self._finished.wait(interval):
                return
            with self._lock:
                if self._closed:
                    return
                try:
                    self.check()
                except (OutboundTimeout, OutboundCancelled):
                    for sock in self._sockets:
                        self._shutdown(sock)
                    return

    def __enter__(self):
        self.check()
        threading.Thread(target=self._watch, name="outbound-deadline", daemon=True).start()
        return self

    def __exit__(self, *args):
        with self._lock:
            self._closed = True
            self._finished.set()
            self._sockets.clear()


def resolve_with_budget(resolve, hostname, port, budget):
    budget.check()
    slots = _dns_slots
    if not slots.acquire(blocking=False):
        raise OutboundCapacityError("订阅 DNS 解析容量已满")
    done = threading.Event()
    result = []
    errors = []

    def worker():
        try:
            result.append(tuple(resolve(hostname, port)))
        except BaseException as exc:
            errors.append(exc)
        finally:
            slots.release()
            done.set()

    try:
        threading.Thread(target=worker, name="outbound-dns", daemon=True).start()
    except BaseException:
        slots.release()
        raise
    # A timed-out worker owns only its local result and semaphore slot. It has
    # no session/socket callback and never commits data or starts a connection.
    budget.wait(done, DNS_TIMEOUT)
    if errors:
        raise errors[0]
    return result[0]
