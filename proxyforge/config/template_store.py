"""Recoverable configuration writes and bounded template history.

All cooperating readers/writers use one reentrant thread + OS file lock.
A durable redo journal is the commit point: interrupted commits finish before
the next read. Never place this directory on a shared/network filesystem.
"""
import contextlib
import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_TEMPLATE_BYTES = 1024 * 1024
MAX_HISTORY_BYTES = 32 * 1024 * 1024
FILES = {"template.yaml", "custom_nodes.yaml", "airports.yaml"}
_registry = {}
_registry_lock = threading.Lock()


class TemplateConflict(Exception):
    def __init__(self, current):
        self.current = current


class ConfigurationTooLarge(ValueError):
    pass


def revision(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class TemplateStore:
    def __init__(self, path, history_limit=30):
        self.path = Path(path).resolve()
        self.root = self.path.parent
        self.history = self.root / "history" / "template"
        self.journal = self.root / ".config-transaction.json"
        self.limit = max(2, min(int(history_limit), 100))
        with _registry_lock:
            self._thread_lock, self._local = _registry.setdefault(
                str(self.root), (threading.RLock(), threading.local()))

    @contextlib.contextmanager
    def locked(self):
        with self._thread_lock:
            if getattr(self._local, "depth", 0):
                self._local.depth += 1
                try:
                    yield
                finally:
                    self._local.depth -= 1
                return
            self.root.mkdir(parents=True, exist_ok=True)
            lock_path = self.root / ".config.lock"
            fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            with os.fdopen(fd, "r+b") as lock:
                if os.name == "nt":
                    import msvcrt
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
                    # Windows byte-range locks also cover reads. Initialize only
                    # after acquiring the lock (locking beyond EOF is valid).
                    if os.fstat(lock.fileno()).st_size == 0:
                        lock.write(b"0")
                        lock.flush()
                else:
                    import fcntl
                    fcntl.flock(lock, fcntl.LOCK_EX)
                self._local.depth = 1
                try:
                    self._recover()
                    yield
                finally:
                    self._local.depth = 0
                    if os.name == "nt":
                        lock.seek(0)
                        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(lock, fcntl.LOCK_UN)

    def _content(self):
        return self.path.read_bytes().decode("utf-8") if self.path.exists() else ""

    def snapshot(self):
        with self.locked():
            content = self._content()
            return {"content": content, "revision": revision(content)}

    def expect(self, expected):
        current = self.snapshot()
        if current["revision"] != expected:
            raise TemplateConflict(current)
        return current

    def _record(self, content, source):
        return {"id": uuid.uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
                "revision": revision(content), "size": len(content.encode("utf-8")),
                "source": source, "content": content}

    def commit(self, updates, source="save"):
        with self.locked():
            if not updates or not set(updates) <= FILES:
                raise ValueError("Invalid configuration paths")
            for value in updates.values():
                if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_TEMPLATE_BYTES:
                    raise ConfigurationTooLarge("Configuration exceeds 1 MiB limit")
            before = self._content()
            after = updates.get("template.yaml", before)
            records = []
            if before != after:
                if not self.history.exists() or not any(self.history.glob("*.json")):
                    records.append(self._record(before, "baseline"))
                records.append(self._record(after, source))
            changed = {name: content for name, content in updates.items()
                       if not (self.root / name).exists()
                       or (self.root / name).read_bytes() != content.encode("utf-8")}
            if changed:
                atomic_write(self.journal, json.dumps({"files": changed, "history": records}))
                self._recover()
            return self.snapshot()

    def _recover(self):
        if not self.journal.exists():
            return
        transaction = json.loads(self.journal.read_text(encoding="utf-8"))
        if not set(transaction["files"]) <= FILES:
            raise ValueError("Invalid transaction")
        for name, content in transaction["files"].items():
            atomic_write(self.root / name, content)
        for record in transaction["history"]:
            if not re.fullmatch(r"[a-f0-9]{32}", record["id"]):
                raise ValueError("Invalid history ID")
            atomic_write(self.history / (record["id"] + ".json"), json.dumps(record))
        self._prune()
        self.journal.unlink()
        sync_directory(self.root)

    def _records(self):
        if not self.history.exists():
            return []
        return sorted((json.loads(p.read_text(encoding="utf-8"))
                       for p in self.history.glob("*.json")),
                      key=lambda r: (r["timestamp"], r["id"]), reverse=True)

    def _prune(self):
        total = 0
        for index, record in enumerate(self._records()):
            total += record["size"]
            if index >= self.limit or total > MAX_HISTORY_BYTES:
                (self.history / (record["id"] + ".json")).unlink()

    def list_history(self):
        with self.locked():
            return [{k: v for k, v in r.items() if k != "content"} for r in self._records()]

    def history_entry(self, entry_id):
        if not re.fullmatch(r"[a-f0-9]{32}", entry_id):
            raise FileNotFoundError("History entry not found")
        with self.locked():
            return json.loads((self.history / (entry_id + ".json")).read_text(encoding="utf-8"))
