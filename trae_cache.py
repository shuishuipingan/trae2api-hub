"""Small JSON-result cache with fixed expiry, memory limits and single-flight misses.

No credentials, request bodies or inference responses should be stored here.
Used exclusively for local dashboard analytics. The builder runs outside the lock.
"""
import json
import threading
import time
from collections import OrderedDict


class JsonResultCache:
    def __init__(self, max_entries=32, max_bytes=16 * 1024 * 1024):
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._entries = OrderedDict()
        self._pending = {}
        self._bytes = 0
        self._hits = self._misses = self._waits = 0

    def get(self, key, builder, ttl=5.0, valid=None):
        if ttl <= 0:
            return builder()
        while True:
            with self._lock:
                now = time.monotonic()
                entry = self._entries.get(key)
                if entry is not None:
                    if now < entry[0]:
                        self._entries.move_to_end(key)
                        self._hits += 1
                        encoded = entry[1]
                        break
                    self._bytes -= len(entry[1])
                    del self._entries[key]
                event = self._pending.get(key)
                if event is None:
                    event = threading.Event()
                    self._pending[key] = event
                    self._misses += 1
                    owner = True
                else:
                    self._waits += 1
                    owner = False
            if not owner:
                # Recheck expiry/exception after owner signals; no global scan lock.
                event.wait()
                continue
            try:
                result = builder()
                data = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(data) <= self.max_bytes and (valid is None or valid()):
                    with self._lock:
                        old = self._entries.pop(key, None)
                        if old:
                            self._bytes -= len(old[1])
                        self._entries[key] = (time.monotonic() + ttl, data)
                        self._bytes += len(data)
                        while (len(self._entries) > self.max_entries
                               or self._bytes > self.max_bytes):
                            _, expired = self._entries.popitem(last=False)
                            self._bytes -= len(expired[1])
                return result
            finally:
                with self._lock:
                    self._pending.pop(key, None)
                    event.set()
        # Each caller owns its result. Mutations never corrupt a shared snapshot.
        return json.loads(encoded)

    def status(self):
        with self._lock:
            return {"entries": len(self._entries), "bytes": self._bytes,
                    "inflight": len(self._pending), "hits": self._hits,
                    "misses": self._misses, "coalesced": self._waits}
