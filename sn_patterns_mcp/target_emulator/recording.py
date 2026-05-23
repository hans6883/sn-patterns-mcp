"""Interaction recording for the Tier-3 emulator.

Every request the emulator answers is appended to a `Recorder` as one
`Interaction`. When a file path is configured, each interaction is also
flushed to a JSONL file so a long-running emulator session survives crashes
and so Phase 3 (record/replay) has a stable on-disk artifact to consume.

Format (one JSON object per line):
    {
      "ts": "2026-05-23T19:00:00.123456+00:00",
      "proto": "snmp",
      "client": "127.0.0.1:54321",
      "request":  { ... protocol-specific ... },
      "response": { ... protocol-specific ... },
      "error":    null or "string"
    }

Phase 3 will add a `Replayer` that reads this file back and verifies a new
emulator session produces byte-identical responses to the recorded ones.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Interaction:
    ts: str
    proto: str
    client: str
    request: dict[str, Any]
    response: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_json_line(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


class Recorder:
    """Thread-safe in-memory recorder with optional JSONL persistence.

    `path` is opened in append mode; existing content is preserved. Pass
    None to keep the recording in-memory only (useful for tests).
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer: list[Interaction] = []
        self._lock = Lock()

    def append(
        self,
        *,
        proto: str,
        client: str,
        request: dict[str, Any],
        response: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Interaction:
        interaction = Interaction(
            ts=_now_iso(),
            proto=proto,
            client=client,
            request=dict(request),
            response=dict(response or {}),
            error=error,
        )
        with self._lock:
            self._buffer.append(interaction)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(interaction.to_json_line() + "\n")
        return interaction

    def all(self) -> list[Interaction]:
        with self._lock:
            return list(self._buffer)

    def count(self) -> int:
        with self._lock:
            return len(self._buffer)

    def reset(self) -> None:
        """Clear in-memory buffer AND delete the on-disk file if any."""
        with self._lock:
            self._buffer.clear()
            if self.path is not None and self.path.exists():
                self.path.unlink()

    @classmethod
    def load(cls, path: Path) -> list[Interaction]:
        """Read a JSONL recording file into Interaction records (no Recorder needed)."""
        out: list[Interaction] = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(Interaction(
                ts=d.get("ts", ""),
                proto=d.get("proto", ""),
                client=d.get("client", ""),
                request=d.get("request", {}),
                response=d.get("response", {}),
                error=d.get("error"),
            ))
        return out
