"""Human-in-the-loop approvals for risky (write) tool calls. Fails closed."""
from __future__ import annotations

import threading
import uuid


class ApprovalQueue:
    """mode: 'control-plane' waits for POST /approvals/{id}/approve|deny,
    'deny' rejects every request, 'allow' approves every request (tests/demos only)."""

    def __init__(self, mode: str = "deny", timeout_s: float = 30.0):
        if mode not in ("control-plane", "deny", "allow"):
            raise ValueError(mode)
        self.mode = mode
        self.timeout_s = timeout_s
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}

    def request(self, tool: str, arguments: dict) -> tuple[bool, str]:
        """Block until a decision. Returns (approved, reason)."""
        if self.mode == "allow":
            return True, "auto-approved"
        if self.mode == "deny":
            return False, "approval required and no approver configured"
        aid = uuid.uuid4().hex[:8]
        entry = {"id": aid, "tool": tool, "arguments": arguments, "event": threading.Event(), "approved": None}
        with self._lock:
            self._pending[aid] = entry
        entry["event"].wait(self.timeout_s)
        with self._lock:
            self._pending.pop(aid, None)
        if entry["approved"] is True:
            return True, "approved by operator"
        if entry["approved"] is False:
            return False, "denied by operator"
        return False, "approval timed out"

    def resolve(self, aid: str, approved: bool) -> bool:
        with self._lock:
            entry = self._pending.get(aid)
        if not entry:
            return False
        entry["approved"] = approved
        entry["event"].set()
        return True

    def pending(self) -> list[dict]:
        with self._lock:
            return [{"id": e["id"], "tool": e["tool"], "arguments": e["arguments"]} for e in self._pending.values()]
