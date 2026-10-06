"""The gateway: a transparent MCP stdio proxy that enforces policy on every tool call.

            +--------+  stdin/stdout   +--------------+  stdin/stdout   +------------+
            | client | <-------------> |   gateway    | <-------------> | MCP server |
            +--------+                 +--------------+                 +------------+
   client -> server : tools/call is checked (policy, injection, PII/secrets, approval)
   server -> client : tools/list is filtered (poisoned/changed tools), tool results are
                      scanned for indirect prompt injection and redacted for PII.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, IO

from .approvals import ApprovalQueue
from .audit import Audit
from .detectors import Finding, redact, scan_injection
from .policy import Policy


# ------------------------------------------------------------------ helpers
def map_strings(obj: Any, fn: Callable[[str], str]) -> Any:
    """Apply fn to every string value in a JSON-like structure."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [map_strings(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: map_strings(v, fn) for k, v in obj.items()}
    return obj


def iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for x in obj:
            yield from iter_strings(x)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)


def blocked_result(rid, reason: str) -> dict:
    """MCP-conformant tool error: the model sees why the call did not go through."""
    return {"jsonrpc": "2.0", "id": rid, "result": {
        "content": [{"type": "text", "text": f"Blocked by MCP Security Gateway: {reason}"}], "isError": True}}


@dataclass
class Decision:
    action: str                      # forward | block | approve
    reason: str = ""
    arguments: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


# ------------------------------------------------------------------ core checks
class Checker:
    """Pure policy logic, separated from I/O so it can be tested and evaluated directly."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def check_call(self, tool: str, arguments: dict) -> Decision:
        p = self.policy
        rule = p.rule_for(tool)
        if rule.action == "deny":
            why = "tool is denied by policy" if tool in p.tools else "tool is not on the allowlist"
            return Decision("block", why)
        findings: list[Finding] = []
        args = arguments or {}
        if p.scan_arguments:
            score, inj = 0, []
            for s in iter_strings(args):
                res = scan_injection(s, "args")
                score += res.injection_score
                inj += res.injection_findings
            findings += inj
            if score >= p.injection_threshold:
                return Decision("block", f"prompt-injection indicators in arguments (score {score})", args, findings)
            mode = rule.pii_in_args or p.args_pii_action
            if mode != "allow":
                hits: list[Finding] = []

                def _scrub(s: str) -> str:
                    new, h = redact(s, rule.allow_rules)
                    hits.extend(h)
                    return new

                cleaned = map_strings(args, _scrub)
                if hits:
                    findings += hits
                    kinds = sorted({h.rule for h in hits})
                    if mode == "block":
                        return Decision("block", f"sensitive data in arguments: {', '.join(kinds)}", args, findings)
                    args = cleaned  # redact
        if rule.action == "require_approval":
            return Decision("approve", "write action requires approval", args, findings)
        return Decision("forward", "ok", args, findings)

    def tool_definition_score(self, tool: dict) -> int:
        return sum(scan_injection(s, "tool_desc").injection_score for s in iter_strings(tool))

    def check_result(self, result: dict) -> tuple[dict, str, list[Finding]]:
        """Returns (possibly rewritten result, decision, findings)."""
        p = self.policy
        if not p.scan_results:
            return result, "allow", []
        score, findings = 0, []
        for s in iter_strings(result):
            res = scan_injection(s, "result")
            score += res.injection_score
            findings += res.injection_findings
        if score >= p.injection_threshold:
            return ({"content": [{"type": "text", "text": (
                f"Blocked by MCP Security Gateway: tool output contained prompt-injection indicators (score {score}).")}],
                "isError": True}, "block", findings)
        if p.results_pii_action == "allow":
            return result, "allow", findings
        hits: list[Finding] = []

        def _scrub(s: str) -> str:
            new, h = redact(s)
            hits.extend(h)
            return new

        cleaned = map_strings(result, _scrub)
        if hits:
            if p.results_pii_action == "block":
                return ({"content": [{"type": "text", "text": "Blocked by MCP Security Gateway: tool output contained sensitive data."}],
                         "isError": True}, "block", findings + hits)
            return cleaned, "redact", findings + hits
        return result, "allow", findings


# ------------------------------------------------------------------ gateway I/O
class Gateway:
    def __init__(self, server_cmd: list[str], policy: Policy, audit: Audit, approvals: ApprovalQueue,
                 client_in: IO[str] | None = None, client_out: IO[str] | None = None):
        self.cmd = server_cmd
        self.policy = policy
        self.checker = Checker(policy)
        self.audit = audit
        self.approvals = approvals
        self._in = client_in or sys.stdin
        self._out = client_out or sys.stdout
        self._out_lock = threading.Lock()
        self._srv_lock = threading.Lock()
        self._pending_calls: dict[Any, str] = {}   # request id -> tool name
        self._list_ids: set = set()
        self._tool_hashes: dict[str, str] = {}
        self.proc: subprocess.Popen | None = None

    # -- output helpers
    def _to_client(self, obj: dict) -> None:
        with self._out_lock:
            self._out.write(json.dumps(obj, ensure_ascii=False) + "\n")
            self._out.flush()

    def _to_server(self, line: str) -> None:
        with self._srv_lock:
            assert self.proc and self.proc.stdin
            try:
                self.proc.stdin.write(line.rstrip("\n") + "\n")
                self.proc.stdin.flush()
            except BrokenPipeError:
                pass

    # -- client -> server
    def _client_loop(self) -> None:
        for line in self._in:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._to_server(line)
                continue
            try:
                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    self._handle_call(msg)
                else:
                    if isinstance(msg, dict) and msg.get("method") == "tools/list" and "id" in msg:
                        self._list_ids.add(msg["id"])
                    self._to_server(line)
            except Exception as e:   # fail closed: tell the client instead of silently dropping the request
                print(f"[mcpgw] internal error handling message: {e!r}", file=sys.stderr)
                if isinstance(msg, dict) and msg.get("id") is not None:
                    self._to_client(blocked_result(msg["id"], "gateway internal error (request not forwarded)"))
        if self.proc and self.proc.stdin:   # client closed: let the server shut down
            try:
                self.proc.stdin.close()
            except Exception:
                pass

    def _handle_call(self, msg: dict) -> None:
        params = msg.get("params") or {}
        tool, rid = params.get("name", ""), msg.get("id")
        d = self.checker.check_call(tool, params.get("arguments") or {})
        base = {"tool": tool, "findings": [f.to_dict() for f in d.findings]}
        if d.action == "block":
            self.audit.log("tool_call", "block", reason=d.reason, **base)
            self._to_client(blocked_result(rid, d.reason))
            return
        if d.action == "approve":
            threading.Thread(target=self._approve_and_forward, args=(msg, d, base), daemon=True).start()
            return
        self.audit.log("tool_call", "allow", reason=d.reason, **base)
        self._forward_call(msg, d.arguments)

    def _approve_and_forward(self, msg: dict, d: Decision, base: dict) -> None:
        tool, rid = base["tool"], msg.get("id")
        ok, why = self.approvals.request(tool, d.arguments)
        if ok:
            self.audit.log("tool_call", "approved", reason=why, **base)
            self._forward_call(msg, d.arguments)
        else:
            self.audit.log("tool_call", "block", reason=why, **base)
            self._to_client(blocked_result(rid, why))

    def _forward_call(self, msg: dict, arguments: dict) -> None:
        msg = {**msg, "params": {**(msg.get("params") or {}), "arguments": arguments}}
        if "id" in msg:
            self._pending_calls[msg["id"]] = msg["params"].get("name", "")
        self._to_server(json.dumps(msg, ensure_ascii=False))

    # -- server -> client
    def _server_loop(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                with self._out_lock:
                    self._out.write(line + "\n")
                    self._out.flush()
                continue
            if isinstance(msg, dict) and "result" in msg and "id" in msg:
                rid = msg["id"]
                if rid in self._list_ids:
                    self._list_ids.discard(rid)
                    msg["result"] = self._filter_tools_list(msg["result"])
                elif rid in self._pending_calls:
                    tool = self._pending_calls.pop(rid)
                    new, decision, findings = self.checker.check_result(msg["result"])
                    msg["result"] = new
                    if decision != "allow" or findings:
                        self.audit.log("tool_result", decision, tool=tool, findings=[f.to_dict() for f in findings])
            self._to_client(msg)

    def _filter_tools_list(self, result: dict) -> dict:
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list) or not self.policy.scan_tool_descriptions:
            return result
        kept = []
        for tool in result["tools"]:
            name = tool.get("name", "")
            blob = json.dumps(tool, sort_keys=True)
            digest = hashlib.sha256(blob.encode()).hexdigest()
            score = self.checker.tool_definition_score(tool)
            if score >= self.policy.injection_threshold:
                self.audit.log("tool_list", "block", tool=name, reason=f"poisoned tool description (score {score})")
                continue
            old = self._tool_hashes.get(name)
            if old and old != digest:
                self.audit.log("tool_list", "block", tool=name, reason="tool definition changed after first use (possible rug pull)")
                continue
            self._tool_hashes[name] = digest
            kept.append(tool)
        return {**result, "tools": kept}

    # -- lifecycle
    def run(self) -> int:
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
                                     text=True, encoding="utf-8", bufsize=1)
        t = threading.Thread(target=self._client_loop, daemon=True)
        t.start()
        self._server_loop()
        return self.proc.wait()
