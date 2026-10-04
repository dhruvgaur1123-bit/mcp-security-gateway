import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class GatewayProc:
    """Spawns the real CLI around the toy server and talks JSON-RPC over its stdio."""

    def __init__(self, tmp_path, env=None, extra_args=None):
        self.audit_path = tmp_path / "audit.jsonl"
        cmd = [sys.executable, "-m", "mcpgw.cli", "--policy", str(ROOT / "policy.yaml"), "--audit", str(self.audit_path),
               *(extra_args or []), "--", sys.executable, str(ROOT / "demo" / "toy_server.py")]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  cwd=ROOT, env={**os.environ, **(env or {}), "PYTHONPATH": str(ROOT)})
        self._id = 0

    def send(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method, **({"params": params} if params is not None else {})}
        if not notify:
            self._id += 1
            msg["id"] = self._id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        return None if notify else self._id

    def recv(self, timeout=10):
        out = {}

        def _r():
            out["line"] = self.p.stdout.readline()

        t = threading.Thread(target=_r, daemon=True)
        t.start()
        t.join(timeout)
        assert "line" in out and out["line"], "gateway produced no output (timeout)"
        return json.loads(out["line"])

    def call(self, name, **arguments):
        self.send("tools/call", {"name": name, "arguments": arguments})
        return self.recv()

    def tools(self):
        self.send("tools/list")
        return [t["name"] for t in self.recv()["result"]["tools"]]

    def audit(self):
        time.sleep(0.2)
        if not self.audit_path.exists():
            return []
        return [json.loads(l) for l in self.audit_path.read_text().splitlines()]

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


@pytest.fixture
def gw(tmp_path):
    procs = []

    def make(env=None, extra_args=None):
        g = GatewayProc(tmp_path, env, extra_args)
        procs.append(g)
        g.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
        g.recv()
        return g

    yield make
    for g in procs:
        g.close()
