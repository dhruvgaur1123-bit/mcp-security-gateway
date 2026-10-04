"""Side-by-side demo: the same agent requests, with and without the gateway.

    python demo/run_demo.py
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = [sys.executable, str(ROOT / "demo" / "toy_server.py")]
GATEWAY = [sys.executable, "-m", "mcpgw.cli", "--policy", str(ROOT / "policy.yaml"), "--audit", "/tmp/mcpgw-demo-audit.jsonl", "--"] + SERVER

REQUESTS = [
    ("poisoned note (indirect injection)", "search_notes", {"query": "poisoned"}),
    ("customer record (PII)", "get_customer", {"id": "42"}),
    ("file with secrets", "read_file", {"path": "secrets.txt"}),
    ("dangerous tool", "delete_file", {"path": "readme.txt"}),
    ("normal note", "search_notes", {"query": "meeting"}),
]


def run(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, cwd=ROOT)
    out = []
    for i, (_, tool, args) in enumerate(REQUESTS, 1):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args}}) + "\n")
        p.stdin.flush()
        out.append(json.loads(p.stdout.readline())["result"]["content"][0]["text"])
    p.stdin.close()
    p.wait(timeout=5)
    return out


if __name__ == "__main__":
    raw, guarded = run(SERVER), run(GATEWAY)
    for (label, _, _), a, b in zip(REQUESTS, raw, guarded):
        print(f"\n== {label}\n  WITHOUT gateway: {a[:150]}\n  WITH gateway:    {b[:150]}")
