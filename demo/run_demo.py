"""Side-by-side demo: the same agent requests, with and without the gateway.

    python demo/run_demo.py
"""
import json
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = [sys.executable, str(ROOT / "demo" / "toy_server.py")]
GATEWAY = [sys.executable, "-m", "mcpgw.cli", "--policy", str(ROOT / "policy.yaml"), "--audit", str(Path(tempfile.gettempdir()) / "mcpgw-demo-audit.jsonl"), "--"] + SERVER

REQUESTS = [
    ("poisoned note (indirect injection)", "search_notes", {"query": "poisoned"}),
    ("customer record (PII)", "get_customer", {"id": "42"}),
    ("file with secrets", "read_file", {"path": "secrets.txt"}),
    ("dangerous tool", "delete_file", {"path": "readme.txt"}),
    ("normal note", "search_notes", {"query": "meeting"}),
]


def read_line(p, timeout=15):
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("line", p.stdout.readline()), daemon=True)
    t.start()
    t.join(timeout)
    if "line" not in box:
        p.kill()
        raise SystemExit("No response within %ss. Run the gateway by hand to see the error:\n  %s" % (timeout, " ".join(p.args)))
    if not box["line"]:
        raise SystemExit("The process exited without answering (see the error above): " + " ".join(p.args))
    return box["line"]


def run(cmd):
    # stderr is inherited so any gateway error is visible in your terminal
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", cwd=ROOT)
    out = []
    for i, (_, tool, args) in enumerate(REQUESTS, 1):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args}}) + "\n")
        p.stdin.flush()
        out.append(json.loads(read_line(p))["result"]["content"][0]["text"])
    p.stdin.close()
    p.wait(timeout=5)
    return out


if __name__ == "__main__":
    raw, guarded = run(SERVER), run(GATEWAY)
    for (label, _, _), a, b in zip(REQUESTS, raw, guarded):
        print(f"\n== {label}\n  WITHOUT gateway: {a[:150]}\n  WITH gateway:    {b[:150]}")
