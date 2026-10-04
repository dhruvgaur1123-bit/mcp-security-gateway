"""Command line: mcpgw --policy policy.yaml [--control-port 8765] -- <server command ...>"""
from __future__ import annotations

import argparse
import sys

from .approvals import ApprovalQueue
from .audit import Audit
from .policy import Policy
from .proxy import Gateway


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mcpgw", description="Security gateway for MCP stdio servers")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--audit", default="audit.jsonl", help="JSONL audit log path")
    ap.add_argument("--control-port", type=int, default=0, help="enable the FastAPI control plane on this port")
    ap.add_argument("--control-host", default="127.0.0.1")
    ap.add_argument("--approval-mode", choices=["control-plane", "deny", "allow"], default=None,
                    help="default: control-plane if --control-port is set, otherwise deny (fail closed)")
    ap.add_argument("server_cmd", nargs=argparse.REMAINDER, help="-- <command that starts the MCP server>")
    args = ap.parse_args(argv)
    cmd = args.server_cmd[1:] if args.server_cmd and args.server_cmd[0] == "--" else args.server_cmd
    if not cmd:
        ap.error("missing server command after --")

    policy = Policy.load(args.policy)
    audit = Audit(args.audit)
    mode = args.approval_mode or ("control-plane" if args.control_port else "deny")
    approvals = ApprovalQueue(mode, policy.approval_timeout_s)

    if args.control_port:
        from .control import create_app, serve_in_background
        serve_in_background(create_app(policy, audit, approvals), args.control_host, args.control_port)
        print(f"[mcpgw] control plane on http://{args.control_host}:{args.control_port}", file=sys.stderr)

    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    return Gateway(cmd, policy, audit, approvals).run()


if __name__ == "__main__":
    raise SystemExit(main())
