"""End-to-end: real gateway process wrapping the toy server."""
import json
import threading
import time
import urllib.request


def text_of(resp):
    return resp["result"]["content"][0]["text"]


def test_benign_call_passes_through(gw):
    g = gw()
    r = g.call("search_notes", query="meeting")
    assert "Thursday" in text_of(r) and not r["result"].get("isError")


def test_indirect_injection_in_tool_result_is_blocked(gw):
    g = gw()
    r = g.call("search_notes", query="poisoned")
    assert r["result"]["isError"] and "Blocked by MCP Security Gateway" in text_of(r)
    assert "attacker@evil" not in text_of(r)


def test_pii_in_result_is_redacted(gw):
    g = gw()
    t = text_of(g.call("get_customer", id="42"))
    assert "priya.nair@example.com" not in t and "4111" not in t and "REDACTED" in t


def test_secrets_in_file_are_redacted(gw):
    g = gw()
    t = text_of(g.call("read_file", path="secrets.txt"))
    assert "AKIA" not in t and "ghp_" not in t


def test_denied_and_unknown_tools_never_reach_server(gw):
    g = gw()
    assert g.call("delete_file", path="readme.txt")["result"]["isError"]
    assert g.call("format_disk")["result"]["isError"]


def test_write_tool_fails_closed_without_approver(gw):
    g = gw()
    r = g.call("send_email", to="bob@corp.example", body="hi")
    assert r["result"]["isError"] and "no approver" in text_of(r)


def test_write_tool_runs_after_human_approval(gw):
    port = 18765
    g = gw(extra_args=["--control-port", str(port)])
    time.sleep(1.0)                                   # let the control plane come up
    g.send("tools/call", {"name": "send_email", "arguments": {"to": "bob@corp.example", "body": "hi"}})
    pending = []
    for _ in range(40):
        pending = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/approvals"))
        if pending:
            break
        time.sleep(0.1)
    assert pending and pending[0]["tool"] == "send_email"
    urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/approvals/{pending[0]['id']}/approve", method="POST"))
    assert "email sent" in text_of(g.recv())
    assert any(e["decision"] == "approved" for e in g.audit())


def test_poisoned_tool_description_is_dropped(gw):
    g = gw(env={"POISON_TOOLS": "1"})
    names = g.tools()
    assert "add_numbers" not in names and "search_notes" in names


def test_rug_pull_is_detected(gw):
    g = gw(env={"RUG_PULL": "1"})
    assert "search_notes" in g.tools()
    assert "search_notes" not in g.tools()            # description changed on 2nd listing


def test_audit_log_records_decisions(gw):
    g = gw()
    g.call("search_notes", query="meeting")
    g.call("delete_file", path="x")
    log = g.audit()
    assert {"allow", "block"} <= {e["decision"] for e in log}
