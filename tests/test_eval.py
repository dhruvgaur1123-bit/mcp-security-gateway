"""Regression gate: detection quality must not silently degrade."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
from run_eval import decide  # noqa: E402

from mcpgw.policy import Policy  # noqa: E402
from mcpgw.proxy import Checker  # noqa: E402


def _rates():
    checker = Checker(Policy.load(ROOT / "policy.yaml"))
    cases = [json.loads(l) for l in (ROOT / "eval" / "cases.jsonl").read_text().splitlines()]
    core = [c for c in cases if c["category"] in ("direct_injection", "obfuscated_injection", "tool_poisoning", "sensitive_args")]
    benign = [c for c in cases if c["category"] in ("benign", "benign_hard")]
    pii = [c for c in cases if c["category"] == "pii_in_result"]
    ok = lambda cs: sum(decide(checker, c) == c["expect"] for c in cs) / len(cs)  # noqa: E731
    return ok(core), ok(benign), ok(pii)


def test_quality_floor():
    core, benign, pii = _rates()
    assert core >= 0.95, f"core attack block rate fell to {core:.0%}"
    assert benign >= 0.85, f"benign pass rate fell to {benign:.0%}"
    assert pii >= 0.95, f"PII redaction rate fell to {pii:.0%}"
