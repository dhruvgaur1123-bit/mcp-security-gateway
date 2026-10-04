"""Heuristic detectors for prompt injection, hidden text, PII, and secrets.

These are deliberately transparent (regex + weights) so every decision can be
explained in the audit log. They are a first line of defence, not a complete one:
see the "Limitations" section of the README and eval/ for measured misses.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# ---------------------------------------------------------------- normalisation
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")


def normalize(text: str) -> str:
    """Fold look-alike characters, drop invisible characters, collapse whitespace."""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(_ZERO_WIDTH)
    t = _TAG_CHARS.sub("", t)
    return re.sub(r"\s+", " ", t)


# ---------------------------------------------------------------- data classes
@dataclass
class Finding:
    kind: str          # injection | hidden_unicode | pii | secret
    rule: str
    weight: int = 0
    span: tuple[int, int] | None = None
    snippet: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "rule": self.rule, "weight": self.weight, "snippet": self.snippet}


@dataclass
class ScanResult:
    injection_score: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def injection_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind in ("injection", "hidden_unicode")]


# ---------------------------------------------------------------- injection rules
# (name, weight, regex, contexts where the rule applies)
_ALL = {"args", "result", "tool_desc"}
_UNTRUSTED = {"result", "tool_desc"}
_I = re.IGNORECASE

INJECTION_RULES: list[tuple[str, int, re.Pattern, set[str]]] = [
    ("ignore_previous_instructions", 5, re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|your)\b"
        r".{0,30}\b(instructions?|rules?|prompts?|directions?|guidelines?)\b", _I), _ALL),
    ("reveal_system_prompt", 5, re.compile(
        r"\b(reveal|print|show|repeat|output|leak|display)\b.{0,30}\b(system|hidden|initial|secret)\b"
        r".{0,15}\b(prompt|instructions?|message)\b", _I), _ALL),
    ("role_hijack", 3, re.compile(
        r"\byou are now\b|\bfrom now on,? you\b|\bact as (an? )?(unrestricted|admin|root|dan)\b|\bnew (instructions?|task)\s*:", _I), _ALL),
    ("fake_system_tag", 4, re.compile(
        r"<\s*/?\s*(system|assistant|im_start|im_end|instructions?)\s*>|\[\s*(system|inst)\s*\]|#{2,}\s*(system|instruction)", _I), _ALL),
    ("secrecy_from_user", 3, re.compile(
        r"\b(do not|don't|never)\b.{0,25}\b(tell|inform|mention|notify|alert|show)\b.{0,25}\b(the )?(user|human|operator)\b", _I), _ALL),
    ("exfiltration_directive", 5, re.compile(
        r"\b(?:send|forward|post|upload|exfiltrate|transmit|leak|email\s+(?:the|all|any|this|that|it|them|everything|your|my|contents?))\b"
        r".{0,60}\b(?:to|at)\b.{0,40}(?:@[\w.-]+\.\w+|https?://)", _I), _UNTRUSTED),
    ("tool_call_directive", 3, re.compile(
        r"\b(before|first|instead|then|always|immediately)\b.{0,40}\b(call|invoke|use|run|execute)\b.{0,30}\b(tool|function|command)\b", _I), _UNTRUSTED),
    ("important_tag", 4, re.compile(r"<\s*(important|secret|hidden)\s*>", _I), _UNTRUSTED),
    ("sensitive_file_access", 4, re.compile(
        r"\b(read|cat|open|include|attach|send)\b.{0,40}(\.ssh|id_rsa|\.env\b|/etc/passwd|credentials|api[_ -]?keys?)", _I), _ALL),
    ("encoded_payload", 2, re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"), _UNTRUSTED),
]


def _hidden_unicode_findings(raw: str) -> list[Finding]:
    out = []
    tags = len(_TAG_CHARS.findall(raw))
    if tags:
        out.append(Finding("hidden_unicode", "unicode_tag_characters", 5, snippet=f"{tags} tag chars"))
    zw = sum(raw.count(c) for c in "\u200b\u200c\u200d\u2060\ufeff")
    if zw >= 3:
        out.append(Finding("hidden_unicode", "zero_width_characters", 2, snippet=f"{zw} zero-width chars"))
    return out


def scan_injection(text: str, context: str = "result") -> ScanResult:
    """Score text for prompt-injection indicators. context: args | result | tool_desc."""
    res = ScanResult()
    for f in _hidden_unicode_findings(text):
        res.findings.append(f)
        res.injection_score += f.weight
    norm = normalize(text)
    for name, weight, rx, contexts in INJECTION_RULES:
        if context not in contexts:
            continue
        m = rx.search(norm)
        if m:
            res.findings.append(Finding("injection", name, weight, m.span(), norm[m.start():m.end()][:80]))
            res.injection_score += weight
    return res


# ---------------------------------------------------------------- PII / secrets
def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits][::-1]
    total = sum(nums[0::2]) + sum(sum(divmod(d * 2, 10)) for d in nums[1::2])
    return total % 10 == 0


_PII_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("secret", "private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("secret", "aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret", "github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("secret", "google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("secret", "generic_secret_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("pii", "ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("pii", "credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("pii", "email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("pii", "phone", re.compile(r"(?<![\w-])(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}(?![\w-])")),
]


def find_pii(text: str) -> list[Finding]:
    """Return non-overlapping PII/secret findings with spans into `text`."""
    found: list[Finding] = []
    for kind, rule, rx in _PII_PATTERNS:
        for m in rx.finditer(text):
            if rule == "credit_card":
                digits = re.sub(r"\D", "", m.group())
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
            if any(m.start() < f.span[1] and f.span[0] < m.end() for f in found):
                continue  # overlaps an earlier (higher-priority) finding
            found.append(Finding(kind, rule, 0, m.span(), f"[{rule}]"))
    return sorted(found, key=lambda f: f.span[0])


def redact(text: str, allow_rules: set[str] | None = None) -> tuple[str, list[Finding]]:
    """Replace PII/secrets with [REDACTED:rule] markers; returns (new_text, findings_redacted)."""
    allow_rules = allow_rules or set()
    hits = [f for f in find_pii(text) if f.rule not in allow_rules]
    for f in reversed(hits):
        text = text[: f.span[0]] + f"[REDACTED:{f.rule}]" + text[f.span[1]:]
    return text, hits
