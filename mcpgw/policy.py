"""Policy loading. Unknown tools are denied by default (allowlist model)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_ACTIONS = {"allow", "deny", "require_approval"}
VALID_PII_ACTIONS = {"allow", "block", "redact"}


@dataclass
class ToolRule:
    action: str = "allow"
    pii_in_args: str | None = None                      # overrides the policy default
    allow_rules: set[str] = field(default_factory=set)  # PII rules permitted in args, e.g. {"email"}


@dataclass
class Policy:
    default_action: str = "deny"
    tools: dict[str, ToolRule] = field(default_factory=dict)
    scan_arguments: bool = True
    scan_results: bool = True
    scan_tool_descriptions: bool = True
    injection_threshold: int = 5
    args_pii_action: str = "block"
    results_pii_action: str = "redact"
    approval_timeout_s: float = 30.0

    def rule_for(self, tool: str) -> ToolRule:
        if tool in self.tools:
            return self.tools[tool]
        return ToolRule(action=self.default_action)

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        tools = {}
        for name, spec in (d.get("tools") or {}).items():
            spec = spec or {}
            tools[name] = ToolRule(
                action=spec.get("action", "allow"),
                pii_in_args=spec.get("pii_in_args"),
                allow_rules=set(spec.get("allow_rules", [])),
            )
        inspect = d.get("inspect") or {}
        p = cls(
            default_action=d.get("default_action", "deny"),
            tools=tools,
            scan_arguments=inspect.get("arguments", True),
            scan_results=inspect.get("results", True),
            scan_tool_descriptions=inspect.get("tool_descriptions", True),
            injection_threshold=int(d.get("injection_threshold", 5)),
            args_pii_action=d.get("args_pii_action", "block"),
            results_pii_action=d.get("results_pii_action", "redact"),
            approval_timeout_s=float(d.get("approval_timeout_s", 30)),
        )
        p.validate()
        return p

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()) or {})

    def validate(self) -> None:
        if self.default_action not in VALID_ACTIONS:
            raise ValueError(f"bad default_action: {self.default_action}")
        for n, r in self.tools.items():
            if r.action not in VALID_ACTIONS:
                raise ValueError(f"tool {n}: bad action {r.action}")
            if r.pii_in_args and r.pii_in_args not in VALID_PII_ACTIONS:
                raise ValueError(f"tool {n}: bad pii_in_args {r.pii_in_args}")
        for a in (self.args_pii_action, self.results_pii_action):
            if a not in VALID_PII_ACTIONS:
                raise ValueError(f"bad pii action: {a}")

    def to_dict(self) -> dict:
        return {
            "default_action": self.default_action,
            "injection_threshold": self.injection_threshold,
            "args_pii_action": self.args_pii_action,
            "results_pii_action": self.results_pii_action,
            "approval_timeout_s": self.approval_timeout_s,
            "tools": {n: {"action": r.action, "pii_in_args": r.pii_in_args, "allow_rules": sorted(r.allow_rules)}
                      for n, r in self.tools.items()},
        }
