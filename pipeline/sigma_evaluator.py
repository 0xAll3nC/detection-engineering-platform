"""
sigma_evaluator.py
------------------
A small, dependency-light Sigma rule evaluator used for FAST unit testing
of detection logic against sample log events (as Python dicts / JSON).

This is deliberately NOT a full Sigma implementation -- it supports the
subset of the spec our rules actually use:

  - logsource / detection / condition blocks
  - field modifiers: |contains, |endswith, |startswith (case-insensitive,
    matching Sigma's default string-matching behavior)
  - list values on a field = logical OR across the list
  - multiple fields in one selection = logical AND
  - condition expressions: "all of <pattern>", "N of <pattern>", "them",
    wildcard selection names ("selection_*"), and plain "and/or/not"
    combinations of named selections.

Why this exists instead of only using pySigma: pySigma compiles rules into
backend queries (see pipeline/compile_rules.py) -- great for deployment,
but proving "does this rule's *logic* actually match this exact event" is
much faster and CI-friendly as a pure-Python unit test with no SIEM/query
engine involved. Real detection engineering teams typically run both
layers: fast logic unit tests here, and slower replay/integration tests
against the real indexer.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    path: Path
    title: str
    rule_id: str
    level: str
    tags: list[str]
    logsource: dict[str, Any]
    detection: dict[str, Any]

    @classmethod
    def load(cls, path: Path) -> "SigmaRule":
        raw = yaml.safe_load(path.read_text())
        return cls(
            path=path,
            title=raw["title"],
            rule_id=raw["id"],
            level=raw.get("level", "medium"),
            tags=raw.get("tags", []),
            logsource=raw.get("logsource", {}),
            detection=raw["detection"],
        )

    @property
    def selections(self) -> dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k != "condition"}

    @property
    def condition(self) -> str:
        return self.detection["condition"]

    @property
    def attack_techniques(self) -> list[str]:
        """Return tags like 'attack.t1003.001' as uppercased technique IDs."""
        techniques = []
        for tag in self.tags:
            m = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)$", tag, re.IGNORECASE)
            if m:
                techniques.append(f"T{m.group(1)}")
        return techniques

    def matches(self, event: dict[str, Any], case_sensitive: bool = False) -> bool:
        """Evaluate the rule against one event.

        case_sensitive=False (default) is Sigma's specified string-matching
        semantics. case_sensitive=True models how the compiled OpenSearch
        Lucene wildcards behave on Wazuh's un-normalised `keyword` fields
        (confirmed live 2026-10-11, see docs/validation/). It exists only so
        backend-semantics tests can document that gap; it is not a second
        definition of what a rule should match.
        """
        selection_results = {
            name: _match_selection(event, spec, case_sensitive)
            for name, spec in self.selections.items()
        }
        return _evaluate_condition(self.condition, selection_results)


def _match_field(
    event: dict[str, Any], field_key: str, expected: Any, case_sensitive: bool = False
) -> bool:
    if "|" in field_key:
        field, modifier = field_key.split("|", 1)
    else:
        field, modifier = field_key, None

    actual = event.get(field)
    if actual is None:
        return False
    fold = (lambda x: x) if case_sensitive else str.lower
    actual_str = fold(str(actual))

    values = expected if isinstance(expected, list) else [expected]
    for val in values:
        val_str = fold(str(val))
        if modifier == "contains":
            if val_str in actual_str:
                return True
        elif modifier == "endswith":
            if actual_str.endswith(val_str):
                return True
        elif modifier == "startswith":
            if actual_str.startswith(val_str):
                return True
        else:  # exact match
            if actual_str == val_str:
                return True
    return False


def _match_selection(
    event: dict[str, Any], selection_spec: dict[str, Any], case_sensitive: bool = False
) -> bool:
    # A selection is a mapping of field -> expected value(s); all fields
    # in the mapping must match (AND). A list value on one field is OR.
    return all(
        _match_field(event, field, expected, case_sensitive)
        for field, expected in selection_spec.items()
    )


_OF_PATTERN = re.compile(r"(?P<quant>\d+|all) of (?P<target>[\w\*]+)")


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    def resolve_of(match: re.Match) -> str:
        quant_raw, target = match.group("quant"), match.group("target")
        if target == "them":
            matching = list(selection_results.keys())
        elif "*" in target:
            matching = [n for n in selection_results if fnmatch.fnmatch(n, target)]
        else:
            matching = [target]

        count_true = sum(1 for n in matching if selection_results.get(n))
        if quant_raw == "all":
            result = len(matching) > 0 and count_true == len(matching)
        else:
            result = count_true >= int(quant_raw)
        return "True" if result else "False"

    expr = _OF_PATTERN.sub(resolve_of, condition)
    # Remaining identifiers are plain selection names referenced directly
    # (e.g. "selection and not filter_known_software").
    return bool(eval(expr, {"__builtins__": {}}, selection_results))  # noqa: S307 - trusted, local rule files only


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    return [SigmaRule.load(p) for p in sorted(rules_dir.rglob("*.yml"))]
