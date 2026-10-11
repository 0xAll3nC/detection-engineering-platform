"""
Dependency-light Sigma rule evaluator used for FAST unit testing of detection
logic against sample events (Python dicts / JSON fixtures).

Deliberately NOT a full Sigma implementation. Supported subset:

  - field modifiers: |contains, |endswith, |startswith, and exact match
    (case-insensitive by default, matching Sigma's string semantics)
  - list values on a field = OR; multiple fields in a selection = AND
  - conditions: `and`, `or`, `not`, parentheses, `1 of x`, `N of x`,
    `all of x`, wildcard targets (`selection_*`) and `them`

Unsupported syntax raises an error instead of evaluating to False, so a rule
using a feature this evaluator does not implement cannot pass silently.

Why both this and pySigma: pySigma compiles rules to backend queries
(see sigma/compiler.py); proving "does this rule's logic match this exact
event" is much faster as a pure-Python unit test. The two layers do not have
identical semantics on every backend - see ADR-0003 and
tests/backend/ for documented divergences.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_MODIFIERS = {None, "contains", "endswith", "startswith"}


class UnsupportedSigmaFeature(ValueError):
    pass


@dataclass
class SigmaRule:
    path: Path
    title: str
    rule_id: str
    status: str
    level: str
    tags: list[str]
    logsource: dict[str, Any]
    detection: dict[str, Any]
    raw: dict[str, Any]

    @classmethod
    def load(cls, path: Path) -> SigmaRule:
        raw = yaml.safe_load(path.read_text())
        return cls(
            path=path,
            title=raw["title"],
            rule_id=str(raw["id"]),
            status=raw.get("status", ""),
            level=raw.get("level", "medium"),
            tags=raw.get("tags", []),
            logsource=raw.get("logsource", {}),
            detection=raw["detection"],
            raw=raw,
        )

    @property
    def selections(self) -> dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k != "condition"}

    @property
    def condition(self) -> str:
        return self.detection["condition"]

    @property
    def attack_techniques(self) -> list[str]:
        """Tags like 'attack.t1003.001' as uppercased technique IDs."""
        techniques = []
        for tag in self.tags:
            m = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)$", tag, re.IGNORECASE)
            if m:
                techniques.append(f"T{m.group(1)}")
        return techniques

    @property
    def fields(self) -> set[str]:
        """Every event field referenced by the detection (modifiers stripped)."""
        return {key.split("|", 1)[0] for spec in self.selections.values() for key in spec}

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
        return evaluate_condition(self.condition, selection_results)


def _match_field(
    event: dict[str, Any], field_key: str, expected: Any, case_sensitive: bool = False
) -> bool:
    field, _, modifier = field_key.partition("|")
    modifier = modifier or None
    if modifier not in SUPPORTED_MODIFIERS:
        raise UnsupportedSigmaFeature(f"modifier '{modifier}' is not supported by the evaluator")

    actual = event.get(field)
    if actual is None:
        return False
    fold: Callable[[str], str] = (lambda x: x) if case_sensitive else str.lower
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
        elif actual_str == val_str:
            return True
    return False


def _match_selection(
    event: dict[str, Any], selection_spec: dict[str, Any], case_sensitive: bool = False
) -> bool:
    # A selection maps field -> expected value(s); all fields must match (AND).
    if not isinstance(selection_spec, dict):
        raise UnsupportedSigmaFeature("only map-style selections are supported by the evaluator")
    return all(
        _match_field(event, field, expected, case_sensitive)
        for field, expected in selection_spec.items()
    )


# --------------------------------------------------------------------------
# Condition parsing: a small recursive-descent parser (replaces eval()).
#
#   expr      := and_expr ("or" and_expr)*
#   and_expr  := not_expr ("and" not_expr)*
#   not_expr  := "not" not_expr | atom
#   atom      := "(" expr ")" | quant "of" target | IDENT
#   quant     := "all" | INTEGER
#   target    := "them" | IDENT (may contain "*")
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            raise UnsupportedSigmaFeature(f"cannot parse condition near: {condition[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], results: dict[str, bool]):
        self.tokens, self.pos, self.results = tokens, 0, results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise UnsupportedSigmaFeature("unexpected end of condition")
        self.pos += 1
        return tok

    def parse(self) -> bool:
        value = self._expr()
        if self._peek() is not None:
            raise UnsupportedSigmaFeature(f"unexpected token {self._peek()!r} in condition")
        return value

    def _expr(self) -> bool:
        value = self._and()
        while self._peek() == "or":
            self._next()
            rhs = self._and()
            value = value or rhs
        return value

    def _and(self) -> bool:
        value = self._not()
        while self._peek() == "and":
            self._next()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._next()
        if tok == "(":
            value = self._expr()
            if self._next() != ")":
                raise UnsupportedSigmaFeature("unbalanced parentheses in condition")
            return value
        if (tok == "all" or tok.isdigit()) and self._peek() == "of":
            self._next()
            return self._quantified(tok, self._next())
        if tok in {"and", "or", "not", ")", "of"}:
            raise UnsupportedSigmaFeature(f"unexpected {tok!r} in condition")
        if tok not in self.results:
            raise UnsupportedSigmaFeature(f"condition references unknown selection {tok!r}")
        return self.results[tok]

    def _quantified(self, quant: str, target: str) -> bool:
        if target == "them":
            names = list(self.results)
        elif "*" in target:
            names = [n for n in self.results if fnmatch.fnmatchcase(n, target)]
        else:
            names = [target]
        if not names:
            raise UnsupportedSigmaFeature(f"'{quant} of {target}' matches no selection")
        hits = sum(1 for n in names if self.results.get(n))
        return hits == len(names) if quant == "all" else hits >= int(quant)


def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    return _Parser(_tokenize(condition), selection_results).parse()


def load_rules(detections_dir: Path) -> list[SigmaRule]:
    return [SigmaRule.load(p) for p in sorted(detections_dir.rglob("*.yml"))]
