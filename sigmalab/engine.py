"""Pure detection engine.

This module has no I/O and no global state. It evaluates parsed rules
(see :mod:`sigmalab.rule`) against individual events represented as plain
dictionaries, which makes every function here directly unit testable.

Supported field modifiers on a selection key ``field|modifier``:

* ``contains``   - case-insensitive substring match
* ``startswith`` - case-insensitive prefix match
* ``endswith``   - case-insensitive suffix match

With no modifier the value is compared for equality. A selection value may
be a single scalar or a list, in which case the field matches if *any*
listed value matches (Sigma list-OR semantics).

The condition evaluator supports ``and``, ``or``, ``not``, parentheses and
selection names. Precedence, highest first: ``not`` > ``and`` > ``or``.
It is a hand-written recursive-descent parser -- ``eval`` is never used.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from .rule import Rule

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_.*]+")
_OPERATORS = {"and", "or", "not"}


def _values(raw: Any) -> List[Any]:
    """Normalise a selection value into a list of candidate matches."""
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return [raw]


def _field_matches(event_value: Any, expected: Any, modifier: str) -> bool:
    """Return True if a single event value satisfies one expected value."""
    if modifier == "contains":
        return str(expected).lower() in str(event_value).lower()
    if modifier == "startswith":
        return str(event_value).lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return str(event_value).lower().endswith(str(expected).lower())
    # Equality: exact match, with a string fallback so that, e.g., an
    # integer EventID in the event matches a YAML-parsed integer or a
    # string spelling of the same value.
    if event_value == expected:
        return True
    return str(event_value) == str(expected)


def match_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    """Return True if *event* satisfies every condition in *selection*.

    A selection is a mapping of ``field`` (optionally ``field|modifier``)
    to an expected scalar or list. All conditions must hold (AND). A field
    that is absent from the event never matches.
    """
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        if field not in event:
            return False
        event_value = event[field]
        candidates = _values(expected)
        if not any(_field_matches(event_value, cand, modifier) for cand in candidates):
            return False
    return True


def eval_condition(condition: str, selection_results: Dict[str, bool]) -> bool:
    """Evaluate a boolean *condition* over ``{selection_name: bool}``.

    Safe by construction: the string is tokenised and parsed by a
    recursive-descent grammar. Unknown selection names evaluate to False.

    Raises:
        ValueError: on malformed input (dangling operator, unbalanced
            parentheses, trailing tokens).
    """
    tokens = _TOKEN_RE.findall(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_expr() -> bool:  # expr := term ('or' term)*
        value = parse_term()
        while (tok := peek()) is not None and tok.lower() == "or":
            advance()
            value = parse_term() or value
        return value

    def parse_term() -> bool:  # term := factor ('and' factor)*
        value = parse_factor()
        while (tok := peek()) is not None and tok.lower() == "and":
            advance()
            value = parse_factor() and value
        return value

    def parse_factor() -> bool:  # factor := 'not' factor | '(' expr ')' | NAME
        tok = peek()
        if tok is None:
            raise ValueError(f"unexpected end of condition: {condition!r}")
        if tok.lower() == "not":
            advance()
            return not parse_factor()
        if tok == "(":
            advance()
            value = parse_expr()
            if peek() != ")":
                raise ValueError(f"missing ')' in condition: {condition!r}")
            advance()
            return value
        if tok == ")" or tok.lower() in _OPERATORS:
            raise ValueError(f"unexpected token {tok!r} in condition: {condition!r}")
        advance()
        return bool(selection_results.get(tok, False))

    result = parse_expr()
    if pos != len(tokens):
        raise ValueError(f"trailing tokens in condition: {condition!r}")
    return result


def _logsource_allows(event: Dict[str, Any], logsource: Dict[str, Any]) -> bool:
    """Return True unless the event declares a conflicting product/service.

    ``logsource`` narrows which events a rule considers. It is a lenient
    filter: an event is a candidate unless it carries a field named in the
    logsource whose value disagrees. Events that do not tag their source at
    all are still considered, matching how many raw log pipelines behave.
    """
    for field in ("product", "service", "category"):
        expected = logsource.get(field)
        if expected is None:
            continue
        if field in event and str(event[field]).lower() != str(expected).lower():
            return False
    return True


def match_rule(event: Dict[str, Any], rule: Rule) -> bool:
    """Return True if *rule* fires on *event*."""
    if not _logsource_allows(event, rule.logsource):
        return False
    selection_results = {
        name: match_selection(event, block)
        for name, block in rule.selections.items()
    }
    return eval_condition(rule.condition, selection_results)


def scan(events: List[Dict[str, Any]], rules: List[Rule]) -> List[Dict[str, Any]]:
    """Evaluate every rule against every event.

    Returns a list of alert dicts, one per (event, firing rule) pair, in
    event-then-rule order::

        {"rule_title": str, "level": str, "attack_id": str | None, "event": dict}
    """
    alerts: List[Dict[str, Any]] = []
    for event in events:
        for rule in rules:
            if match_rule(event, rule):
                alerts.append(
                    {
                        "rule_title": rule.title,
                        "level": rule.level,
                        "attack_id": rule.attack_id,
                        "event": event,
                    }
                )
    return alerts
