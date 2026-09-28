"""Loading and modelling of Sigma-style detection rules.

Only a practical subset of the Sigma specification is supported. See the
README for the exact grammar. Rules are parsed from YAML into the
:class:`Rule` dataclass, which the pure engine in :mod:`sigmalab.engine`
then evaluates against events.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Matches an ATT&CK technique tag such as ``attack.t1059.001`` and captures
# the technique id (``t1059.001``), which we normalise to upper case.
_ATTACK_TAG = re.compile(r"^attack\.(t\d+(?:\.\d+)?)$", re.IGNORECASE)

_VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


@dataclass
class Rule:
    """An in-memory representation of a supported Sigma rule subset.

    Attributes:
        title: Human readable rule name.
        level: Severity, one of the Sigma levels.
        attack_id: MITRE ATT&CK technique id (e.g. ``T1110``) or ``None``.
        logsource: product/service filter; used only to narrow candidate events.
        selections: Mapping of selection name to its field-condition block.
        condition: Boolean expression over the selection names.
        tags: The raw tag list from the rule.
    """

    title: str
    level: str
    condition: str
    selections: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    logsource: Dict[str, Any] = field(default_factory=dict)
    attack_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)


def _extract_attack_id(tags: List[str]) -> Optional[str]:
    """Return the first ATT&CK technique id found in *tags*, upper-cased."""
    for tag in tags:
        match = _ATTACK_TAG.match(str(tag).strip())
        if match:
            return match.group(1).upper()
    return None


def load_rule(data: Dict[str, Any]) -> Rule:
    """Build a :class:`Rule` from a parsed YAML mapping.

    Raises:
        ValueError: if a required field is missing or the level is invalid.
    """
    if not isinstance(data, dict):
        raise ValueError("rule document must be a mapping")

    title = data.get("title")
    if not title:
        raise ValueError("rule is missing a 'title'")

    level = str(data.get("level", "")).lower()
    if level not in _VALID_LEVELS:
        raise ValueError(
            f"rule {title!r} has invalid level {data.get('level')!r}; "
            f"expected one of {sorted(_VALID_LEVELS)}"
        )

    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise ValueError(f"rule {title!r} is missing a 'detection' block")

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        raise ValueError(f"rule {title!r} detection is missing a 'condition'")

    selections = {
        name: block
        for name, block in detection.items()
        if name != "condition"
    }
    if not selections:
        raise ValueError(f"rule {title!r} defines no selection blocks")

    tags = list(data.get("tags", []) or [])
    logsource = data.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise ValueError(f"rule {title!r} has a non-mapping 'logsource'")

    return Rule(
        title=str(title),
        level=level,
        condition=condition,
        selections=selections,
        logsource=logsource,
        attack_id=_extract_attack_id(tags),
        tags=tags,
    )


def load_rules(directory: str | Path) -> List[Rule]:
    """Load every ``*.yml`` / ``*.yaml`` rule in *directory*.

    Files are processed in sorted order for deterministic output.

    Raises:
        FileNotFoundError: if *directory* does not exist.
        ValueError: if any rule file fails to parse or validate.
    """
    path = Path(directory)
    if not path.is_dir():
        raise FileNotFoundError(f"rules directory not found: {path}")

    rules: List[Rule] = []
    files = sorted(
        p for p in path.iterdir() if p.suffix.lower() in {".yml", ".yaml"}
    )
    for rule_file in files:
        with rule_file.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        try:
            rules.append(load_rule(document))
        except ValueError as exc:
            raise ValueError(f"{rule_file.name}: {exc}") from exc
    return rules
