"""Unit tests for the pure detection engine."""

import json
from pathlib import Path

import pytest

from sigmalab.engine import eval_condition, match_rule, match_selection, scan
from sigmalab.rule import load_rule, load_rules

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
EVENTS_FILE = Path(__file__).resolve().parent.parent / "examples" / "events.jsonl"


# --------------------------------------------------------------------------
# match_selection
# --------------------------------------------------------------------------


def test_match_selection_equals():
    event = {"EventID": 4625}
    assert match_selection(event, {"EventID": 4625}) is True
    assert match_selection(event, {"EventID": 4624}) is False


def test_match_selection_equals_int_string_coercion():
    # An integer event value should match a string spelling and vice versa.
    assert match_selection({"EventID": 4625}, {"EventID": "4625"}) is True
    assert match_selection({"EventID": "4720"}, {"EventID": 4720}) is True


def test_match_selection_list_is_or():
    event = {"EventID": 4625}
    assert match_selection(event, {"EventID": [4624, 4625, 4634]}) is True
    assert match_selection(event, {"EventID": [4624, 4634]}) is False


def test_match_selection_contains_case_insensitive():
    event = {"CommandLine": "powershell.exe -EncodedCommand ABCDEF"}
    assert match_selection(event, {"CommandLine|contains": "-enc"}) is True
    assert match_selection(event, {"CommandLine|contains": "-ENC"}) is True
    assert match_selection(event, {"CommandLine|contains": "mimikatz"}) is False


def test_match_selection_startswith_case_insensitive():
    event = {"Image": "C:\\Windows\\System32\\powershell.exe"}
    assert match_selection(event, {"Image|startswith": "c:\\windows"}) is True
    assert match_selection(event, {"Image|startswith": "D:\\"}) is False


def test_match_selection_endswith_case_insensitive():
    event = {"Image": "C:\\Windows\\System32\\powershell.exe"}
    assert match_selection(event, {"Image|endswith": "\\powershell.exe"}) is True
    assert match_selection(event, {"Image|endswith": "\\POWERSHELL.EXE"}) is True
    assert match_selection(event, {"Image|endswith": "\\cmd.exe"}) is False


def test_match_selection_missing_field_is_no_match():
    assert match_selection({"EventID": 4625}, {"Image": "x"}) is False


def test_match_selection_all_conditions_must_hold():
    event = {"Image": "a\\powershell.exe", "CommandLine": "powershell -enc x"}
    assert match_selection(
        event, {"Image|endswith": "powershell.exe", "CommandLine|contains": "-enc"}
    ) is True
    # Second condition fails -> whole selection fails.
    assert match_selection(
        event, {"Image|endswith": "powershell.exe", "CommandLine|contains": "-nop"}
    ) is False


# --------------------------------------------------------------------------
# eval_condition
# --------------------------------------------------------------------------


def test_eval_condition_single_selection():
    assert eval_condition("selection", {"selection": True}) is True
    assert eval_condition("selection", {"selection": False}) is False


def test_eval_condition_unknown_name_is_false():
    assert eval_condition("missing", {}) is False


def test_eval_condition_and():
    assert eval_condition("a and b", {"a": True, "b": True}) is True
    assert eval_condition("a and b", {"a": True, "b": False}) is False


def test_eval_condition_or():
    assert eval_condition("a or b", {"a": False, "b": True}) is True
    assert eval_condition("a or b", {"a": False, "b": False}) is False


def test_eval_condition_not():
    assert eval_condition("not a", {"a": False}) is True
    assert eval_condition("not a", {"a": True}) is False


def test_eval_condition_precedence():
    # not binds tighter than and, which binds tighter than or.
    results = {"a": True, "b": False, "c": True}
    assert eval_condition("a or b and c", results) is True
    assert eval_condition("not b and a", results) is True


def test_eval_condition_parentheses():
    results = {"a": True, "b": False, "c": False}
    assert eval_condition("(a or b) and not c", results) is True
    assert eval_condition("(b or c) and a", results) is False


def test_eval_condition_case_insensitive_operators():
    assert eval_condition("a AND b", {"a": True, "b": True}) is True
    assert eval_condition("NOT a", {"a": False}) is True


def test_eval_condition_malformed_raises():
    with pytest.raises(ValueError):
        eval_condition("a and", {"a": True})
    with pytest.raises(ValueError):
        eval_condition("(a or b", {"a": True})


# --------------------------------------------------------------------------
# match_rule
# --------------------------------------------------------------------------


def test_match_rule_fires_and_respects_condition():
    rule = load_rule(
        {
            "title": "PS Encoded",
            "level": "high",
            "tags": ["attack.t1059.001"],
            "logsource": {"product": "windows", "service": "sysmon"},
            "detection": {
                "selection_image": {"Image|endswith": "\\powershell.exe"},
                "selection_flag": {"CommandLine|contains": "-enc"},
                "condition": "selection_image and selection_flag",
            },
        }
    )
    firing = {
        "product": "windows",
        "service": "sysmon",
        "Image": "C:\\x\\powershell.exe",
        "CommandLine": "powershell -enc AAAA",
    }
    benign = {
        "product": "windows",
        "service": "sysmon",
        "Image": "C:\\x\\powershell.exe",
        "CommandLine": "powershell -File run.ps1",
    }
    assert match_rule(firing, rule) is True
    assert match_rule(benign, rule) is False


def test_match_rule_logsource_conflict_blocks():
    rule = load_rule(
        {
            "title": "4625",
            "level": "medium",
            "tags": ["attack.t1110"],
            "logsource": {"product": "windows", "service": "security"},
            "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
        }
    )
    # Same EventID but the event declares a conflicting service.
    conflicting = {"EventID": 4625, "product": "windows", "service": "sysmon"}
    assert match_rule(conflicting, rule) is False
    matching = {"EventID": 4625, "product": "windows", "service": "security"}
    assert match_rule(matching, rule) is True


# --------------------------------------------------------------------------
# scan (integration against the bundled rules + events)
# --------------------------------------------------------------------------


def _load_events():
    events = []
    for line in EVENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def test_scan_bundled_rules_and_events():
    rules = load_rules(RULES_DIR)
    events = _load_events()
    alerts = scan(events, rules)

    # Two failed logons, one encoded PowerShell, one new account => 4 alerts.
    assert len(alerts) == 4

    titles = sorted(a["rule_title"] for a in alerts)
    assert titles == [
        "Multiple Failed Logons (Possible Brute Force)",
        "Multiple Failed Logons (Possible Brute Force)",
        "New Local Account Created",
        "Suspicious PowerShell Encoded Command",
    ]

    # ATT&CK technique ids carry through onto the alerts.
    by_title = {}
    for alert in alerts:
        by_title.setdefault(alert["rule_title"], alert["attack_id"])
    assert by_title["Multiple Failed Logons (Possible Brute Force)"] == "T1110"
    assert by_title["Suspicious PowerShell Encoded Command"] == "T1059.001"
    assert by_title["New Local Account Created"] == "T1136.001"


def test_scan_no_rules_yields_no_alerts():
    assert scan(_load_events(), []) == []
