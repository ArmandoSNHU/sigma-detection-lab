# sigma-detection-lab

A small, self-contained detection-engineering lab. It loads Sigma-style
detection rules written in YAML, evaluates them against sample log events
(JSON Lines), and reports which rules fired, on which events, together with
each rule's severity and its MITRE ATT&CK technique id.

The point of the project is to show **detection-as-code** end to end: rules
live in version control as plain text, the matching logic is a small pure
library with full unit tests, and the command line doubles as a CI gate.

## Why detection-as-code, and what Sigma is

[Sigma](https://github.com/SigmaHQ/sigma) is a vendor-neutral, YAML-based
format for describing log detections. Instead of hand-writing a query for
every SIEM dialect, you write the detection logic once in Sigma and convert
it to the target backend.

Treating detections as code means they get the same discipline as
application code: they are reviewed in pull requests, tested, and their
coverage is tracked against a framework such as MITRE ATT&CK. This lab is a
miniature version of that workflow — small enough to read in one sitting,
but structured the way a real detection repository is.

## Supported rule subset

This lab implements a practical subset of the Sigma specification, enough to
express realistic rules without pulling in the full grammar:

| Field                | Support |
|----------------------|---------|
| `title`              | Required. The alert name. |
| `level`              | Required. One of `informational`, `low`, `medium`, `high`, `critical`. |
| `tags`               | The first `attack.tNNNN[.NNN]` tag becomes the ATT&CK technique id (normalised to upper case, e.g. `T1059.001`). |
| `logsource`          | `product` / `service` / `category`. Used **only** as a filter (see below). |
| `detection`          | One or more named selection blocks plus a `condition`. |

Inside a selection block, each entry is a field condition:

* `field: value` — equality (integers and their string spellings compare equal).
* `field: [v1, v2]` — matches if the event value equals **any** listed value.
* `field|contains: substr` — case-insensitive substring match.
* `field|startswith: prefix` — case-insensitive prefix match.
* `field|endswith: suffix` — case-insensitive suffix match.

All entries in a selection must hold (logical AND). A field that is absent
from the event never matches.

The `condition` is a boolean expression over the selection names supporting
`and`, `or`, `not`, and parentheses. It is evaluated by a small hand-written
parser — **never** `eval`. Operator precedence, highest first, is
`not` > `and` > `or`; use parentheses to override it.

**logsource as a filter.** `logsource` narrows which events a rule considers.
It is lenient: an event is a candidate unless it carries a `product`,
`service`, or `category` field whose value disagrees with the rule. Events
that do not tag their source at all are still considered, which mirrors how
many raw log pipelines behave.

Aggregation (Sigma's `count() by ...` correlation) is intentionally out of
scope — the engine evaluates one event at a time. The brute-force rule below
therefore surfaces the individual failed-logon events; counting them over a
window is left to the downstream SIEM.

## Install

```bash
python -m venv .venv
# Windows PowerShell:  .venv\Scripts\Activate.ps1
# Linux/macOS:         source .venv/bin/activate
pip install -r requirements.txt        # runtime dependency: pyyaml
pip install -e ".[dev]"                # editable install + pytest
```

## Run

```bash
python -m sigmalab.cli scan examples/events.jsonl rules
```

Sample output:

```
LEVEL   ATT&CK     RULE                                          EVENT
------  ---------  --------------------------------------------  --------------------------------------------------
MEDIUM  T1110      Multiple Failed Logons (Possible Brute Force) EventID=4625
MEDIUM  T1110      Multiple Failed Logons (Possible Brute Force) EventID=4625
HIGH    T1059.001  Suspicious PowerShell Encoded Command         CommandLine=powershell.exe -NoProfile -EncodedComm...
MEDIUM  T1136.001  New Local Account Created                     EventID=4720

4 alert(s) from 3 rule(s).
```

Add `--json` for machine-readable output (each alert carries the full
matching event):

```bash
python -m sigmalab.cli scan examples/events.jsonl rules --json
```

**Exit codes.** The command exits `1` when any rule fires and `0` when none
do, so it can be dropped into a pipeline as a gate (a non-zero exit fails the
job when detections appear in a sample or replayed log set). Bad input
(missing file, malformed rule) exits `2`.

If installed as a package, the `sigmalab` console script is equivalent:

```bash
sigmalab scan examples/events.jsonl rules
```

## Bundled rules and their ATT&CK mapping

| Rule file                        | Title                                          | Level  | Technique | ATT&CK name |
|----------------------------------|------------------------------------------------|--------|-----------|-------------|
| `failed_login_bruteforce.yml`    | Multiple Failed Logons (Possible Brute Force)  | medium | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force |
| `powershell_encoded_command.yml` | Suspicious PowerShell Encoded Command          | high   | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell |
| `new_local_account.yml`          | New Local Account Created                      | medium | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account |

* **T1110 — Brute Force.** Matches Windows failed-logon events
  (`EventID 4625`). One event is a weak signal; correlating many from a
  single source over a short window is the brute-force indicator.
* **T1059.001 — PowerShell.** Matches PowerShell (`Image` ending in
  `\powershell.exe`) invoked with an encoded command
  (`CommandLine` containing `-enc`), a common obfuscation technique.
* **T1136.001 — Create Account: Local Account.** Matches local account
  creation (`EventID 4720`), frequently used to establish persistence.

## Add a rule

1. Drop a new `*.yml` file into `rules/`.
2. Give it a `title`, a `level`, an `attack.tNNNN` tag, a `logsource`, and a
   `detection` block with at least one selection and a `condition`.
3. Run the scan. New files are picked up automatically (sorted by filename).

Minimal template:

```yaml
title: My New Detection
level: high
tags:
  - attack.t1078          # ATT&CK technique id
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    CommandLine|contains: whoami
  condition: selection
```

## Testing

```bash
pytest -q
```

The suite covers the engine in isolation — `match_selection` (equality,
lists, the `contains`/`startswith`/`endswith` modifiers, case-insensitivity,
missing fields), `eval_condition` (and/or/not, precedence, parentheses,
malformed input), `match_rule`, and an end-to-end `scan` — plus a rule-load
test asserting every bundled YAML rule parses and carries a title, level,
ATT&CK id, selections, and condition.

## Project structure

```
sigma-detection-lab/
├── sigmalab/
│   ├── __init__.py        # version + package docstring
│   ├── rule.py            # Rule dataclass, load_rule / load_rules (YAML)
│   ├── engine.py          # pure matching + safe condition evaluator
│   └── cli.py             # argparse scan command / CI gate
├── rules/                 # bundled Sigma-style rules (YAML)
├── examples/
│   └── events.jsonl       # sample log events
├── tests/                 # pytest suite
├── pyproject.toml
├── requirements.txt
├── LICENSE
└── README.md
```
