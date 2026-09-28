"""sigma-detection-lab: a small detection-engineering lab.

Loads Sigma-style detection rules (YAML) and evaluates them against
sample log events (JSON Lines), reporting which rules fired, on which
events, with each rule's severity and MITRE ATT&CK technique id.

The engine module is pure and side-effect free so the matching logic can
be unit tested in isolation from file I/O and the command line.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
