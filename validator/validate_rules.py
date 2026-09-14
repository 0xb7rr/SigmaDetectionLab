#!/usr/bin/env python3
"""
validate_rules.py
------------------
A minimal, dependency-light Sigma-rule matching engine built to demonstrate
and self-test the detection rules in ../rules/ against the sample logs in
../sample_logs/.

This is NOT a full Sigma backend (see https://github.com/SigmaHQ/pySigma for
that). It implements the subset of Sigma detection syntax used by the rules
in this repo:

  - selection blocks made of field: value, field: [list of values]
  - modifiers: |contains, |endswith, |gte
  - condition strings combining selections with 'and', 'or', 'not'

Usage:
    python3 validate_rules.py

Exit code is 0 if every log entry's actual detection matches its
'expected_detection' label, non-zero otherwise (useful in CI).
"""

import json
import re
import sys
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"
LOGS_DIR = Path(__file__).parent.parent / "sample_logs"

# Map each rule file to the sample log file that exercises it.
RULE_LOG_PAIRS = {
    "kerberoasting.yml": "kerberoasting_sample.json",
    "powershell_obfuscation.yml": "powershell_obfuscation_sample.json",
    "lolbin_certutil_abuse.yml": "lolbin_certutil_sample.json",
    "lsass_credential_dumping.yml": "lsass_credential_dumping_sample.json",
    "dns_tunneling.yml": "dns_tunneling_sample.json",
}


def load_rule(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_logs(path):
    with open(path, "r") as f:
        return json.load(f)


def field_matches(log_entry, field_expr, expected):
    """Evaluate a single field expression (possibly with a |modifier) against a log entry."""
    if "|" in field_expr:
        field, modifier = field_expr.split("|", 1)
    else:
        field, modifier = field_expr, None

    actual = log_entry.get(field)
    if actual is None:
        return False

    values = expected if isinstance(expected, list) else [expected]

    for value in values:
        if modifier == "contains":
            if isinstance(actual, str) and str(value).lower() in actual.lower():
                return True
        elif modifier == "endswith":
            if isinstance(actual, str) and actual.lower().endswith(str(value).lower()):
                return True
        elif modifier == "gte":
            try:
                if float(actual) >= float(value):
                    return True
            except (TypeError, ValueError):
                continue
        else:
            # plain equality (case-insensitive for strings)
            if isinstance(actual, str) and isinstance(value, str):
                if actual.lower() == value.lower():
                    return True
            elif actual == value:
                return True
    return False


def selection_matches(log_entry, selection_block):
    """A selection block matches if ALL of its field expressions match (implicit AND)."""
    for field_expr, expected in selection_block.items():
        if not field_matches(log_entry, field_expr, expected):
            return False
    return True


def evaluate_condition(condition_str, selection_results):
    """
    Evaluate a Sigma condition string like:
      'selection_eventid and selection_weak_crypto and not filter_machine_accounts'
    against a dict of {selection_name: bool}.
    """
    # Tokenize on word boundaries, keep 'and'/'or'/'not' as Python operators.
    expr = condition_str
    for name in sorted(selection_results.keys(), key=len, reverse=True):
        expr = re.sub(rf"\b{name}\b", str(selection_results[name]), expr)
    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))
    except Exception as e:
        raise ValueError(f"Could not evaluate condition '{condition_str}' -> '{expr}': {e}")


def run_rule_against_log(rule, log_entry):
    detection = rule["detection"]
    condition_str = detection["condition"]
    selection_results = {}
    for name, block in detection.items():
        if name == "condition":
            continue
        selection_results[name] = selection_matches(log_entry, block)
    return evaluate_condition(condition_str, selection_results)


def main():
    total = 0
    passed = 0
    failures = []

    print("=" * 78)
    print("Sigma Detection Lab - Rule Validator")
    print("=" * 78)

    for rule_file, log_file in RULE_LOG_PAIRS.items():
        rule_path = RULES_DIR / rule_file
        log_path = LOGS_DIR / log_file

        if not rule_path.exists() or not log_path.exists():
            print(f"[SKIP] Missing rule or log file for {rule_file}")
            continue

        rule = load_rule(rule_path)
        logs = load_logs(log_path)

        print(f"\nRule: {rule['title']}")
        print(f"  ID: {rule['id']}  |  Level: {rule['level']}  |  Tags: {', '.join(rule.get('tags', []))}")
        print(f"  Log file: {log_file} ({len(logs)} entries)")
        print("-" * 78)

        for i, entry in enumerate(logs):
            total += 1
            expected = entry.get("expected_detection", False)
            note = entry.get("note", "")
            try:
                actual = run_rule_against_log(rule, entry)
            except ValueError as e:
                print(f"  [ERROR] entry {i}: {e}")
                failures.append((rule_file, i, note))
                continue

            status = "MATCH   " if actual else "no-match"
            ok = actual == expected
            result_tag = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failures.append((rule_file, i, note))

            print(f"  [{result_tag}] detection={status}  expected={str(expected):5}  -- {note}")

    print("\n" + "=" * 78)
    print(f"RESULTS: {passed}/{total} log entries scored as expected")
    print("=" * 78)

    if failures:
        print("\nUnexpected results (review these first):")
        for rule_file, idx, note in failures:
            print(f"  - {rule_file} entry #{idx}: {note}")
        sys.exit(1)
    else:
        print("\nAll rules behaved exactly as expected against the sample data.")
        sys.exit(0)


if __name__ == "__main__":
    main()
