#!/usr/bin/env python3
"""
linux-auditd-threat-hunter: EDR-style hunting detections against real
Linux auditd log telemetry (/var/log/audit/audit.log format).
"""
import argparse
import json
import sys

from parser import load_events
from checks import run_all

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def render_console(findings):
    if not findings:
        return "No findings - all checks passed."
    lines = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity), reverse=True):
        lines.append(f"[{f.severity.upper():<8}] {f.hunt_id} ({f.technique}): {f.message}")
    return "\n".join(lines)


def to_json(findings):
    return [
        {"hunt_id": f.hunt_id, "severity": f.severity, "technique": f.technique, "message": f.message}
        for f in findings
    ]


def main():
    ap = argparse.ArgumentParser(description="Hunt for threats in a real Linux auditd log")
    ap.add_argument("audit_log", help="Path to an auditd-format log file")
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any"], default=None)
    args = ap.parse_args()

    events = load_events(args.audit_log)
    findings = run_all(events)

    print(f"Parsed {len(events)} audit event(s).\n")
    print(render_console(findings))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(findings), fh, indent=2)

    if args.fail_on:
        trigger_idx = 0 if args.fail_on == "any" else SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) >= trigger_idx for f in findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
