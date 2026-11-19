"""
5 EDR-style hunting detections against normalized auditd events - the
Linux-side complement to this portfolio's `sysmon-log-hunter` (Windows).
Each is tagged with a real MITRE ATT&CK technique, the same convention
used there.
"""
from dataclasses import dataclass

REVERSE_SHELL_MARKERS = ("/dev/tcp/", "nc -e", "bash -i", "/bin/sh -i", "ncat ")

SENSITIVE_FILES = {
    "/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa", "/etc/pam.d/common-auth",
}

PERSISTENCE_PREFIXES = (
    "/etc/cron.d/", "/etc/crontab", "/etc/systemd/system/",
    "/var/spool/cron/", "/etc/rc.local",
)

PERSISTENCE_ALLOWLIST_COMM = {"cron", "crontab", "systemd", "dpkg", "apt", "apt-get"}

SHELL_COMMS = {"bash", "sh", "python3", "python", "perl", "nc", "ncat"}


@dataclass
class Finding:
    hunt_id: str
    severity: str
    technique: str
    message: str


def hunt_reverse_shell(events: list) -> list:
    return [
        Finding("LHUNT-1", "critical", "T1059",
                f"[{e.serial}] {e.comm} (uid={e.uid}) executed a reverse-shell-pattern "
                f"command: \"{e.command}\".")
        for e in events
        if e.syscall_name == "execve" and e.success == "yes"
        and any(marker in e.command for marker in REVERSE_SHELL_MARKERS)
    ]


def hunt_privilege_escalation(events: list) -> list:
    return [
        Finding("LHUNT-2", "critical", "T1548",
                f"[{e.serial}] {e.comm} (auid={e.auid}, a non-root login session) "
                f"successfully called {e.syscall_name}() - privilege escalation attempt.")
        for e in events
        if e.syscall_name in ("setuid", "setresuid") and e.success == "yes"
        and e.auid not in ("0", "unset", "4294967295")
    ]


def hunt_sensitive_file_access(events: list) -> list:
    findings = []
    for e in events:
        hit_paths = [p for p in e.paths if p in SENSITIVE_FILES]
        if hit_paths and e.uid != "0":
            findings.append(Finding(
                "LHUNT-3", "critical", "T1003",
                f"[{e.serial}] {e.comm} (uid={e.uid}, non-root) accessed sensitive "
                f"file(s): {', '.join(hit_paths)}.",
            ))
    return findings


def hunt_persistence_write(events: list) -> list:
    findings = []
    for e in events:
        if e.syscall_name not in ("open", "openat") or e.success != "yes":
            continue
        hit_paths = [p for p in e.paths if p.startswith(PERSISTENCE_PREFIXES)]
        if hit_paths and e.comm not in PERSISTENCE_ALLOWLIST_COMM:
            findings.append(Finding(
                "LHUNT-4", "high", "T1053.003",
                f"[{e.serial}] {e.comm} (uid={e.uid}) wrote to persistence location(s): "
                f"{', '.join(hit_paths)} - not a recognized scheduler/package-manager process.",
            ))
    return findings


def hunt_outbound_from_shell(events: list) -> list:
    return [
        Finding("LHUNT-5", "high", "T1071",
                f"[{e.serial}] {e.comm} (uid={e.uid}) made an outbound connect() call - "
                f"a shell/scripting process opening its own network connection is a "
                f"classic C2-beacon or reverse-shell signature.")
        for e in events
        if e.syscall_name == "connect" and e.comm in SHELL_COMMS
    ]


def run_all(events: list) -> list:
    findings = []
    findings += hunt_reverse_shell(events)
    findings += hunt_privilege_escalation(events)
    findings += hunt_sensitive_file_access(events)
    findings += hunt_persistence_write(events)
    findings += hunt_outbound_from_shell(events)
    return findings
