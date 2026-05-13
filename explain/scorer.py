"""
scorer.py — Layer 2 Heuristic Scoring Engine

Score → Risk level:
  0–19   → safe
  20–39  → caution
  40–69  → destructive
  70+    → irreversible
"""

import re
from dataclasses import dataclass, field


THRESHOLDS = {
    "safe":         (0,  19),
    "caution":      (20, 39),
    "destructive":  (40, 69),
    "irreversible": (70, 999),
}


def score_to_risk(score: int) -> str:
    for level, (lo, hi) in THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "irreversible"


HEURISTIC_RULES = [

    # Privilege escalation
    (r'\bsudo\b',          25, "sudo: root execution",
     "Command runs as superuser — mistakes have system-wide consequences"),

    (r'\bsu\s+-\b',        25, "su -: full root shell",
     "Opens a full root login shell — complete system access"),

    (r'\bpkexec\b',        20, "pkexec: GUI privilege escalation",
     "Runs a graphical program as root"),

    # Network + remote code execution
    (r'curl.+\|\s*(sudo\s+)?ba?sh', 80, "curl|bash: remote code exec",
     "Downloads a script and pipes it directly to bash — cannot inspect before running"),

    (r'wget.+\|\s*(sudo\s+)?ba?sh', 80, "wget|bash: remote code exec",
     "Downloads a script and pipes it directly to bash — cannot inspect before running"),

    (r'curl.+\|\s*sh',     75, "curl|sh: remote code exec",
     "Downloads and immediately executes a remote script"),

    (r'wget.+\|\s*sh',     75, "wget|sh: remote code exec",
     "Downloads and immediately executes a remote script"),

    (r'\bwget\b.+-O\s*-',  30, "wget to stdout",
     "Streams downloaded content directly to stdout — often used before piping to shell"),

    (r'https?://',         10, "External network request",
     "Command fetches data from the internet"),

    (r'\bssh\b.+\|',       30, "SSH pipe",
     "Pipes output from a remote machine — commands run on another system"),

    # Destructive file operations
    (r'\brm\b.+-r',        40, "rm -r: recursive delete",
     "Recursively deletes directory — all nested files and folders removed"),

    (r'\brm\b.+-f',        20, "rm -f: force delete",
     "Force delete — skips all confirmation prompts"),

    (r'\bshred\b',         65, "shred: secure wipe",
     "Overwrites file data to make recovery impossible"),

    (r'\btruncate\b',      35, "truncate: file shrink",
     "Shrinks or zeroes a file — data past the new size is permanently lost"),

    (r'\bwipe\b',          70, "wipe: secure erase",
     "Securely erases disk data — cannot be recovered"),

    # Disk and filesystem operations
    (r'\bdd\b.+of=/dev/',  90, "dd to device: disk wipe",
     "Writes directly to a block device — can destroy all data on a disk"),

    (r'\bdd\b',            30, "dd: raw disk I/O",
     "Block-level copy tool — one wrong path argument can overwrite a disk"),

    (r'\bmkfs\b',          80, "mkfs: format filesystem",
     "Creates a new filesystem — destroys all existing data on the partition"),

    (r'\bfdisk\b',         50, "fdisk: partition editor",
     "Modifies partition tables — changes here can make data inaccessible"),

    (r'\bparted\b',        50, "parted: partition editor",
     "Modifies disk partitions — destructive if applied to wrong device"),

    (r'\bfsck\b',          40, "fsck: filesystem check",
     "Repairs filesystem — run only on unmounted partitions to avoid corruption"),

    (r'/dev/sd[a-z]',      70, "/dev/sd*: raw disk device",
     "References a raw disk device — operations here bypass the filesystem"),

    (r'/dev/zero',         60, "/dev/zero: zero fill source",
     "Reads zeros — typically used to wipe disks or create empty files"),

    (r'/dev/nvme',         70, "/dev/nvme*: NVMe disk device",
     "References an NVMe disk device — direct writes destroy data"),

    # System config paths
    (r'>/\s*/etc/',        50, "write to /etc/",
     "Writes to system config directory — can break authentication, networking, and services"),

    (r'/etc/',             20, "access /etc/",
     "System configuration directory — changes affect all users and services"),

    (r'/boot/',            55, "access /boot/",
     "Boot partition — corrupting this can make the system unbootable"),

    (r'/(usr|bin|sbin)/',  25, "system binary path",
     "Core system directory — modifying can break installed software"),

    (r'/var/log/',         15, "log directory",
     "Log directory — deleting logs may erase audit trails"),

    # Permission changes
    (r'\bchmod\b.*777',    40, "chmod 777: world-writable",
     "Grants full read/write/execute to everyone — serious security misconfiguration"),

    (r'\bchmod\b.*-R',     20, "chmod -R: recursive permissions",
     "Applies permission change to entire directory tree"),

    (r'\bchown\b.*-R',     20, "chown -R: recursive ownership",
     "Changes ownership across entire directory tree"),

    (r'\bchown\b.*root',   30, "chown root: root ownership",
     "Transfers file ownership to root — may lock out current user"),

    # Process management
    (r'\bkillall\b',       25, "killall: kills by name",
     "Kills every process matching the name — can take down system services"),

    (r'\bkill\b.*-9',      20, "kill -9: force terminate",
     "SIGKILL — forcefully terminates process with no cleanup"),

    (r'\bpkill\b',         20, "pkill: pattern kill",
     "Kills all processes matching a pattern — scope can be wider than expected"),

    # Service and system management
    (r'\bsystemctl\b.+(stop|disable|mask)', 25, "systemctl: service control",
     "Stops or disables a system service — may affect running applications"),

    (r'\bsystemctl\b.*mask', 35, "systemctl mask: block service",
     "Completely prevents a service from starting — harder to reverse than disable"),

    (r'\bservice\b.+stop', 20, "service stop",
     "Stops a running system service"),

    (r'\binit\b\s+[016]',  80, "init: system runlevel change",
     "Changes system runlevel — 0=shutdown, 1=single user, 6=reboot"),

    (r'\breboot\b',        30, "reboot: system restart",
     "Reboots the system — any unsaved work is lost"),

    (r'\bshutdown\b',      30, "shutdown: system halt",
     "Shuts down the system"),

    (r'\bpoweroff\b',      30, "poweroff: immediate halt",
     "Immediately powers off the machine"),

    # Cron
    (r'\bcrontab\b.*-r',   45, "crontab -r: delete all crons",
     "Removes ALL scheduled cron jobs for this user — no confirmation"),

    (r'\bcrontab\b',       15, "crontab: modifies schedule",
     "Modifies scheduled tasks — typos can cause repeated unintended commands"),

    # Dangerous flags
    (r'\s--force\b',       20, "--force flag",
     "Skips safety checks and confirmation prompts"),

    (r'\s-f\b',            10, "-f: force flag",
     "Force flag — suppresses warnings and confirmation"),

    (r'\s--no-preserve-root', 90, "--no-preserve-root",
     "Allows deletion of the root filesystem — can destroy the entire OS"),

    (r'\s--delete\b',      35, "--delete flag",
     "Deletes files at the destination not present in source"),

    # Pipe complexity
    (r'\|.*\|',            10, "Multi-pipe chain",
     "Command is a pipeline — combined effect can be larger than individual parts"),

    (r'\|\s*(sudo\s+)?bash', 60, "Pipe to bash",
     "Pipes output directly into bash for execution"),

    (r'\|\s*(sudo\s+)?sh\b', 60, "Pipe to sh",
     "Pipes output directly into sh for execution"),

    # Output redirection
    (r'>\s*/dev/',         55, "Redirect to device",
     "Redirects output directly to a device file — can corrupt or wipe hardware"),

    (r'>\s*/etc/',         50, "Redirect to /etc/",
     "Overwrites a system config file — can break OS services"),

    (r'>>\s*/etc/',        40, "Append to /etc/",
     "Appends to a system config file — can inject malicious config"),

    # Environment manipulation
    (r'\bexport\b.*PATH=', 20, "PATH modification",
     "Changes PATH — can hijack which binaries get executed"),

    # Tool-specific dangerous subcommands
    (r'\bterraform\b.*destroy', 55, "terraform destroy",
     "Destroys all infrastructure managed by this Terraform state — irreversible in production"),

    (r'\bkubectl\b.*delete', 40, "kubectl delete",
     "Deletes a Kubernetes resource — pods, namespaces, and PVCs may lose data"),

    (r'\bkubectl\b.*delete.*namespace', 60, "kubectl delete namespace",
     "Deletes an entire Kubernetes namespace and all resources within it"),

    (r'\bdocker\b.*rm\b',  20, "docker rm: remove container",
     "Removes a Docker container — any non-volume data inside is lost"),

    (r'\bdocker\b.*rmi\b', 20, "docker rmi: remove image",
     "Removes a Docker image — must re-pull or rebuild to use again"),

    (r'\bdocker\b.*prune', 35, "docker prune: remove unused",
     "Removes all unused Docker resources — images, containers, volumes"),

    (r'\bansible-playbook\b.*(prod|live|master)', 40, "ansible: production target",
     "Ansible playbook targeting production — changes are applied to live systems"),

    (r'\bheroku\b.*destroy', 50, "heroku destroy",
     "Permanently destroys a Heroku app and all its data"),

    (r'\bgcloud\b.*delete', 40, "gcloud delete",
     "Deletes a Google Cloud resource — may be irreversible"),

    (r'\baws\b.*delete',   40, "aws delete",
     "Deletes an AWS resource — S3 objects and terminated instances may be unrecoverable"),

    (r'\baz\b.*delete',    40, "az delete",
     "Deletes an Azure resource"),

    (r'\bnpm\b.*(publish|unpublish)', 30, "npm publish/unpublish",
     "Modifies a public npm package — unpublishing can break dependents"),

    (r'\bgit\b.*--force',  35, "git force push",
     "Force push rewrites remote history — affects all collaborators"),

    (r'\bgit\b.*clean\b',  35, "git clean: delete untracked",
     "Removes all untracked files — cannot be recovered with git"),

    (r'\bgit\b.*reset.*--hard', 35, "git reset --hard",
     "Discards all uncommitted changes — cannot be recovered"),
]


@dataclass
class HeuristicResult:
    score: int
    risk: str
    signals: list = field(default_factory=list)


def score(command: str) -> HeuristicResult:
    """
    Runs all heuristic rules against the raw command string.
    Returns score, risk level, and triggered signals.
    """
    total = 0
    triggered = []
    seen_signals = set()

    for pattern, points, signal_text, detail in HEURISTIC_RULES:
        if re.search(pattern, command, re.IGNORECASE):
            if signal_text not in seen_signals:
                total += points
                triggered.append((signal_text, points, detail))
                seen_signals.add(signal_text)

    risk = score_to_risk(total)
    return HeuristicResult(score=total, risk=risk, signals=triggered)


def should_escalate_to_llm(score_val: int) -> bool:
    """
    Returns True if score is in the ambiguous range (40-69).
    Day 3 will use this to decide when to call the LLM.
    """
    return 40 <= score_val <= 69
