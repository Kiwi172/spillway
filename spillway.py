#!/usr/bin/env python3
"""spillway -- find the secrets that spilled onto your machine.

gitleaks and trufflehog audit repositories in CI. Nothing audits the places
secrets actually leak on a workstation: shell history, .env files, dotfiles,
git remotes with embedded credentials, ~/.netrc. spillway does, in one
command, with nothing but the Python standard library. No network, no
install, no telemetry.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

VERSION = "0.1.0"

# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

HIGH, MEDIUM, LOW = "high", "medium", "low"
CONF_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass(frozen=True)
class Rule:
    name: str
    confidence: str
    pattern: "re.Pattern[str]"
    group: int = 0
    note: str = ""
    gates: tuple = ()   # required substrings; a line must contain one to match


def _r(name, conf, pattern, group=0, note="", gates=()):
    return Rule(name, conf, re.compile(pattern), group, note, gates)


RULES = [
    # -- provider tokens with unmistakable prefixes: high confidence --------
    _r("github-token", HIGH,
       r"\b(?:gh[pousr]_[0-9A-Za-z]{36,255}|github_pat_[0-9A-Za-z_]{22,255})\b",
       note="GitHub personal-access or fine-grained token",
       gates=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    _r("anthropic-key", HIGH, r"\bsk-ant-[A-Za-z0-9_-]{20,}\b",
       gates=("sk-ant-",)),
    _r("openai-key", HIGH, r"\bsk-[A-Za-z0-9_-]{20,}\b",
       note="also matches keys of other sk- issuers", gates=("sk-",)),
    _r("aws-access-key-id", HIGH, r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
       note="the id half of an AWS key pair",
       gates=("AKIA", "ASIA", "ABIA", "ACCA")),
    _r("google-api-key", HIGH, r"\bAIza[0-9A-Za-z_-]{35}\b", gates=("AIza",)),
    _r("google-oauth-refresh", HIGH, r"\bya29\.[0-9A-Za-z_-]{20,}\b",
       gates=("ya29.",)),
    _r("slack-token", HIGH, r"\bxox[babrsu]-[0-9A-Za-z-]{10,}\b", gates=("xox",)),
    _r("slack-webhook", HIGH,
       r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+",
       gates=("hooks.slack.com",)),
    _r("stripe-key", HIGH, r"\b(?:sk|pk|rk|wk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
       gates=("_live_", "_test_")),
    _r("gitlab-token", HIGH, r"\bglpat-[0-9A-Za-z_-]{20}\b", gates=("glpat-",)),
    _r("huggingface-token", HIGH, r"\bhf_[A-Za-z0-9]{34,}\b", gates=("hf_",)),
    _r("npm-token", HIGH, r"\bnpm_[0-9A-Za-z]{36}\b", gates=("npm_",)),
    _r("pypi-token", HIGH, r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{40,}",
       gates=("pypi-AgEIcHlwaS5vcmc",)),
    _r("sendgrid-key", HIGH, r"\bSG\.[0-9A-Za-z_-]{20,28}\.[0-9A-Za-z_-]{40,}\b",
       gates=("SG.",)),
    _r("twilio-key", HIGH, r"\bAC[0-9a-f]{32}\b", gates=("AC",)),
    _r("digitalocean-token", HIGH, r"\bdop_[a-z0-9]{1,3}_[0-9a-f]{64}\b",
       gates=("dop_",)),
    _r("telegram-bot-token", HIGH, r"\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b",
       gates=(":AA",)),
    _r("sentry-dsn", HIGH,
       r"https://[0-9a-f]{32}@[A-Za-z0-9.]+\.sentry\.io/[0-9]+",
       gates=("sentry.io",)),
    _r("private-key-block", HIGH,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
       note="a private key lives in this file", gates=("-----BEGIN",)),
    _r("jwt", HIGH,
       r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
       note="JSON web token", gates=("eyJ",)),

    # -- structural patterns: medium confidence -----------------------------
    _r("url-credentials", MEDIUM,
       r"(?i)\b(?:https?|ftp|ftps|sftp|ssh|git|ws|wss|postgres(?:ql)?"
       r"(?:\+\w+)?|mysql|maria?db|mongodb(?:\+srv)?|redis[s]?|amqps?|"
       r"mssql|sqlserver|clickhouse|cockroachdb|influxdb|smtp|imap|ldap|s3)://"
       r"[^/\s:@]+:([^/\s:@]{4,})@",
       group=1, note="password embedded in a URL", gates=("@",)),
    _r("discord-token", MEDIUM,
       r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"),
    _r("aws-secret-access-key", MEDIUM,
       r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b",
       group=1, gates=("aws_secret", "AWS_SECRET", "Aws_Secret")),

    # -- heuristics: low confidence, hidden unless --min-confidence low -----
    _r("generic-assignment", LOW,
       r"(?i)\b(?:secret|token|api[_-]?key|apikey|access[_-]?key|auth|"
       r"credential|passwd|password|pwd|client[_-]?secret|private[_-]?token)"
       r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{16,})[\"']?",
       group=1, note="assignment to a secret-sounding name"),
    _r("hex-40", LOW, r"\b[0-9a-f]{40}\b",
       note="could be a git SHA; could be a legacy token"),
]

# values that are almost certainly placeholders, not secrets
_PLACEHOLDER = re.compile(
    r"(?i)(example|changeme|change_me|your[_-]|placeholder|dummy|sample|"
    r"notareal|redacted|removed|invalid|test[-_]?key|xxxxxxxx|<[^>]*>|"
    r"\{\{.*?\}\}|\$\{[^}]*\}|%\()")

# stock defaults in connection strings: weak, but not "leaked"
_COMMON_DEFAULTS = {
    "password", "pass", "postgres", "postgresql", "mysql", "mongodb",
    "redis", "admin", "administrator", "root", "user", "secret", "test",
    "testing", "dev", "develop", "local", "localhost", "public", "app",
    "123456", "letmein", "admin123", "secret123", "changeme", "none",
    "null", "todo", "fixme", "yourpassword", "dbpassword",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_real(value: str, confidence: str) -> bool:
    """Reject obvious placeholders and low-entropy strings for heuristics."""
    if _PLACEHOLDER.search(value):
        return False
    if confidence != HIGH and value.lower() in _COMMON_DEFAULTS:
        return False
    if len(set(value)) < 4:          # aaaa, 1212, ...
        return False
    if confidence == LOW:
        if value.isdigit() or value.isalpha():
            return False
        if shannon_entropy(value) < 3.5:
            return False
    return True


# --------------------------------------------------------------------------
# scanning
# --------------------------------------------------------------------------

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__",
    ".cache", ".cargo", ".rustup", ".npm", ".gradle", ".m2", ".local",
    ".mozilla", ".pki", ".java", ".dotnet", ".snapshots",
    ".mypy_cache", ".pytest_cache", ".tox", ".direnv", ".Trash", ".snapshots",
    "snap", ".thumbnails", ".icons", ".fonts", ".certs", ".blas",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache", ".yarn",
    ".pnpm-store", ".serverless", "coverage", "htmlcov", "target",
}
# .git is skipped wholesale, but .git/config is a classic leak site
GIT_FILES = {"config"}

# prefilter: token-shaped runs, URLs, or PEM markers
_CANDIDATE = re.compile(
    r"[A-Za-z0-9_+/=.:-]{16,}|[A-Za-z][A-Za-z0-9+.-]*://|-----BEGIN")

HISTORY_FILES = [
    ".bash_history", ".zsh_history", ".python_history", ".node_repl_history",
    ".psql_history", ".mysql_history", ".config/fish/fish_history",
    ".config/nushell/history.txt",
]
WELL_KNOWN = [
    ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".condarc",
    ".aws/credentials", ".aws/config", ".docker/config.json",
    ".config/gh/hosts.yml", ".config/containers/auth.json",
    ".config/gcloud/properties", ".ssh/config",
]


def is_probably_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:8192]


def scan_text(text: str, min_conf: str):
    """Yield (rule, value, line_no, line_text) for one file's text.

    Two cheap gates run before any expensive regex: a line-level
    prefilter (no token-shaped run, no URL, no PEM marker -> skip the
    line entirely) and per-rule substring gates (a line without "ghp_"
    cannot hold a GitHub token). On real-world trees this skips ~99%
    of the regex work.
    """
    active = [r for r in RULES if CONF_RANK[r.confidence] <= CONF_RANK[min_conf]]
    for line_no, line in enumerate(text.splitlines(), 1):
        if not _CANDIDATE.search(line):
            continue
        for rule in active:
            if rule.gates and not any(g in line for g in rule.gates):
                continue
            for m in rule.pattern.finditer(line):
                value = m.group(rule.group)
                if not value or not looks_real(value, rule.confidence):
                    continue
                yield rule, value, line_no, line


def scan_file(path: Path, max_bytes: int):
    """Yield findings from one file, or ('skip', reason)."""
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > max_bytes:
        yield None, f"over {max_bytes} bytes", 0, ""
        return
    try:
        raw = path.read_bytes()
    except OSError:
        return
    if is_probably_binary(raw):
        yield None, "binary", 0, ""
        return
    text = raw.decode("utf-8", errors="replace")
    yield from scan_text(text, _MIN_CONF)


def walk_files(root: Path, excludes, max_depth: int | None):
    """Yield candidate files under root, honouring skip rules."""
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if max_depth is not None and depth >= max_depth:
            continue
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            name = e.name
            p = Path(e.path)
            if any(p.fnmatch(pat) or name == pat for pat in excludes):
                continue
            if e.is_symlink():
                continue
            if e.is_dir(follow_symlinks=False):
                if name in SKIP_DIRS:
                    if name == ".git":
                        for g in GIT_FILES:
                            gp = p / g
                            if gp.is_file():
                                yield gp
                    continue
                stack.append((p, depth + 1))
            elif e.is_file(follow_symlinks=False):
                if name.endswith(".spillway-bak"):
                    continue
                yield p


def home_targets(home: Path, excludes):
    """The curated default: the places secrets actually leak on a workstation."""
    seen = set()

    def emit(p: Path):
        if p.is_file() and str(p) not in seen:
            seen.add(str(p))
            yield p

    for rel in HISTORY_FILES + WELL_KNOWN:
        yield from emit(home / rel)
    # dotfiles directly in $HOME
    try:
        for e in sorted(os.scandir(home), key=lambda e: e.name):
            p = Path(e.path)
            if (e.is_file(follow_symlinks=False)
                    and p.name.startswith(".")
                    and not any(p.fnmatch(pat) for pat in excludes)):
                yield from emit(p)
    except OSError:
        pass
    # .env files and git configs, bounded walk
    for p in walk_files(home, excludes, max_depth=4):
        if (p.name.startswith(".env") or p.name.endswith(".env")
                or (p.parent.name == ".git" and p.name in GIT_FILES)):
            yield from emit(p)


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def mask_value(value: str) -> str:
    if len(value) <= 14:
        return value[:3] + "…"
    return f"{value[:6]}…{value[-4:]}"


class Palette:
    def __init__(self, enabled: bool):
        self.on = enabled

    def __call__(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s


def group_findings(raw):
    """Collapse repeated copies of the same secret into one finding."""
    groups: dict = {}
    for rule, value, path, line_no, line in raw:
        key = (rule.name, value)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "rule": rule.name, "confidence": rule.confidence,
                "note": rule.note, "value": value, "occurrences": [],
            }
        g["occurrences"].append({"file": str(path), "line": line_no,
                                 # never echo the secret itself back
                                 "snippet": line.strip().replace(
                                     value, mask_value(value))[:160]})
    out = sorted(groups.values(),
                 key=lambda g: (CONF_RANK[g["confidence"]], g["rule"],
                                g["occurrences"][0]["file"]))
    return out


def print_text(findings, stats, color, show_snippets=True, max_occ=3):
    c = color
    if not findings:
        print(c("32", "clean") + f"  ·  no secrets found in "
              f"{stats['files']:,} files / {stats['bytes'] / 1e6:.1f} MB")
        return
    n_files = len({o["file"] for f in findings for o in f["occurrences"]})
    for f in findings:
        conf = {"high": c("31", "HIGH  "), "medium": c("33", "MED   "),
                "low": c("36", "LOW   ")}[f["confidence"]]
        head = f"  {conf} {c('1', f['rule'])}  {mask_value(f['value'])}"
        if f["note"]:
            head += c("90", f"   ({f['note']})")
        print(head)
        occs = f["occurrences"]
        for o in occs[:max_occ]:
            print(f"         {o['file']}:{o['line']}")
            if show_snippets and o["snippet"]:
                print(c("90", f"         {o['snippet']}"))
        if len(occs) > max_occ:
            print(c("90", f"         … and {len(occs) - max_occ} more copies"))
        print()
    total_occ = sum(len(f["occurrences"]) for f in findings)
    print(f"{len(findings)} secret{'s' if len(findings) != 1 else ''} in "
          f"{n_files} file{'s' if n_files != 1 else ''} "
          f"({total_occ} occurrences)  ·  scanned {stats['files']:,} files / "
          f"{stats['bytes'] / 1e6:.1f} MB in {stats['seconds']:.1f}s")


def print_json(findings, stats):
    print(json.dumps({
        "tool": "spillway", "version": VERSION,
        "scanned": stats,
        "findings": [{
            "rule": f["rule"], "confidence": f["confidence"],
            "note": f["note"], "value_masked": mask_value(f["value"]),
            "occurrences": f["occurrences"],
        } for f in findings],
    }, indent=2))


def apply_mask(findings, dry_run: bool):
    """Redact every matched value in place; keep one .spillway-bak per file."""
    by_file: dict = {}
    for f in findings:
        for o in f["occurrences"]:
            by_file.setdefault(o["file"], []).append(f["value"])
    changed = 0
    for path_str, values in sorted(by_file.items()):
        p = Path(path_str)
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        new = text
        for v in sorted(set(values), key=len, reverse=True):
            new = new.replace(v, "[redacted:spillway]")
        if new == text:
            continue
        if dry_run:
            print(f"would redact {len(set(values))} secret(s) in {p}")
            continue
        bak = Path(str(p) + ".spillway-bak")
        if not bak.exists():
            bak.write_bytes(p.read_bytes())
        p.write_text(new)
        changed += 1
        print(f"redacted {p}  (backup: {bak.name})")
    if not dry_run:
        print(f"{changed} file(s) rewritten.")


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

_MIN_CONF = MEDIUM  # set from argv; scan_file reads it (single-threaded tool)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="spillway",
        description="Find secrets that spilled onto your machine: shell "
                    "history, .env files, dotfiles, git configs. "
                    "Stdlib-only, no network.",
        epilog="With no PATHS, scans the usual leak sites under $HOME.")
    ap.add_argument("paths", nargs="*", metavar="PATH",
                    help="files or directories to scan (default: $HOME)")
    ap.add_argument("--min-confidence", choices=[LOW, MEDIUM, HIGH],
                    default=MEDIUM,
                    help="lowest confidence to report (default: medium)")
    ap.add_argument("--mask", action="store_true",
                    help="redact found secrets in place (writes .spillway-bak)")
    ap.add_argument("--dry-run", action="store_true",
                    help="with --mask: show what would change")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output")
    ap.add_argument("--no-snippets", action="store_true",
                    help="omit context lines (safe to share output)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="extra name/glob to skip (repeatable)")
    ap.add_argument("--max-file-size", type=int, default=2, metavar="MB",
                    help="skip files larger than this (default: 2)")
    ap.add_argument("--max-depth", type=int, default=None, metavar="N",
                    help="limit directory depth when scanning paths")
    ap.add_argument("--rules", action="store_true",
                    help="list detection rules and exit")
    ap.add_argument("--fail-found", action="store_true",
                    help="exit 1 if anything is found (for scripts)")
    ap.add_argument("--version", action="version",
                    version=f"spillway {VERSION}")
    return ap


def main(argv=None) -> int:
    global _MIN_CONF
    args = build_parser().parse_args(argv)

    if args.rules:
        for r in RULES:
            note = f"  # {r.note}" if r.note else ""
            print(f"{r.confidence:<7} {r.name}{note}")
        return 0

    _MIN_CONF = args.min_confidence
    home = Path.home()
    excludes = list(args.exclude)

    if args.paths:
        targets = []
        for p in map(Path, args.paths):
            if p.is_file():
                targets.append(p)
            elif p.is_dir():
                targets.extend(walk_files(p, excludes, args.max_depth))
            else:
                print(f"spillway: no such path: {p}", file=sys.stderr)
                return 2
    else:
        targets = home_targets(home, excludes)

    color = Palette(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
    raw = []
    stats = {"files": 0, "bytes": 0}
    max_bytes = args.max_file_size * 1024 * 1024
    t0 = time.monotonic()
    for path in targets:
        for rule, value, line_no, line in scan_file(path, max_bytes):
            if rule is None:
                break                      # skipped (size); don't count it
            raw.append((rule, value, path, line_no, line))
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= max_bytes:
            stats["files"] += 1
            stats["bytes"] += size

    stats["seconds"] = time.monotonic() - t0
    findings = group_findings(raw)

    if args.as_json:
        print_json(findings, stats)
    else:
        scope = ", ".join(args.paths) if args.paths else f"leak sites under {home}"
        print(f"spillway {VERSION}  ·  {scope}\n")
        print_text(findings, stats, color,
                   show_snippets=not args.no_snippets)

    if args.mask and findings:
        print()
        apply_mask(findings, args.dry_run)

    if args.fail_found and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
