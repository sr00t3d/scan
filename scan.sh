#!/usr/bin/env bash
# ==============================================================================
# scan.sh — Hybrid ClamAV + Heuristic Webshell Scanner & Quarantine CLI (v2.0.0)
# ==============================================================================
# Clean-room Bash + Python 3.6+ reimplementation inspired by scan_2.sh (2012,
# Michael Karr, HostGator.com, LLC).
#
# Eliminates unencrypted HTTP binary downloads (scripts.hostgator.com),
# self-deleting script traps, symlink privilege escalation from writing root
# locks/logs/quarantine inside user homedirs ($SCANDIR/.security/), and
# duplicated CLI flags in reseller loops.
#
# Adds hybrid ClamAV + built-in heuristic webshell/EICAR engine (--engine),
# symlink-safe traversal, root-only 0700 quarantine vault (/var/quarantine/scan)
# with SHA-256 manifest.json and full restore subcommand, --dry-run,
# --exit-code (2), and table/json/csv outputs.
#
# License: Apache-2.0
# Author:  Percio Castelo (https://perciocastelo.com.br)
# Repo:    https://github.com/sr00t3d/scan
# ==============================================================================

set -euo pipefail

readonly SCRIPT_NAME="scan.sh"
readonly SCRIPT_VERSION="2.0.0"

ACTION="scan"
TARGET_USER=""
TARGET_PATH=""
RESELLER=""
LIST_FILE=""
RESTORE_TARGET=""
SCAN_ALL=0
USE_CWD=0
SCAN_TMP=1
SCAN_SHM=1
FOLLOW_SYMLINKS=0
DO_QUARANTINE=0
QUARANTINE_DIR="/var/quarantine/scan"
ENGINE="auto"
MAX_SIZE_MB="2"
DRY_RUN=0
EXIT_CODE_MODE=0
OUTPUT_FMT="table"
QUIET=0
NO_COLOR=0

C_RED=""
C_GREEN=""
C_YELLOW=""
C_CYAN=""
C_BOLD=""
C_RESET=""

init_colors() {
  if [[ "$NO_COLOR" -eq 0 && -t 1 && "$OUTPUT_FMT" == "table" ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_CYAN=$'\033[0;36m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
  fi
}

usage() {
  cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} — Hybrid ClamAV + Heuristic Webshell Scanner & Quarantine CLI

Usage:
  ${SCRIPT_NAME} [options] <username>           Scan a cPanel/Plesk/Linux user (+ /tmp & /dev/shm)
  ${SCRIPT_NAME} --path <dir> [options]         Scan a specific directory (symlink-safe)
  ${SCRIPT_NAME} --cwd [options]                Scan the current working directory
  ${SCRIPT_NAME} --reseller <user> [options]    Scan all accounts owned by a cPanel reseller
  ${SCRIPT_NAME} --all [options]                Scan all accounts in /home or /var/www/vhosts
  ${SCRIPT_NAME} --list <file> [options]        Scan explicit file paths listed in <file>
  ${SCRIPT_NAME} restore <vault_dir> [options]  Restore quarantined files from manifest.json

Options:
  -p, --path <dir>          Scan the given directory path
  --cwd                     Scan current working directory
  -r, --reseller <user>     Scan all accounts owned by reseller
  -a, --all                 Scan all hosted accounts (/home or /var/www/vhosts)
  -l, --list <file>         Scan file paths listed in <file> (1 per line)
  --engine <mode>           Detection engine: auto (default), clamav, heuristic, both
  -c, --clean, --quarantine Move detected threats to root-only 0700 quarantine vault
  --quarantine-dir <dir>    Quarantine base directory (default: /var/quarantine/scan)
  --max-size <MB>           Max file size in MB to scan (default: 2)
  --notmp                   Skip /tmp scan when scanning user accounts
  --noshm                   Skip /dev/shm scan when scanning user accounts
  -f, --follow-symlinks     Follow directory symlinks (disabled by default for safety)
  --dry-run                 Preview quarantine moves without modifying any files
  --exit-code               Exit 2 if one or more threats are detected
  -o, --output <fmt>        Output format: table (default), json, csv
  -q, --quiet, -s, --simple Minimal output
  --no-color                Disable ANSI colors
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  ${SCRIPT_NAME} --path /home/percio/public_html
  ${SCRIPT_NAME} percio --engine both --exit-code
  ${SCRIPT_NAME} --path /var/www/html --quarantine --dry-run
  ${SCRIPT_NAME} --path /var/www/html --quarantine -o json
  ${SCRIPT_NAME} restore /var/quarantine/scan/20261123-223500

Exit codes:
  0  Clean (or restore succeeded)
  1  Error (invalid arguments, missing path/user, I/O error)
  2  Threats detected (with --exit-code)
EOF
}

parse_args() {
  local positional=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help|--usage|-u) usage; exit 0 ;;
      -v|--version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      -p|--path)
        [[ $# -ge 2 ]] || { printf '[ERR] --path requires a directory.\n' >&2; exit 1; }
        TARGET_PATH="$2"; SCAN_TMP=0; SCAN_SHM=0; shift 2 ;;
      --cwd) USE_CWD=1; SCAN_TMP=0; SCAN_SHM=0; shift ;;
      -r|--reseller)
        [[ $# -ge 2 ]] || { printf '[ERR] --reseller requires a username.\n' >&2; exit 1; }
        RESELLER="$2"; shift 2 ;;
      -a|--all) SCAN_ALL=1; shift ;;
      -l|--list)
        [[ $# -ge 2 ]] || { printf '[ERR] --list requires a file path.\n' >&2; exit 1; }
        LIST_FILE="$2"; SCAN_TMP=0; SCAN_SHM=0; shift 2 ;;
      --engine)
        [[ $# -ge 2 ]] || { printf '[ERR] --engine requires auto|clamav|heuristic|both.\n' >&2; exit 1; }
        ENGINE="$2"; shift 2 ;;
      -c|--clean|--quarantine) DO_QUARANTINE=1; shift ;;
      --quarantine-dir)
        [[ $# -ge 2 ]] || { printf '[ERR] --quarantine-dir requires a path.\n' >&2; exit 1; }
        QUARANTINE_DIR="$2"; shift 2 ;;
      --max-size)
        [[ $# -ge 2 ]] || { printf '[ERR] --max-size requires an integer (MB).\n' >&2; exit 1; }
        MAX_SIZE_MB="$2"; shift 2 ;;
      --notmp) SCAN_TMP=0; shift ;;
      --noshm) SCAN_SHM=0; shift ;;
      -f|--follow-symlinks) FOLLOW_SYMLINKS=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --exit-code) EXIT_CODE_MODE=1; shift ;;
      -o|--output)
        [[ $# -ge 2 ]] || { printf '[ERR] --output requires table|json|csv.\n' >&2; exit 1; }
        OUTPUT_FMT="$2"; shift 2 ;;
      -q|--quiet|-s|--simple) QUIET=1; shift ;;
      --no-color) NO_COLOR=1; shift ;;
      --) shift; while [[ $# -gt 0 ]]; do positional+=("$1"); shift; done ;;
      -*)
        printf '[ERR] Unknown option: %s\n' "$1" >&2
        exit 1 ;;
      *)
        positional+=("$1"); shift ;;
    esac
  done

  if [[ ${#positional[@]} -gt 0 && "${positional[0]}" == "restore" ]]; then
    ACTION="restore"
    RESTORE_TARGET="${positional[1]:-}"
  elif [[ ${#positional[@]} -gt 0 && -z "$TARGET_PATH" && -z "$RESELLER" && -z "$LIST_FILE" && "$SCAN_ALL" -eq 0 && "$USE_CWD" -eq 0 ]]; then
    TARGET_USER="${positional[0]}"
  fi

  case "$ENGINE" in
    auto|clamav|heuristic|both) ;;
    *) printf '[ERR] Invalid --engine: %s (expected auto|clamav|heuristic|both)\n' "$ENGINE" >&2; exit 1 ;;
  esac
  case "$OUTPUT_FMT" in
    table|json|csv) ;;
    *) printf '[ERR] Invalid --output: %s (expected table|json|csv)\n' "$OUTPUT_FMT" >&2; exit 1 ;;
  esac
  [[ "$MAX_SIZE_MB" =~ ^[0-9]+$ && "$MAX_SIZE_MB" -ge 1 ]] || { printf '[ERR] --max-size must be a positive integer.\n' >&2; exit 1; }
}

main() {
  parse_args "$@"

  if ! command -v python3 >/dev/null 2>&1; then
    printf '[ERR] python3 is required.\n' >&2
    exit 1
  fi

  init_colors

  local ts_utc cwd_path
  ts_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  cwd_path="$(pwd)"

  local py_script
  py_script="$(cat <<'PYEOF'
import csv
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

(
    action, target_user, target_path, reseller, list_file, restore_target,
    scan_all_s, use_cwd_s, scan_tmp_s, scan_shm_s, follow_symlinks_s,
    do_quarantine_s, quarantine_dir, engine, max_size_mb_s, dry_run_s,
    exit_code_s, fmt, quiet_s, cwd_path, script_name, script_version, ts_utc,
    c_red, c_green, c_yellow, c_cyan, c_bold, c_reset
) = sys.argv[1:30]

scan_all = scan_all_s == "1"
use_cwd = use_cwd_s == "1"
scan_tmp = scan_tmp_s == "1"
scan_shm = scan_shm_s == "1"
follow_symlinks = follow_symlinks_s == "1"
do_quarantine = do_quarantine_s == "1"
dry_run = dry_run_s == "1"
exit_code_mode = exit_code_s == "1"
quiet = quiet_s == "1"
max_bytes = int(max_size_mb_s) * 1024 * 1024

EXCLUDED_DIRS = {
    "virtfs", "cpeasyapache", "access-logs", "mail", "awstats",
    "webalizer", "analog", "cpbandwidth", "webalizerftp", ".git",
    "node_modules", ".security",
}

TEXT_SCAN_EXTS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8", ".phar",
    ".inc", ".ico", ".js", ".html", ".htm", ".shtml", ".cgi", ".pl", ".py",
    ".sh", ".htaccess", ".txt", ".suspected",
}

EICAR_STR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

HEURISTIC_RULES = [
    ("EICAR-Test-Signature", "CRITICAL", re.compile(re.escape(EICAR_STR))),
    ("PHP.Webshell.EvalBase64", "HIGH", re.compile(
        rb'\beval\s*\(\s*(?:@\s*)?(?:gzinflate|gzuncompress|str_rot13|base64_decode|rawurldecode)\s*\(',
        re.IGNORECASE,
    )),
    ("PHP.Webshell.UserInputExec", "CRITICAL", re.compile(
        rb'\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
        re.IGNORECASE,
    )),
    ("PHP.Webshell.AssertInput", "CRITICAL", re.compile(
        rb'\bassert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
        re.IGNORECASE,
    )),
    ("PHP.Webshell.PregReplaceE", "HIGH", re.compile(
        rb'\bpreg_replace\s*\(\s*[\'"]/[^\'"]{1,120}/[a-zA-Z]*e[a-zA-Z]*[\'"]\s*,',
        re.IGNORECASE,
    )),
    ("PHP.Webshell.KnownFamily", "CRITICAL", re.compile(
        rb'(?:FilesMan|WSO\s+[0-9]\.[0-9]|c99shell|r57shell|b374k|IndoXploit|ALFA\s+TEaM\s+Shell|Leaf\s+PHPMailer)',
        re.IGNORECASE,
    )),
    ("PHP.Backdoor.CreateFunction", "CRITICAL", re.compile(
        rb'\bcreate_function\s*\(\s*[\'"][\'"]\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
        re.IGNORECASE,
    )),
    ("PHP.Backdoor.DynamicInclude", "HIGH", re.compile(
        rb'\b(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
        re.IGNORECASE,
    )),
]


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "-"


def detect_clamav():
    for cand in [
        shutil.which("clamdscan"),
        shutil.which("clamscan"),
        "/usr/local/cpanel/3rdparty/bin/clamscan",
    ]:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def get_homedir(user):
    if os.path.exists("/etc/psa/.psa.shadow"):
        p = f"/var/www/vhosts/{user}"
        if os.path.isdir(p):
            return os.path.realpath(p)
    try:
        hd = pwd.getpwnam(user).pw_dir
        if hd and os.path.isdir(hd):
            return os.path.realpath(hd)
    except KeyError:
        pass
    return None


def get_reseller_users(res):
    users = []
    if os.path.isfile("/etc/trueuserowners"):
        with open("/etc/trueuserowners", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if ":" in line:
                    u, own = line.split(":", 1)
                    if own.strip() == res:
                        users.append(u.strip())
    return sorted(set(users))


def collect_files_from_dir(root_dir):
    files = []
    for cur_root, dirs, fnames in os.walk(root_dir, followlinks=follow_symlinks):
        # Prune excluded dirs and (by default) symlinked dirs
        pruned = []
        for d in dirs:
            if d in EXCLUDED_DIRS:
                continue
            full_d = os.path.join(cur_root, d)
            if not follow_symlinks and os.path.islink(full_d):
                continue
            pruned.append(d)
        dirs[:] = pruned
        for fn in fnames:
            fp = os.path.join(cur_root, fn)
            if not follow_symlinks and os.path.islink(fp):
                continue
            files.append(fp)
    return files


def collect_tmp_shm_files(user=None):
    extra = []
    uid_filter = None
    if user:
        try:
            uid_filter = pwd.getpwnam(user).pw_uid
        except KeyError:
            uid_filter = None
    roots = []
    if scan_tmp and os.path.isdir("/tmp"):
        roots.append("/tmp")
    if scan_shm and os.path.isdir("/dev/shm"):
        roots.append("/dev/shm")
    for base in roots:
        for cur_root, dirs, fnames in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(cur_root, d))]
            for fn in fnames:
                fp = os.path.join(cur_root, fn)
                if os.path.islink(fp):
                    continue
                try:
                    st = os.lstat(fp)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if uid_filter is not None and st.st_uid != uid_filter:
                        continue
                    extra.append(fp)
                except Exception:
                    continue
    return extra


def heuristic_scan_files(file_list):
    hits = {}
    scanned = 0
    for fp in file_list:
        try:
            st = os.lstat(fp)
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size == 0 or st.st_size > max_bytes:
                continue
            _, ext = os.path.splitext(fp.lower())
            # Scan web/script extensions, extensionless files in /tmp or /dev/shm, or small files
            in_tmp = fp.startswith("/tmp/") or fp.startswith("/dev/shm/")
            if ext not in TEXT_SCAN_EXTS and not in_tmp:
                continue
            scanned += 1
            with open(fp, "rb") as f:
                data = f.read(max_bytes)
            for sig_name, sev, pat in HEURISTIC_RULES:
                if pat.search(data):
                    hits[fp] = {
                        "path": fp,
                        "engine": "heuristic",
                        "signature": sig_name,
                        "severity": sev,
                        "size_bytes": st.st_size,
                        "sha256": sha256_file(fp),
                    }
                    break
        except Exception:
            continue
    return hits, scanned


def clamav_scan_paths(clam_bin, targets, is_file_list=False):
    hits = {}
    if not clam_bin or not targets:
        return hits
    cmd = [clam_bin, "--infected", "--no-summary"]
    if os.path.basename(clam_bin) == "clamscan":
        cmd.extend([
            "-r",
            f"--max-filesize={max_size_mb_s}M",
            "--follow-dir-symlinks=" + ("1" if follow_symlinks else "0"),
            "--follow-file-symlinks=0",
        ])
        for ex in EXCLUDED_DIRS:
            cmd.append(f"--exclude-dir=/{ex}/")
    if is_file_list:
        cmd.extend(["-f", targets[0]])
    else:
        cmd.extend(targets)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=1800)
        for line in p.stdout.splitlines():
            if line.endswith(" FOUND"):
                parts = line[:-6].rsplit(": ", 1)
                if len(parts) == 2:
                    fp, sig = parts[0].strip(), parts[1].strip()
                    sz = os.path.getsize(fp) if os.path.isfile(fp) else 0
                    hits[fp] = {
                        "path": fp,
                        "engine": "clamav",
                        "signature": sig,
                        "severity": "HIGH",
                        "size_bytes": sz,
                        "sha256": sha256_file(fp),
                    }
    except Exception:
        pass
    return hits


def emit_output(payload, columns, rows, header_title):
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(columns)
        for r in rows:
            w.writerow(r)
        sys.stdout.write(buf.getvalue())
        return

    if not quiet:
        print("=" * 98)
        print(f" {c_bold}{script_name} v{script_version}{c_reset} | {header_title} | {ts_utc}")
        print("=" * 98)

    if not rows:
        print(f"{c_green}[CLEAN]{c_reset} No threats detected.")
        return

    widths = [len(c) for c in columns]
    for r in rows:
        for idx, val in enumerate(r):
            plain = re.sub(r'\033\[[0-9;]*m', '', str(val))
            if len(plain) > widths[idx]:
                widths[idx] = min(len(plain), 62)

    hdr = "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns))
    sep = "  ".join("-" * widths[i] for i in range(len(columns)))
    print(f"{c_bold}{hdr}{c_reset}")
    print(sep)
    for r in rows:
        cells = []
        for idx, val in enumerate(r):
            s = str(val)
            plain = re.sub(r'\033\[[0-9;]*m', '', s)
            pad = max(0, widths[idx] - len(plain))
            cells.append(s + (" " * pad))
        print("  ".join(cells))


# ==============================================================================
# ACTION: RESTORE FROM QUARANTINE
# ==============================================================================
if action == "restore":
    if not restore_target:
        print("[ERR] Usage: scan.sh restore <quarantine_vault_dir>", file=sys.stderr)
        sys.exit(1)
    mpath = os.path.join(restore_target, "manifest.json") if os.path.isdir(restore_target) else restore_target
    if not os.path.isfile(mpath):
        print(f"[ERR] Quarantine manifest not found: {mpath}", file=sys.stderr)
        sys.exit(1)
    with open(mpath, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    restored = []
    for item in manifest.get("quarantined", []):
        src = item["quarantine_path"]
        dst = item["original_path"]
        if not os.path.isfile(src):
            restored.append({"path": dst, "status": "MISSING_IN_VAULT"})
            continue
        if dry_run:
            restored.append({"path": dst, "status": "DRY-RUN"})
            continue
        parent = os.path.dirname(dst)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        shutil.move(src, dst)
        try:
            os.chmod(dst, int(item["mode"], 8))
            os.chown(dst, int(item["uid"]), int(item["gid"]))
        except Exception:
            pass
        restored.append({"path": dst, "status": "RESTORED"})

    payload = {
        "tool": script_name,
        "version": script_version,
        "action": "restore",
        "dry_run": dry_run,
        "manifest": mpath,
        "count": len(restored),
        "results": restored,
    }
    rows = [[r["status"], r["path"]] for r in restored]
    emit_output(payload, ["STATUS", "ORIGINAL_PATH"], rows, f"Quarantine Restore [{'DRY-RUN' if dry_run else 'APPLIED'}]")
    sys.exit(0)


# ==============================================================================
# ACTION: SCAN
# ==============================================================================
scan_roots = []
explicit_files = []
scope_label = ""

if list_file:
    if not os.path.isfile(list_file):
        print(f"[ERR] File list not found: {list_file}", file=sys.stderr)
        sys.exit(1)
    with open(list_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            p = line.strip()
            if p and os.path.isfile(p):
                explicit_files.append(p)
    scope_label = f"list:{list_file}"
elif target_path:
    if not os.path.exists(target_path):
        print(f"[ERR] Target path not found: {target_path}", file=sys.stderr)
        sys.exit(1)
    rp = os.path.realpath(target_path)
    if os.path.isfile(rp):
        explicit_files.append(rp)
    else:
        scan_roots.append(rp)
    scope_label = rp
elif use_cwd:
    scan_roots.append(os.path.realpath(cwd_path))
    scope_label = os.path.realpath(cwd_path)
elif reseller:
    rusers = get_reseller_users(reseller)
    if not rusers:
        print(f"[ERR] No resold accounts found for reseller '{reseller}'.", file=sys.stderr)
        sys.exit(1)
    for u in rusers:
        hd = get_homedir(u)
        if hd:
            scan_roots.append(hd)
    scope_label = f"reseller:{reseller} ({len(rusers)} accts)"
elif scan_all:
    base = "/var/www/vhosts" if os.path.exists("/etc/psa/.psa.shadow") else "/home"
    if not os.path.isdir(base):
        print(f"[ERR] Base directory not found: {base}", file=sys.stderr)
        sys.exit(1)
    scan_roots.append(base)
    scope_label = f"all:{base}"
elif target_user:
    hd = get_homedir(target_user)
    if not hd:
        print(f"[ERR] Could not resolve home directory for user '{target_user}'.", file=sys.stderr)
        sys.exit(1)
    scan_roots.append(hd)
    scope_label = f"user:{target_user}"
else:
    print("[ERR] Specify a <username>, --path <dir>, --cwd, --reseller <user>, --all, or --list <file>.", file=sys.stderr)
    sys.exit(1)

clam_bin = detect_clamav()
use_clam = False
use_heur = False

if engine == "clamav":
    if not clam_bin:
        print("[ERR] --engine clamav requested, but clamscan/clamdscan is not installed.", file=sys.stderr)
        sys.exit(1)
    use_clam = True
elif engine == "heuristic":
    use_heur = True
elif engine == "both":
    use_heur = True
    use_clam = bool(clam_bin)
else:  # auto
    use_heur = True
    use_clam = bool(clam_bin)

all_files = list(explicit_files)
for r in scan_roots:
    all_files.extend(collect_files_from_dir(r))
if target_user and (scan_tmp or scan_shm):
    all_files.extend(collect_tmp_shm_files(target_user))

findings_map = {}
scanned_count = len(all_files)

if use_heur:
    h_hits, h_scanned = heuristic_scan_files(all_files)
    findings_map.update(h_hits)
    scanned_count = max(scanned_count, h_scanned)

if use_clam:
    if list_file:
        c_hits = clamav_scan_paths(clam_bin, [list_file], is_file_list=True)
    else:
        c_hits = clamav_scan_paths(clam_bin, scan_roots + explicit_files, is_file_list=False)
    for fp, rec in c_hits.items():
        if fp not in findings_map:
            findings_map[fp] = rec

findings = sorted(findings_map.values(), key=lambda x: x["path"])
vault_dir = ""
quarantined_records = []

if do_quarantine and findings:
    run_slug = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    vault_dir = os.path.join(quarantine_dir, run_slug)
    if not dry_run:
        os.makedirs(vault_dir, mode=0o700, exist_ok=True)
        os.chmod(vault_dir, 0o700)
    for idx, fitem in enumerate(findings, 1):
        src = fitem["path"]
        qname = f"{idx:04d}_{os.path.basename(src)}.quarantined"
        qpath = os.path.join(vault_dir, qname)
        st = os.lstat(src)
        rec = {
            "original_path": src,
            "quarantine_path": qpath,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "sha256": fitem["sha256"],
            "signature": fitem["signature"],
            "engine": fitem["engine"],
        }
        if not dry_run:
            shutil.move(src, qpath)
            os.chmod(qpath, 0o400)
            fitem["action"] = "QUARANTINED"
        else:
            fitem["action"] = "DRY-RUN"
        quarantined_records.append(rec)
    if not dry_run:
        mpath = os.path.join(vault_dir, "manifest.json")
        fd = os.open(mpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as mf:
            mf.write(json.dumps({
                "tool": script_name,
                "version": script_version,
                "created_utc": ts_utc,
                "scope": scope_label,
                "quarantined": quarantined_records,
            }, indent=2) + "\n")
else:
    for fitem in findings:
        fitem["action"] = "DETECTED"

engines_used = []
if use_clam:
    engines_used.append(f"clamav({os.path.basename(clam_bin)})")
if use_heur:
    engines_used.append("heuristic")

payload = {
    "tool": script_name,
    "version": script_version,
    "action": "scan",
    "dry_run": dry_run,
    "timestamp_utc": ts_utc,
    "scope": scope_label,
    "engines_used": engines_used,
    "files_scanned": scanned_count,
    "threats_found": len(findings),
    "quarantine_vault": vault_dir or None,
    "findings": findings,
}

rows = []
for fitem in findings:
    sev = fitem["severity"]
    act = fitem["action"]
    if fmt == "table":
        sev = f"{c_red}{sev}{c_reset}" if sev == "CRITICAL" else f"{c_yellow}{sev}{c_reset}"
        if act == "QUARANTINED":
            act = f"{c_green}QUARANTINED{c_reset}"
        elif act == "DRY-RUN":
            act = f"{c_yellow}DRY-RUN{c_reset}"
        else:
            act = f"{c_red}DETECTED{c_reset}"
    rows.append([sev, fitem["engine"], fitem["signature"], act, fitem["path"]])

emit_output(
    payload,
    ["SEVERITY", "ENGINE", "SIGNATURE", "ACTION", "PATH"],
    rows,
    f"Scan | {scope_label} | {'+'.join(engines_used)}",
)
if fmt == "table" and not quiet:
    print(f"\nSummary: {scanned_count} file(s) scanned | {len(findings)} threat(s) found")
    if vault_dir:
        tag = "[DRY-RUN] " if dry_run else ""
        print(f"Vault:   {tag}{vault_dir}")

if exit_code_mode and len(findings) > 0:
    sys.exit(2)
sys.exit(0)
PYEOF
)"

  python3 -c "$py_script" \
    "$ACTION" "$TARGET_USER" "$TARGET_PATH" "$RESELLER" "$LIST_FILE" "$RESTORE_TARGET" \
    "$SCAN_ALL" "$USE_CWD" "$SCAN_TMP" "$SCAN_SHM" "$FOLLOW_SYMLINKS" \
    "$DO_QUARANTINE" "$QUARANTINE_DIR" "$ENGINE" "$MAX_SIZE_MB" "$DRY_RUN" \
    "$EXIT_CODE_MODE" "$OUTPUT_FMT" "$QUIET" "$cwd_path" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$ts_utc" \
    "$C_RED" "$C_GREEN" "$C_YELLOW" "$C_CYAN" "$C_BOLD" "$C_RESET"
}

main "$@"
