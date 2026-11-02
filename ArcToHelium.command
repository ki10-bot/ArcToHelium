#!/bin/bash
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
#  ARC  ->  HELIUM   |   Cookie Migration
#  Just double-click. No input, no installation required.
# ---------------------------------------------------------------------------
set -u

cd "$HOME" 2>/dev/null || cd /
printf '\033]0;Arc > Helium | Cookie Migration\007' 2>/dev/null || true

echo "=================================================================="
echo "  ARC  ->  HELIUM   |   Cookie Migration"
echo "  Fully automatic - please do not type anything."
echo "=================================================================="
echo ""

# On a Mac without Xcode Command Line Tools, /usr/bin/python3 is only a
# stub that opens an install dialog. We detect it WITHOUT running it.
# If it is unavailable, the script automatically falls back to the Perl
# built into macOS (see below).
pick_python() {
    local c
    local -a cands=()
    [ -n "${A2H_PYTHON:-}" ] && cands+=("$A2H_PYTHON")
    cands+=(
        /opt/homebrew/bin/python3
        /usr/local/bin/python3
        /opt/homebrew/opt/python@3.14/bin/python3
        /opt/homebrew/opt/python@3.13/bin/python3
        /opt/homebrew/opt/python@3.12/bin/python3
        /opt/local/bin/python3
        /usr/local/opt/python@3.13/bin/python3
        /usr/local/opt/python@3.12/bin/python3
        "$HOME/.pyenv/shims/python3"
        "$HOME/miniconda3/bin/python3"
        "$HOME/anaconda3/bin/python3"
        /opt/conda/bin/python3
    )
    for c in /Library/Frameworks/Python.framework/Versions/*/bin/python3 \
             /opt/homebrew/bin/python3.* /usr/local/bin/python3.*; do
        [ -x "$c" ] && cands+=("$c")
    done
    if [ -x /usr/bin/python3 ] && /usr/bin/xcode-select -p >/dev/null 2>&1; then
        cands+=(/usr/bin/python3)
    fi
    p=$(command -v python3 2>/dev/null || true)
    if [ -n "$p" ] && [ "$p" != "/usr/bin/python3" ]; then cands+=("$p"); fi

    for c in "${cands[@]}"; do
        [ -x "$c" ] || continue
        if "$c" -c 'import sys, sqlite3, hashlib, subprocess, json; sys.exit(0 if sys.version_info >= (3, 7) else 1)' >/dev/null 2>&1; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

RC=2
if [ "${A2H_FORCE_PERL:-0}" = "1" ]; then
    PY=""
else
    PY="$(pick_python || true)"
fi

if [ -n "$PY" ]; then
    echo "  Mode: Python 3 ($PY)"
    echo ""
    "$PY" - <<'__ARC2HELIUM_PYTHON_EOF__'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Arc -> Helium: 1:1 cookie migration for macOS.

Reads every cookie from every Arc profile, decrypts it with the Arc
Keychain entry ("Arc Safe Storage"), re-encrypts it with the Helium
Keychain entry ("Helium Storage Key") and writes it -- including all
attributes -- into Helium's cookie databases.

Python standard library only. No pip packages, no Xcode, no Homebrew.
"""
from __future__ import annotations

import datetime as _dt
import getpass
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Environment / testability (all defaults stay untouched in normal use)
# ---------------------------------------------------------------------------
def env(name: str, default: str = "") -> str:
    return os.environ.get("A2H_" + name, default)


def HOME() -> str:
    return os.path.abspath(env("HOME") or os.path.expanduser("~"))


def flag(name: str) -> bool:
    return env(name, "") not in ("", "0", "false", "no")


SUPPORT = os.path.join(HOME(), "Library", "Application Support", "ArcToHelium")
LOGFILE = os.path.join(SUPPORT, "last-run.log")
CACHEFILE = os.path.join(SUPPORT, "key-cache.json")
KC_CACHE_SERVICE = "Arc to Helium Migration Keys"
KC_CACHE_ACCOUNT = getpass.getuser()

ARC_ROOTS = [
    os.path.join(HOME(), "Library", "Application Support", "Arc", "User Data"),
    os.path.join(HOME(), "Library", "Application Support", "Arc"),
]
HELIUM_ROOTS = [
    os.path.join(HOME(), "Library", "Application Support", "net.imput.helium"),
    os.path.join(HOME(), "Library", "Application Support", "Helium"),
]

ARC_KEYS = [("Arc Safe Storage", "Arc"),
            ("Chromium Safe Storage", "Chromium"),
            ("Chrome Safe Storage", "Chrome")]
HELIUM_KEYS = [("Helium Storage Key", "Helium"),
               ("Helium Safe Storage", "Helium"),
               ("Chromium Safe Storage", "Chromium")]

# Should session cookies (is_persistent = 0) be marked as persistent?
# Chromium deletes those cookies on the next launch otherwise. Default: yes,
# so that nothing is lost.
FORCE_PERSISTENT = env("FORCE_PERSISTENT", "1") not in ("0", "false", "no")

# Columns Helium may have in addition that are NOT NULL without a DEFAULT.
COLUMN_DEFAULTS = {
    "top_frame_site_key": "",
    "value": "",
    "path": "/",
    "host_key": "",
    "name": "",
    "samesite": -1,
    "source_port": -1,
    "source_scheme": 0,
    "source_type": 0,
    "has_cross_site_ancestor": 0,
    "priority": 1,
    "has_expires": 1,
    "is_persistent": 1,
    "last_update_utc": 0,
    "creation_utc": 0,
    "last_access_utc": 0,
    "expires_utc": 0,
    "is_secure": 0,
    "is_httponly": 0,
    "encrypted_value": b"",
}

_LOG = []


def log(msg: str = "") -> None:
    print(msg, flush=True)
    _LOG.append(msg)


def warn(msg: str) -> None:
    log("  ! " + msg)


def ok(msg: str) -> None:
    log("  ok  " + msg)


class Fatal(Exception):
    pass


# ---------------------------------------------------------------------------
# AES-128 (ECB/CBC) in pure Python -- no openssl or pip needed
# ---------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _gpow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gmul(r, a)
        a = _gmul(a, a)
        n >>= 1
    return r


def _make_sboxes():
    sbox = []
    for a in range(256):
        inv = _gpow(a, 254) if a else 0
        s = inv
        for sh in (1, 2, 3, 4):
            s ^= ((inv << sh) | (inv >> (8 - sh))) & 0xFF
        sbox.append(s ^ 0x63)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _make_sboxes()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


class AES128:
    """AES-128 with ECB block operations; CBC is done manually."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key")
        w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
        for i in range(4, 44):
            t = w[i - 1][:]
            if i % 4 == 0:
                t = t[1:] + t[:1]
                t = [SBOX[x] for x in t]
                t[0] ^= RCON[i // 4 - 1]
            w.append([w[i - 4][j] ^ t[j] for j in range(4)])
        self.rk = []
        for r in range(11):
            self.rk.append(bytes(sum((w[r * 4 + c] for c in range(4)), [])))

    @staticmethod
    def _shift_rows(s: bytearray, inverse: bool = False) -> bytearray:
        out = bytearray(16)
        for c in range(4):
            for r in range(4):
                src_c = (c - r) % 4 if inverse else (c + r) % 4
                out[4 * c + r] = s[4 * src_c + r]
        return out

    @staticmethod
    def _mix_columns(s: bytearray, inverse: bool = False) -> bytearray:
        out = bytearray(16)
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            if inverse:
                out[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
                out[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
                out[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
                out[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
            else:
                out[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
                out[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
                out[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
                out[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        return out

    @staticmethod
    def _add_round_key(s: bytearray, rk: bytes) -> bytearray:
        return bytearray(s[i] ^ rk[i] for i in range(16))

    def encrypt_block(self, block: bytes) -> bytes:
        s = self._add_round_key(bytearray(block), self.rk[0])
        for r in range(1, 11):
            s = bytearray(SBOX[b] for b in s)
            s = self._shift_rows(s)
            if r != 10:
                s = self._mix_columns(s)
            s = self._add_round_key(s, self.rk[r])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = self._add_round_key(bytearray(block), self.rk[10])
        for r in range(9, -1, -1):
            s = self._shift_rows(s, inverse=True)
            s = bytearray(INV_SBOX[b] for b in s)
            s = self._add_round_key(s, self.rk[r])
            if r != 0:
                s = self._mix_columns(s, inverse=True)
        return bytes(s)


IV = b" " * 16


def _pkcs7(data: bytes) -> bytes:
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def _unpkcs7(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def aes_cbc_encrypt(plain: bytes, key: bytes) -> bytes:
    cipher = AES128(key)
    data = _pkcs7(plain)
    prev = IV
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = cipher.encrypt_block(block)
        out += prev
    return bytes(out)


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes | None:
    if len(data) < 16 or len(data) % 16:
        return None
    cipher = AES128(key)
    prev = IV
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        dec = cipher.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return _unpkcs7(bytes(out))


def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), b"saltysalt", 1003, 16)


def chromium_decrypt(blob: bytes, key: bytes) -> bytes | None:
    """Decrypts a 'v10'/'v11' encrypted_value (macOS/Linux)."""
    if not blob:
        return None
    if blob[:3] not in (b"v10", b"v11"):
        return None
    return aes_cbc_decrypt(blob[3:], key)


def chromium_encrypt(plain: bytes, key: bytes) -> bytes:
    return b"v10" + aes_cbc_encrypt(plain, key)


def host_hash(host_key: str) -> bytes:
    return hashlib.sha256(host_key.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# macOS helpers
# ---------------------------------------------------------------------------
SECURITY = "/usr/bin/security"
OPEN = "/usr/bin/open"


def security_bin() -> str:
    return env("SECURITY") or SECURITY


def open_bin() -> str:
    return env("OPEN") or OPEN


def run(cmd, timeout=30, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        return None
    except (OSError, ValueError):
        return None


def keychain_password(service: str, account: str, timeout: int = 150) -> str | None:
    r = run([security_bin(), "find-generic-password", "-s", service,
             "-a", account, "-w"], timeout=timeout)
    if r is None or r.returncode != 0:
        return None
    pw = r.stdout.rstrip("\r\n")
    return pw or None


def cache_load() -> dict:
    # 1) our own Keychain item (created with -T /usr/bin/security,
    #    so it can be read without a prompt)
    r = run([security_bin(), "find-generic-password", "-s", KC_CACHE_SERVICE,
             "-a", KC_CACHE_ACCOUNT, "-w"], timeout=6)
    if r is not None and r.returncode == 0 and r.stdout.strip():
        try:
            return json.loads(r.stdout.strip())
        except (ValueError, TypeError):
            pass
    # 2) file fallback (readable only by the current user)
    try:
        with open(CACHEFILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def cache_save(data: dict) -> None:
    payload = json.dumps(data, separators=(",", ":"))
    run([security_bin(), "add-generic-password", "-U", "-s", KC_CACHE_SERVICE,
         "-a", KC_CACHE_ACCOUNT, "-w", payload, "-T", "/usr/bin/security"],
        timeout=20)
    try:
        os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
        tmp = CACHEFILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            os.chmod(tmp, 0o600)
            f.write(payload)
        os.replace(tmp, CACHEFILE)
        os.chmod(CACHEFILE, 0o600)
    except OSError:
        pass


def platform_check() -> None:
    if flag("ALLOW_NON_MAC"):
        return
    if sys.platform != "darwin":
        raise Fatal("This program only runs on macOS.")


def quit_helium() -> bool:
    """Quits Helium (without Apple Events -> no TCC prompt)."""
    if flag("SKIP_QUIT"):
        return False
    ps = run(["/bin/ps", "-axww", "-o", "pid=,command="], timeout=15)
    if ps is None:
        return False
    me = os.getpid()
    pids = []
    for line in ps.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        pid, cmd = int(parts[0]), parts[1]
        if pid == me:
            continue
        low = cmd.lower()
        if "helium.app/contents/macos/" in low or low.startswith("helium ") \
                or "/helium.app/contents/macos/helium" in low:
            pids.append(pid)
    if not pids:
        return False
    log("  Quitting Helium (PIDs: %s) ..." % ", ".join(map(str, pids[:12])))
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    deadline = time.time() + 15
    while time.time() < deadline:
        alive = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        if not alive:
            break
        time.sleep(0.3)
        pids = alive
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    time.sleep(0.4)
    return True


def relaunch_helium() -> None:
    if flag("SKIP_RELAUNCH"):
        return
    for args in (["-b", "net.imput.helium"], ["-a", "Helium"]):
        r = run([open_bin()] + args, timeout=20)
        if r is not None and r.returncode == 0:
            ok("Helium is being reopened.")
            return
    warn("Could not relaunch Helium automatically (please open it yourself).")


def open_privacy_settings() -> None:
    run([open_bin(), "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"],
        timeout=15)


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------
def ro_uri(path: str) -> str:
    return "file:" + urllib.parse.quote(os.path.abspath(path), safe="/") + "?mode=ro"


def snapshot_db(path: str, dest: str) -> str:
    """Consistent copy of a (possibly open, WAL-mode) SQLite DB."""
    src = sqlite3.connect(ro_uri(path), uri=True, timeout=10)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)          # automatically replays an existing WAL
    finally:
        src.close()
        dst.close()
    return dest


def table_columns(con) -> list:
    return [r[1] for r in con.execute("PRAGMA table_info(cookies)").fetchall()]


def table_info(con) -> list:
    return con.execute("PRAGMA table_info(cookies)").fetchall()


def meta_version(con) -> int:
    try:
        row = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.Error, ValueError, TypeError):
        return 0


def count_cookies(con) -> int:
    try:
        return int(con.execute("SELECT COUNT(*) FROM cookies").fetchone()[0])
    except sqlite3.Error:
        return -1


def sample_rows(con, limit: int = 12) -> list:
    try:
        cols = table_columns(con)
        if "host_key" not in cols or "encrypted_value" not in cols:
            return []
        return con.execute(
            "SELECT host_key, encrypted_value FROM cookies "
            "WHERE encrypted_value IS NOT NULL AND length(encrypted_value) > 3 "
            "LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error:
        return []


def looks_printable(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:64]
    good = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(sample) > 0.85


def probe_key(con, key: bytes):
    """-> (valid, has_hash_prefix) or (False, None)."""
    yes = no = 0
    for host, blob in sample_rows(con):
        plain = chromium_decrypt(bytes(blob), key)
        if plain is None:
            continue
        if len(plain) >= 32 and plain[:32] == host_hash(host or ""):
            yes += 1
        elif looks_printable(plain):
            no += 1
    if yes == 0 and no == 0:
        return (False, None)
    return (True, yes >= no)


def resolve_key(candidates, cached_hex, validation_con, label: str):
    """Uses the cached key when it can be verified against real cookies,
    which avoids any Keychain prompt at all. Otherwise the Keychain
    is read once."""
    cached = None
    if cached_hex:
        try:
            cached = bytes.fromhex(cached_hex)
            if len(cached) != 16:
                cached = None
        except ValueError:
            cached = None
    if cached is not None and validation_con is not None:
        valid, _ = probe_key(validation_con, cached)
        if valid:
            ok("%s key from cache (no prompt needed)." % label)
            return cached
    if cached is not None and validation_con is None:
        # No probe cookies available (e.g. a completely fresh Helium profile):
        # briefly confirm the cached key against the Keychain.
        # After a one-time 'Always Allow' this takes milliseconds;
        # if macOS does prompt and nobody is there, the cache stays active.
        for service, account in candidates:
            pw = keychain_password(service, account, timeout=8)
            if pw:
                ok("%s key confirmed from the Keychain." % label)
                return derive_key(pw)
        ok("%s key from cache." % label)
        return cached

    log("  Reading %s key from the macOS Keychain ..." % label)
    log("    (If macOS asks once: please click 'Always Allow'.)")
    for service, account in candidates:
        pw = keychain_password(service, account)
        if not pw:
            continue
        key = derive_key(pw)
        if validation_con is not None:
            valid, _ = probe_key(validation_con, key)
            if not valid:
                warn('Keychain entry "%s" does not match the cookies '
                     "- trying the next one." % service)
                continue
        ok('%s key found (%s / %s).' % (label, service, account))
        return key
    raise Fatal(
        "Could not read the %s key from the macOS Keychain.\n"
        "  Possible reasons: the dialog was denied, or %s has never\n"
        "  been launched. Please start %s once and double-click this program again."
        % (label, label, label))


# ---------------------------------------------------------------------------
# Path discovery
# ---------------------------------------------------------------------------
def first_existing(roots) -> str | None:
    for r in roots:
        if os.path.isdir(r):
            return r
    return None


def find_cookie_dbs(root: str) -> dict:
    """profile name -> list of all Cookies DBs (incl. Network/Cookies)."""
    out = {}
    if not root or not os.path.isdir(root):
        return out
    try:
        entries = sorted(os.listdir(root))
    except OSError as e:
        raise Fatal("Cannot read %s (%s).\n"
                    "  -> Please give Terminal/iTerm 'Full Disk Access' once in "
                    "System Settings > Privacy & Security." % (root, e))
    for name in entries:
        p = os.path.join(root, name)
        if not os.path.isdir(p):
            continue
        found = []
        for rel in ("Network/Cookies", "Cookies"):
            f = os.path.join(p, rel)
            if os.path.isfile(f) and os.path.getsize(f) >= 512:
                found.append(f)
        # also unknown layouts (max. 2 levels deep)
        for f in glob.glob(os.path.join(p, "*", "Cookies")):
            f = os.path.normpath(f)
            if os.path.isfile(f) and f not in found:
                found.append(f)
        if found:
            out[name] = found
    return out


def cookie_db_is_valid(path: str) -> bool:
    try:
        con = sqlite3.connect(ro_uri(path), uri=True, timeout=5)
        n = count_cookies(con)
        con.close()
        return n >= 0
    except sqlite3.Error:
        return False


def target_paths_for(helium_root: str, profile: str, existing: list) -> list:
    """All target files to write to. If Helium has no Cookies DB yet,
    both common Chromium paths are created."""
    if existing:
        return existing
    d = os.path.join(helium_root, profile)
    return [os.path.join(d, "Network", "Cookies"),
            os.path.join(d, "Cookies")]


# ---------------------------------------------------------------------------
# Transformation
# ---------------------------------------------------------------------------
def transform_payload(enc: bytes, plain_value, host_key: str,
                      arc_key: bytes, helium_key: bytes,
                      src_hash: bool, dst_hash: bool) -> tuple:
    """-> (new encrypted_value, plaintext length, error)"""
    if enc and len(enc) > 3:
        plain = chromium_decrypt(enc, arc_key)
        if plain is None:
            return (None, 0, "decryption failed")
        if src_hash:
            if len(plain) >= 32 and plain[:32] == host_hash(host_key):
                value_bytes = plain[32:]
            else:
                return (None, 0, "hash prefix missing (wrong key?)")
        else:
            value_bytes = plain
    else:
        # older / unencrypted cookies: plaintext from the 'value' column
        if isinstance(plain_value, bytes):
            value_bytes = plain_value
        else:
            value_bytes = (plain_value or "").encode("utf-8")
    payload = (host_hash(host_key) if dst_hash else b"") + value_bytes
    return (chromium_encrypt(payload, helium_key), len(value_bytes), None)


# Canonical Chromium v24 schema. Every Arc profile is normalised into this
# format; on write it is mapped onto Helium's own schema. This way no rows
# are lost even with multiple Cookies files per profile, and a newly
# created Helium profile is always v24-compatible.
CANON_COLS = [
    "creation_utc", "host_key", "top_frame_site_key", "name", "value",
    "encrypted_value", "path", "expires_utc", "is_secure", "is_httponly",
    "last_access_utc", "has_expires", "is_persistent", "priority",
    "samesite", "source_scheme", "source_port", "last_update_utc",
    "source_type", "has_cross_site_ancestor",
]
CANON_TYPES = {
    "creation_utc": "INTEGER", "host_key": "TEXT", "top_frame_site_key": "TEXT",
    "name": "TEXT", "value": "TEXT", "encrypted_value": "BLOB", "path": "TEXT",
    "expires_utc": "INTEGER", "is_secure": "INTEGER", "is_httponly": "INTEGER",
    "last_access_utc": "INTEGER", "has_expires": "INTEGER",
    "is_persistent": "INTEGER", "priority": "INTEGER", "samesite": "INTEGER",
    "source_scheme": "INTEGER", "source_port": "INTEGER",
    "last_update_utc": "INTEGER", "source_type": "INTEGER",
    "has_cross_site_ancestor": "INTEGER",
}


def read_arc_rows(con, wanted):
    sql = "SELECT " + ", ".join('"%s"' % c for c in wanted) + " FROM cookies"
    return con.execute(sql).fetchall()


def canonical_rows(con):
    """Reads any Chromium Cookies DB and returns canonical tuples
    in CANON_COLS order."""
    cols = table_columns(con)
    present = [c for c in CANON_COLS if c in cols]
    sql = "SELECT " + ", ".join('"%s"' % c for c in present) + " FROM cookies"
    out = []
    for raw in con.execute(sql):
        d = {c: COLUMN_DEFAULTS.get(c, 0) for c in CANON_COLS}
        for c, v in zip(present, raw):
            if isinstance(v, memoryview):
                v = bytes(v)
            d[c] = v
        out.append(tuple(d[c] for c in CANON_COLS))
    return out


def make_combined_snapshot(dest: str, row_groups: list) -> str:
    """Creates a clean v24 database with all rows from all Cookies
    files of an Arc profile (values still Arc-encrypted)."""
    if os.path.isfile(dest):
        os.remove(dest)
    con = sqlite3.connect(dest)
    ddl = ", ".join('"%s" %s NOT NULL' % (c, CANON_TYPES[c]) for c in CANON_COLS)
    con.execute("CREATE TABLE meta(key TEXT NOT NULL UNIQUE PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES('version','24')")
    con.execute("INSERT INTO meta VALUES('last_compatible_version','24')")
    con.execute("CREATE TABLE cookies(%s)" % ddl)
    con.execute("CREATE UNIQUE INDEX cookies_unique_index ON cookies("
                "host_key, top_frame_site_key, has_cross_site_ancestor, "
                "name, path, source_scheme, source_port)")
    sql = "INSERT OR REPLACE INTO cookies(%s) VALUES(%s)" % (
        ", ".join(CANON_COLS), ", ".join("?" * len(CANON_COLS)))
    for rows in row_groups:
        for r in rows:
            try:
                con.execute(sql, r)
            except sqlite3.Error:
                pass
    con.commit()
    con.close()
    return dest


def merge_into_target(target_db: str, arc_rows: list, arc_cols: list,
                      arc_key: bytes, helium_key: bytes,
                      src_hash: bool) -> dict:
    """Writes the Arc rows (re-encrypted) into an existing Helium DB.
    Columns are mapped via their intersection."""
    stats = {"inserted": 0, "failed": 0, "before": 0, "after": 0, "errors": []}
    con = sqlite3.connect(target_db, timeout=20, isolation_level=None)
    try:
        # Fully merge the WAL into the main file so that orphaned -wal
        # files cannot overwrite our changes later.
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            con.execute("PRAGMA journal_mode=DELETE")
        except sqlite3.Error:
            pass
        stats["before"] = count_cookies(con)
        dst_hash = meta_version(con) >= 24
        info = table_info(con)
        tcols = [r[1] for r in info]
        common = [c for c in tcols if c in arc_cols]
        if "encrypted_value" not in common and "encrypted_value" in tcols:
            common.append("encrypted_value")
        extra = []
        for cid, name, typ, notnull, dflt, pk in info:
            if name in common or pk:
                continue
            if notnull and dflt is None:
                extra.append(name)
        allcols = common + extra
        placeholders = ", ".join("?" for _ in allcols)
        sql = "INSERT OR REPLACE INTO cookies (%s) VALUES (%s)" % (
            ", ".join('"%s"' % c.replace('"', '""') for c in allcols), placeholders)

        con.execute("BEGIN")
        for row in arc_rows:
            d = dict(zip(arc_cols, row))
            host = d.get("host_key", "")
            if isinstance(host, bytes):
                host = host.decode("utf-8", "replace")
            enc = d.get("encrypted_value", b"")
            enc = bytes(enc) if isinstance(enc, (bytes, bytearray, memoryview)) else b""
            new_enc, _, err = transform_payload(
                enc, d.get("value", ""), host, arc_key, helium_key,
                src_hash, dst_hash)
            if err:
                stats["failed"] += 1
                if len(stats["errors"]) < 8:
                    stats["errors"].append("%s/%s: %s" % (host, d.get("name", "?"), err))
                continue
            values = []
            for c in allcols:
                if c == "encrypted_value":
                    values.append(new_enc)
                elif c == "value":
                    values.append("")     # never populate both at the same time!
                elif c == "is_persistent" and FORCE_PERSISTENT:
                    values.append(1)
                elif c in d:
                    v = d[c]
                    values.append(bytes(v) if isinstance(v, memoryview) else v)
                else:
                    values.append(COLUMN_DEFAULTS.get(c, 0))
            try:
                con.execute(sql, values)
                stats["inserted"] += 1
            except sqlite3.Error as e:
                stats["failed"] += 1
                if len(stats["errors"]) < 8:
                    stats["errors"].append("%s/%s: %s" % (host, d.get("name", "?"), e))
        con.commit()
        try:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        stats["after"] = count_cookies(con)
    finally:
        con.close()
    # Remove orphaned WAL/SHM files (Helium recreates them on launch)
    for suffix in ("-wal", "-shm"):
        try:
            p = target_db + suffix
            if os.path.isfile(p) and os.path.getsize(p) <= 64 * 1024:
                os.remove(p)
        except OSError:
            pass
    return stats


def build_clone(source_db: str, arc_key: bytes, helium_key: bytes,
                src_hash: bool, dst_hash: bool, dest: str) -> dict:
    """For profiles without an existing Helium DB: clone the (canonical,
    v24) Arc database 1:1 and only re-encrypt the encrypted_value
    column with the Helium key."""
    stats = {"inserted": 0, "failed": 0, "before": 0, "after": 0, "errors": []}
    shutil.copy2(source_db, dest)
    con = sqlite3.connect(dest, timeout=20, isolation_level=None)
    try:
        try:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("UPDATE OR IGNORE meta SET value='24' WHERE key='version'")
            con.execute("UPDATE OR IGNORE meta SET value='24' "
                        "WHERE key='last_compatible_version'")
        except sqlite3.Error:
            pass
        stats["before"] = count_cookies(con)
        cur = con.execute("SELECT rowid, host_key, value, encrypted_value FROM cookies")
        updates = []
        for rowid, host, value, enc in cur.fetchall():
            if isinstance(host, bytes):
                host = host.decode("utf-8", "replace")
            enc = bytes(enc) if isinstance(enc, (bytes, bytearray, memoryview)) else b""
            new_enc, _, err = transform_payload(enc, value, host, arc_key,
                                                helium_key, src_hash, dst_hash)
            if err:
                stats["failed"] += 1
                if len(stats["errors"]) < 8:
                    stats["errors"].append("%s: %s" % (host, err))
                continue
            updates.append((new_enc, 1 if FORCE_PERSISTENT else 0, rowid))
        con.execute("BEGIN")
        con.executemany(
            "UPDATE cookies SET encrypted_value=?, value='', "
            "is_persistent=CASE WHEN ?=1 THEN 1 ELSE is_persistent END WHERE rowid=?",
            updates)
        con.commit()
        stats["after"] = count_cookies(con)
        stats["inserted"] = len(updates)
    finally:
        con.close()
    return stats


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------
def main() -> int:
    os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
    started = _dt.datetime.now()
    log("=" * 66)
    log("  ARC  ->  HELIUM   |   Cookie Migration v" + VERSION)
    log("  " + started.strftime("%d.%m.%Y  %H:%M:%S"))
    log("=" * 66)
    platform_check()

    if not flag("ALLOW_NON_MAC"):
        if not os.path.isdir("/Applications") :
            raise Fatal("macOS not detected.")

    arc_root = env("ARC_ROOT") or first_existing(ARC_ROOTS)
    helium_root = env("HELIUM_ROOT") or first_existing(HELIUM_ROOTS)

    if not arc_root:
        raise Fatal("Arc profile folder not found (~/Library/Application Support/Arc/User Data).")
    if not helium_root:
        # Helium has never been launched: create the folder automatically.
        helium_root = HELIUM_ROOTS[0]
        os.makedirs(helium_root, exist_ok=True)
        ok("Created Helium profile folder: " + helium_root)
    log("  Arc    : " + arc_root)
    log("  Helium : " + helium_root)

    arc_profiles = find_cookie_dbs(arc_root)
    helium_profiles = find_cookie_dbs(helium_root)
    if not arc_profiles:
        raise Fatal("No Arc Cookies database found. "
                    "Is Arc installed and has it been used yet?")

    log("  Found: %d Arc profile(s), %d Helium profile(s)." %
        (len(arc_profiles), len(helium_profiles)))

    # Backup (exact 1:1 copies BEFORE any change)
    backup = os.path.join(SUPPORT, "Backups",
                          started.strftime("%Y-%m-%d_%H-%M-%S"))
    os.makedirs(backup, exist_ok=True)
    backed_up = 0
    for label, profiles in (("Arc", arc_profiles), ("Helium-before", helium_profiles)):
        for prof, paths in profiles.items():
            for p in paths:
                try:
                    rel = os.path.relpath(p, HOME())
                    d = os.path.join(backup, label, rel)
                    os.makedirs(os.path.dirname(d), exist_ok=True)
                    shutil.copy2(p, d)
                    for s in ("-wal", "-shm"):
                        if os.path.isfile(p + s):
                            shutil.copy2(p + s, d + s)
                    backed_up += 1
                except OSError as e:
                    warn("Could not back up %s: %s" % (p, e))
    log("  Backup: %d file(s) in %s" % (backed_up, backup))

    # Helium must be closed, otherwise it would overwrite our changes.
    if quit_helium():
        ok("Helium has been closed.")
    else:
        log("  Helium was not running (or skipping is enabled).")

    # --- Keys --------------------------------------------------------------
    cache = cache_load()
    tmpdir = tempfile.mkdtemp(prefix="arc2helium-")
    arc_cols_by_profile = {}
    arc_rows_by_profile = {}
    arc_meta = {}
    try:
        # Arc snapshots (consistent even while Arc is running).
        # All Cookies files of a profile are merged into one canonical
        # v24 database -> no row is lost.
        usable = {}
        for prof, paths in arc_profiles.items():
            groups, metas = [], []
            slug = re.sub(r"\W+", "_", prof)
            for i, p in enumerate(paths):
                snap = os.path.join(tmpdir, "arc_%s_%d.db" % (slug, i))
                try:
                    snapshot_db(p, snap)
                except sqlite3.Error as e:
                    warn("Arc DB %s is not readable: %s" % (p, e))
                    open_privacy_settings()
                    continue
                con = sqlite3.connect(snap)
                c = table_columns(con)
                if "host_key" not in c:
                    con.close()
                    continue
                metas.append(meta_version(con))
                groups.append(canonical_rows(con))
                con.close()
                # 1:1 copy of the unchanged snapshot
                try:
                    shutil.copy2(snap, os.path.join(
                        backup, "Arc", os.path.relpath(p, HOME()) + ".snapshot"))
                except OSError:
                    pass
            if not groups:
                continue
            combined = os.path.join(tmpdir, "src_%s.db" % slug)
            make_combined_snapshot(combined, groups)
            con = sqlite3.connect(combined)
            rows = con.execute("SELECT " + ", ".join(CANON_COLS) +
                               " FROM cookies").fetchall()
            con.close()
            if rows:
                usable[prof] = (combined, rows, max(metas) if metas else 0)
        if not usable:
            raise Fatal("No readable cookies found in any Arc Cookies database.")
        arc_rows_by_profile = {k: v[1] for k, v in usable.items()}
        arc_meta = {k: v[2] for k, v in usable.items()}
        total_arc = sum(len(v) for v in arc_rows_by_profile.values())
        log("  Arc cookies in total: %d (from %d profiles)." %
            (total_arc, len(usable)))

        # Probe connection for key validation
        probe_con = sqlite3.connect(next(iter(usable.values()))[0])
        arc_key = resolve_key(ARC_KEYS, cache.get("arc"), probe_con, "Arc")

        # Determine the source hash convention empirically (more robust than meta version)
        src_hash = None
        if probe_con is not None:
            valid, detected = probe_key(probe_con, arc_key)
            if valid:
                src_hash = detected
        if src_hash is None:
            src_hash = max(arc_meta.values()) >= 24
        try:
            probe_con.close()
        except sqlite3.Error:
            pass
        log("  Arc format: %s" % ("SHA-256 domain prefix (schema >= 24)" if src_hash
                                  else "legacy format"))

        # Helium key: validate against existing Helium cookies
        def find_probe(profiles):
            for paths in profiles.values():
                for p in paths:
                    try:
                        con = sqlite3.connect(ro_uri(p), uri=True, timeout=5)
                        if sample_rows(con):
                            return con
                        con.close()
                    except sqlite3.Error:
                        pass
            return None

        hel_probe = find_probe(helium_profiles)
        helium_key = resolve_key(HELIUM_KEYS, cache.get("helium"),
                                 hel_probe, "Helium")
        if hel_probe is not None:
            hel_probe.close()

        cache["arc"] = arc_key.hex()
        cache["helium"] = helium_key.hex()
        cache_save(cache)

        # --- Migration -----------------------------------------------------
        grand = {"inserted": 0, "failed": 0, "before": 0, "after": 0, "errors": [],
                 "targets": 0}
        for prof in sorted(usable):
            combined, rows, _meta = usable[prof]
            cols = CANON_COLS
            tgt_prof = prof if (prof in helium_profiles or prof == "Default") else "Default"
            existing = helium_profiles.get(tgt_prof, [])
            targets = target_paths_for(helium_root, tgt_prof, existing)
            log("  Profile '%s' -> Helium '%s' (%d cookies, %d target DB(s))" %
                (prof, tgt_prof, len(rows), len(targets)))

            for t in targets:
                os.makedirs(os.path.dirname(t), exist_ok=True)
                is_new = not os.path.isfile(t)
                if is_new:
                    # A newly created DB is always v24 -> add the hash prefix.
                    st = build_clone(combined, arc_key, helium_key,
                                     src_hash, True, t)
                else:
                    st = merge_into_target(t, rows, cols, arc_key,
                                           helium_key, src_hash)
                grand["inserted"] += st["inserted"]
                grand["failed"] += st["failed"]
                grand["before"] += st["before"]
                grand["after"] += st["after"]
                grand["targets"] += 1
                grand["errors"].extend(st["errors"][:4])
                ok("%s : %d written (%d -> %d cookies)%s" %
                   (os.path.relpath(t, helium_root), st["inserted"], st["before"],
                    st["after"], " [created]" if is_new else ""))

        # --- Verification --------------------------------------------------
        verified = 0
        for prof, paths in find_cookie_dbs(helium_root).items():
            for p in paths:
                try:
                    con = sqlite3.connect(ro_uri(p), uri=True, timeout=10)
                    want_hash = meta_version(con) >= 24
                    good, bad = 0, 0
                    for host, blob in sample_rows(con, 25):
                        plain = chromium_decrypt(bytes(blob), helium_key)
                        if plain is None:
                            bad += 1
                        elif want_hash:
                            if plain[:32] == host_hash(host or ""):
                                good += 1
                            else:
                                bad += 1
                        else:
                            good += 1
                    con.close()
                    verified += good
                    if bad:
                        warn("Verification: %d cookie(s) in %s could not be read." % (bad, p))
                except sqlite3.Error:
                    pass
        ok("Verification: %d cookies successfully decrypted "
           "with the Helium key." % verified)

        # --- Report --------------------------------------------------------
        report = [
            "Arc -> Helium Cookie Migration",
            "Date: " + started.strftime("%d.%m.%Y %H:%M:%S"),
            "",
            "Arc profiles        : %d" % len(usable),
            "Arc cookies         : %d" % total_arc,
            "Rows written        : %d" % grand["inserted"],
            "Failed              : %d" % grand["failed"],
            "Target databases    : %d" % grand["targets"],
            "Cookies before      : %d" % grand["before"],
            "Cookies after       : %d" % grand["after"],
            "Verified            : %d" % verified,
            "Keep session cookies   : %s" % ("yes" if FORCE_PERSISTENT else "no"),
            "Backup              : " + backup,
            "",
        ]
        if grand["errors"]:
            report += ["Notes:"] + ["  - " + e for e in grand["errors"]] + [""]
        with open(os.path.join(backup, "REPORT.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(report))

        log("")
        log("  DONE: %d cookie rows transferred, %d errors." %
            (grand["inserted"], grand["failed"]))
        log("  Backup + report: " + backup)
        if grand["failed"]:
            for e in grand["errors"][:6]:
                warn(e)
        relaunch_helium()
        return 0 if grand["inserted"] > 0 else 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        try:
            with open(LOGFILE, "w", encoding="utf-8") as f:
                f.write("\n".join(_LOG) + "\n")
        except OSError:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as e:
        log("")
        log("  ERROR: " + str(e))
        try:
            os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
            with open(LOGFILE, "w", encoding="utf-8") as f:
                f.write("\n".join(_LOG) + "\n")
        except OSError:
            pass
        sys.exit(2)
    except Exception as e:  # unexpected error: report it cleanly
        import traceback
        log("")
        log("  UNEXPECTED ERROR: %s: %s" % (type(e).__name__, e))
        _LOG.append(traceback.format_exc())
        try:
            os.makedirs(SUPPORT, mode=0o700, exist_ok=True)
            with open(LOGFILE, "w", encoding="utf-8") as f:
                f.write("\n".join(_LOG) + "\n")
        except OSError:
            pass
        sys.exit(3)
__ARC2HELIUM_PYTHON_EOF__
    RC=$?
elif [ -x /usr/bin/perl ] && [ -x "${A2H_SQLITE:-/usr/bin/sqlite3}" ]; then
    echo "  Mode: built-in macOS tools (Perl + sqlite3) - no Python needed."
    echo ""
    /usr/bin/perl - <<'__ARC2HELIUM_PERL_EOF__'
#!/usr/bin/perl
# -*- coding: utf-8 -*-
# Arc -> Helium: fallback engine for Macs without Python 3.
# Uses only tools built into macOS:
#   /usr/bin/perl, /usr/bin/sqlite3, /usr/bin/security, /usr/bin/open
# Core modules only (Digest::SHA, JSON::PP, File::Copy, ...).
use strict;
use warnings;
use File::Copy qw(copy);
use File::Path qw(make_path remove_tree);
use File::Basename qw(dirname);
use File::Spec;
use Digest::SHA qw(hmac_sha1 sha256);
use JSON::PP;
use POSIX qw(strftime);
use Time::HiRes qw(sleep);
use Cwd qw(abs_path);

my $VERSION = "1.0-perl";
my @LOG;

sub E { my ($k, $d) = @_; return exists $ENV{"A2H_$k"} ? $ENV{"A2H_$k"} : ($d // ""); }
sub FLAG { my ($k) = @_; my $v = E($k, ""); return $v ne "" && $v ne "0" && lc($v) ne "no" && lc($v) ne "false"; }
sub saylog { my $m = shift // ""; print "$m\n"; push @LOG, $m; }
sub ok   { saylog("  ok  " . shift); }
sub warnl{ saylog("  !   " . shift); }
sub fatal{ die("FATAL: " . shift . "\n"); }

my $HOME = abs_path(E("HOME") || ($ENV{HOME} || "/"));
my $SUPPORT = File::Spec->catdir($HOME, "Library", "Application Support", "ArcToHelium");
my $LOGFILE = File::Spec->catfile($SUPPORT, "last-run.log");
my $CACHEFILE = File::Spec->catfile($SUPPORT, "key-cache.json");
my $KC_SERVICE = "Arc to Helium Migration Keys";
my $KC_ACCOUNT = $ENV{USER} || $ENV{LOGNAME} || getpwuid($<) || "user";
my $SQLITE = E("SQLITE") || "/usr/bin/sqlite3";
my $SECURITY = E("SECURITY") || "/usr/bin/security";
my $OPEN = E("OPEN") || "/usr/bin/open";

my @ARC_ROOTS = (
  File::Spec->catdir($HOME, "Library", "Application Support", "Arc", "User Data"),
  File::Spec->catdir($HOME, "Library", "Application Support", "Arc"),
);
my @HEL_ROOTS = (
  File::Spec->catdir($HOME, "Library", "Application Support", "net.imput.helium"),
  File::Spec->catdir($HOME, "Library", "Application Support", "Helium"),
);
my @ARC_KEYS = (["Arc Safe Storage", "Arc"], ["Chromium Safe Storage", "Chromium"],
                ["Chrome Safe Storage", "Chrome"]);
my @HEL_KEYS = (["Helium Storage Key", "Helium"], ["Helium Safe Storage", "Helium"],
                ["Chromium Safe Storage", "Chromium"]);

my @CANON = qw(creation_utc host_key top_frame_site_key name value encrypted_value
               path expires_utc is_secure is_httponly last_access_utc has_expires
               is_persistent priority samesite source_scheme source_port
               last_update_utc source_type has_cross_site_ancestor);
my %CANON_TYPE = map { $_ => "INTEGER" } @CANON;
for my $c (qw(host_key top_frame_site_key name value path)) { $CANON_TYPE{$c} = "TEXT"; }
$CANON_TYPE{encrypted_value} = "BLOB";
my %DEFAULTS = (
  host_key => "", top_frame_site_key => "", name => "", value => "", path => "/",
  samesite => -1, source_port => -1, source_scheme => 0, source_type => 0,
  has_cross_site_ancestor => 0, priority => 1, has_expires => 1,
  is_persistent => 1, last_update_utc => 0, creation_utc => 0,
  last_access_utc => 0, expires_utc => 0, is_secure => 0, is_httponly => 0,
  encrypted_value => "",
);
my $FORCE_PERSISTENT = (E("FORCE_PERSISTENT", "1") =~ /^(0|no|false)$/i) ? 0 : 1;

# ---------------------------------------------------------------- AES-128 ---
my (@SBOX, @INV);
sub gmul {
  my ($a, $b) = @_; my $p = 0;
  for (1 .. 8) {
    $p ^= $a if $b & 1;
    my $hi = $a & 0x80;
    $a = ($a << 1) & 0xFF;
    $a ^= 0x1B if $hi;
    $b >>= 1;
  }
  return $p & 0xFF;
}
sub gpow {
  my ($a, $n) = @_; my $r = 1;
  while ($n) { $r = gmul($r, $a) if $n & 1; $a = gmul($a, $a); $n >>= 1; }
  return $r;
}
{
  for my $a (0 .. 255) {
    my $inv = $a ? gpow($a, 254) : 0;
    my $s = $inv;
    for my $sh (1 .. 4) { $s ^= (($inv << $sh) | ($inv >> (8 - $sh))) & 0xFF; }
    $s ^= 0x63;
    $SBOX[$a] = $s;
    $INV[$s] = $a;
  }
}
my @RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36);

sub expand_key {
  my ($key) = @_;
  my @b = unpack("C16", $key);
  my @w;
  for my $i (0 .. 3) { $w[$i] = [@b[$i * 4 .. $i * 4 + 3]]; }
  for my $i (4 .. 43) {
    my @t = @{$w[$i - 1]};
    if ($i % 4 == 0) {
      @t = (@t[1 .. 3], $t[0]);
      @t = map { $SBOX[$_] } @t;
      $t[0] ^= $RCON[$i / 4 - 1];
    }
    my @nw;
    for my $j (0 .. 3) { $nw[$j] = $w[$i - 4][$j] ^ $t[$j]; }
    $w[$i] = \@nw;
  }
  my @rk;
  for my $r (0 .. 10) {
    my @x;
    for my $c (0 .. 3) { push @x, @{$w[$r * 4 + $c]}; }
    push @rk, pack("C16", @x);
  }
  return \@rk;
}
sub shift_rows {
  my ($sref, $inverse) = @_; my @s = @$sref; my @o = (0) x 16;
  for my $c (0 .. 3) {
    for my $r (0 .. 3) {
      my $sc = $inverse ? ($c - $r) % 4 : ($c + $r) % 4;
      $o[4 * $c + $r] = $s[4 * $sc + $r];
    }
  }
  return @o;
}
sub mix_columns {
  my ($sref, $inverse) = @_; my @s = @$sref; my @o = (0) x 16;
  for my $c (0 .. 3) {
    my @a = @s[4 * $c .. 4 * $c + 3];
    if ($inverse) {
      $o[4 * $c + 0] = gmul($a[0],14) ^ gmul($a[1],11) ^ gmul($a[2],13) ^ gmul($a[3],9);
      $o[4 * $c + 1] = gmul($a[0],9)  ^ gmul($a[1],14) ^ gmul($a[2],11) ^ gmul($a[3],13);
      $o[4 * $c + 2] = gmul($a[0],13) ^ gmul($a[1],9)  ^ gmul($a[2],14) ^ gmul($a[3],11);
      $o[4 * $c + 3] = gmul($a[0],11) ^ gmul($a[1],13) ^ gmul($a[2],9)  ^ gmul($a[3],14);
    } else {
      $o[4 * $c + 0] = gmul($a[0],2) ^ gmul($a[1],3) ^ $a[2] ^ $a[3];
      $o[4 * $c + 1] = $a[0] ^ gmul($a[1],2) ^ gmul($a[2],3) ^ $a[3];
      $o[4 * $c + 2] = $a[0] ^ $a[1] ^ gmul($a[2],2) ^ gmul($a[3],3);
      $o[4 * $c + 3] = gmul($a[0],3) ^ $a[1] ^ $a[2] ^ gmul($a[3],2);
    }
  }
  return @o;
}
sub xor_rk {
  my ($sref, $rk) = @_; my @s = @$sref; my @k = unpack("C16", $rk);
  my @o; for my $i (0 .. 15) { $o[$i] = $s[$i] ^ $k[$i]; }
  return @o;
}
sub enc_block {
  my ($rk, $blk) = @_;
  my @s = xor_rk([unpack("C16", $blk)], $rk->[0]);
  for my $r (1 .. 10) {
    @s = map { $SBOX[$_] } @s;
    @s = shift_rows(\@s, 0);
    @s = mix_columns(\@s, 0) if $r != 10;
    @s = xor_rk(\@s, $rk->[$r]);
  }
  return pack("C16", @s);
}
sub dec_block {
  my ($rk, $blk) = @_;
  my @s = xor_rk([unpack("C16", $blk)], $rk->[10]);
  for my $r (reverse 0 .. 9) {
    @s = shift_rows(\@s, 1);
    @s = map { $INV[$_] } @s;
    @s = xor_rk(\@s, $rk->[$r]);
    @s = mix_columns(\@s, 1) if $r != 0;
  }
  return pack("C16", @s);
}
my $IV = " " x 16;
sub cbc_encrypt {
  my ($plain, $rk) = @_;
  my $n = 16 - (length($plain) % 16);
  $plain .= chr($n) x $n;
  my ($prev, $out) = ($IV, "");
  for (my $i = 0; $i < length($plain); $i += 16) {
    $prev = enc_block($rk, substr($plain, $i, 16) ^ $prev);
    $out .= $prev;
  }
  return $out;
}
sub cbc_decrypt {
  my ($data, $rk) = @_;
  return undef if length($data) < 16 || length($data) % 16;
  my ($prev, $out) = ($IV, "");
  for (my $i = 0; $i < length($data); $i += 16) {
    my $blk = substr($data, $i, 16);
    $out .= (dec_block($rk, $blk) ^ $prev);
    $prev = $blk;
  }
  my $n = ord(substr($out, -1));
  if ($n >= 1 && $n <= 16 && substr($out, -$n) eq chr($n) x $n) {
    $out = substr($out, 0, length($out) - $n);
  }
  return $out;
}
sub derive_key {
  my ($pw) = @_;
  my $u = hmac_sha1("saltysalt" . pack("N", 1), $pw);
  my $t = $u;
  for (2 .. 1003) { $u = hmac_sha1($u, $pw); $t ^= $u; }
  return substr($t, 0, 16);
}
sub host_hash { return sha256($_[0]); }
sub chromium_decrypt {
  my ($blob, $rk) = @_;
  return undef unless length($blob) > 3 && substr($blob, 0, 3) =~ /^v1[01]$/;
  return cbc_decrypt(substr($blob, 3), $rk);
}
sub chromium_encrypt {
  my ($plain, $rk) = @_;
  return "v10" . cbc_encrypt($plain, $rk);
}

# ------------------------------------------------------------ SQLite helpers ---
sub sq_read {
  my ($db, $sql) = @_;
  my $pid = open(my $fh, "-|", $SQLITE, "-json", $db, $sql);
  return "" unless defined $pid;
  local $/; my $out = <$fh> // "";
  close $fh;
  return $out;
}
sub sq_json {
  my ($db, $sql) = @_;
  my $raw = sq_read($db, $sql);
  return [] unless $raw =~ /\S/;
  my $d = eval { JSON::PP->new->utf8(0)->decode($raw) };
  return ($@ || ref($d) ne "ARRAY") ? [] : $d;
}
sub sq_exec {
  my ($db, $sql) = @_;
  my $pid = open(my $fh, "|-", $SQLITE, $db);
  return 0 unless defined $pid;
  print $fh ".output /dev/null\n" . $sql;
  close $fh;
  return $? == 0 ? 1 : 0;
}
sub sq_scalar {
  my ($db, $sql, $key) = @_;
  my $r = sq_json($db, $sql);
  return undef unless @$r && exists $r->[0]{$key};
  return $r->[0]{$key};
}
sub table_info {
  my ($db) = @_;
  return sq_json($db, "PRAGMA table_info(cookies)");
}
sub meta_version {
  my ($db) = @_;
  my $v = sq_scalar($db, "SELECT value FROM meta WHERE key='version'", "value");
  return (defined $v && $v =~ /^\d+$/) ? 0 + $v : 0;
}
sub count_cookies {
  my ($db) = @_;
  my $v = sq_scalar($db, "SELECT COUNT(*) AS n FROM cookies", "n");
  return defined $v ? 0 + $v : -1;
}
sub hex_sql_select {
  my ($db) = @_;
  my @info = @{table_info($db)};
  my @sel = map { 'hex("' . $_->{name} . '") AS "' . $_->{name} . '"' } @info;
  return @sel ? sq_json($db, "SELECT " . join(",", @sel) . " FROM cookies") : [];
}
sub qhex { return "CAST(X'" . ($_[0] // "") . "' AS TEXT)"; }
sub unhex { return pack("H*", $_[0] // ""); }

# ------------------------------------------------------------------ Keys ---
sub kc_read {
  my ($svc, $acct, $timeout) = @_;
  my $out = "";
  eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm($timeout // 150);
    $out = `$SECURITY find-generic-password -s \Q$svc\E -a \Q$acct\E -w 2>/dev/null`;
    alarm(0);
  };
  alarm(0);
  return undef if $? != 0;
  $out =~ s/[\r\n]+\z//;
  return length($out) ? $out : undef;
}
sub cache_load {
  my $raw = kc_read($KC_SERVICE, $KC_ACCOUNT, 5);
  if (defined $raw) {
    my $d = eval { JSON::PP->new->decode($raw) };
    return $d if !$@ && ref($d) eq "HASH";
  }
  if (open(my $f, "<", $CACHEFILE)) {
    local $/; my $t = <$f>; close $f;
    my $d = eval { JSON::PP->new->decode($t // "") };
    return $d if !$@ && ref($d) eq "HASH";
  }
  return {};
}
sub cache_save {
  my ($d) = @_;
  my $payload = JSON::PP->new->canonical->encode($d);
  system($SECURITY, "add-generic-password", "-U", "-s", $KC_SERVICE,
         "-a", $KC_ACCOUNT, "-w", $payload, "-T", "/usr/bin/security");
  make_path($SUPPORT, { mode => 0700 });
  if (open(my $f, ">", $CACHEFILE)) {
    chmod 0600, $CACHEFILE;
    print $f $payload; close $f;
  }
}
sub probe_rows {
  my ($db) = @_;
  my @info = @{table_info($db)};
  my %have = map { $_->{name} => 1 } @info;
  return () unless $have{host_key} && $have{encrypted_value};
  my @r = @{sq_json($db,
    "SELECT hex(host_key) AS host_key, hex(encrypted_value) AS encrypted_value " .
    "FROM cookies WHERE length(encrypted_value)>3 LIMIT 12")};
  return @r;
}
sub probe_key {
  my ($db, $key) = @_;
  my $rk = expand_key($key);
  my ($yes, $no) = (0, 0);
  for my $r (probe_rows($db)) {
    my $host = unhex($r->{host_key});
    my $plain = chromium_decrypt(unhex($r->{encrypted_value}), $rk);
    next unless defined $plain;
    if (length($plain) >= 32 && substr($plain, 0, 32) eq host_hash($host)) { $yes++ }
    else {
      my $s = substr($plain, 0, 64);
      my $good = () = ($s =~ /[\x20-\x7E\t\n\r]/g);
      $no++ if !length($s) || $good / length($s) > 0.85;
    }
  }
  return (0, undef) if !$yes && !$no;
  return (1, $yes >= $no ? 1 : 0);
}
sub resolve_key {
  my ($cands, $cached_hex, $probe_db, $label) = @_;
  if ($cached_hex && $cached_hex =~ /^[0-9a-fA-F]{32}$/) {
    my $key = pack("H*", $cached_hex);
    if ($probe_db) {
      my ($valid) = probe_key($probe_db, $key);
      if ($valid) { ok("$label key from cache (no prompt needed)."); return $key; }
    } else {
      # No probe cookies: briefly confirm the key against the Keychain.
      for my $c (@$cands) {
        my $pw = kc_read($c->[0], $c->[1], 8);
        if (defined $pw) {
          ok("$label key confirmed from the Keychain.");
          return derive_key($pw);
        }
      }
      ok("$label key from cache.");
      return $key;
    }
  }
  saylog("  Reading $label key from the macOS Keychain ...");
  saylog("    (If macOS asks once: please click 'Always Allow'.)");
  for my $c (@$cands) {
    my $pw = kc_read($c->[0], $c->[1], 150);
    next unless defined $pw;
    my $key = derive_key($pw);
    if ($probe_db) {
      my ($valid) = probe_key($probe_db, $key);
      if (!$valid) { warnl("Keychain entry '$c->[0]' does not match - trying the next one."); next; }
    }
    ok("$label key found ($c->[0] / $c->[1]).");
    return $key;
  }
  fatal("Could not read the $label key. Please start $label once "
      . "and double-click this program again.");
}

# ------------------------------------------------------------- Path lookup ---
sub first_existing { for my $r (@_) { return $r if -d $r; } return undef; }
sub find_dbs {
  my ($root) = @_;
  my %out;
  return %out unless $root && -d $root;
  opendir(my $dh, $root) or fatal("Cannot read $root. Please give Terminal "
    . "'Full Disk Access' once in System Settings > Privacy & Security.");
  my @entries = sort readdir($dh); closedir $dh;
  for my $name (@entries) {
    next if $name =~ /^\./;
    my $p = File::Spec->catdir($root, $name);
    next unless -d $p;
    my @f;
    for my $rel ("Network/Cookies", "Cookies") {
      my $f = File::Spec->catfile($p, split m{/}, $rel);
      push @f, $f if -f $f && -s $f >= 512;
    }
    for my $f (glob(File::Spec->catfile($p, "*", "Cookies"))) {
      push @f, $f if -f $f && !grep { $_ eq $f } @f;
    }
    $out{$name} = \@f if @f;
  }
  return %out;
}
sub target_paths {
  my ($root, $prof, $existing) = @_;
  return @$existing if $existing && @$existing;
  return (File::Spec->catfile($root, $prof, "Network", "Cookies"),
          File::Spec->catfile($root, $prof, "Cookies"));
}
sub v24_ddl {
  my @parts;
  for my $c (@CANON) { push @parts, '"' . $c . '" ' . $CANON_TYPE{$c} . ' NOT NULL'; }
  return
    "CREATE TABLE meta(key TEXT NOT NULL UNIQUE PRIMARY KEY, value TEXT);\n" .
    "INSERT INTO meta VALUES('version','24');\n" .
    "INSERT INTO meta VALUES('last_compatible_version','24');\n" .
    "CREATE TABLE cookies(" . join(",", @parts) . ");\n" .
    "CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key," .
    "top_frame_site_key,has_cross_site_ancestor,name,path,source_scheme,source_port);\n";
}

# ------------------------------------------------------------ Transformation ---
sub transform_payload {
  my ($enc_hex, $value_hex, $host, $arc_rk, $hel_rk, $src_hash, $dst_hash) = @_;
  my $value_bytes;
  if (length($enc_hex // "") > 6) {
    my $plain = chromium_decrypt(unhex($enc_hex), $arc_rk);
    return (undef, "decryption failed") unless defined $plain;
    if ($src_hash) {
      return (undef, "hash prefix missing") unless
        length($plain) >= 32 && substr($plain, 0, 32) eq host_hash($host);
      $value_bytes = substr($plain, 32);
    } else { $value_bytes = $plain; }
  } else {
    $value_bytes = unhex($value_hex);
  }
  my $payload = ($dst_hash ? host_hash($host) : "") . $value_bytes;
  return (unpack("H*", chromium_encrypt($payload, $hel_rk)), undef);
}

sub build_sql_for {
  my ($rows, $src_cols, $target_db, $arc_rk, $hel_rk, $src_hash) = @_;
  my @info = @{table_info($target_db)};
  my %tcols = map { $_->{name} => 1 } @info;
  my @common = grep { $tcols{$_} } @$src_cols;
  push @common, "encrypted_value" if $tcols{encrypted_value} && !grep { $_ eq "encrypted_value" } @common;
  my @extra;
  for my $i (@info) {
    next if $tcols{$i->{name}} && grep { $_ eq $i->{name} } @common;
    next if $i->{pk};
    push @extra, $i->{name} if $i->{notnull} && !defined $i->{dflt_value};
  }
  my @all = (@common, @extra);
  my $dst_hash = meta_version($target_db) >= 24;
  my $sql = "PRAGMA journal_mode=DELETE;\nBEGIN;\n";
  my $cols = join(",", map { '"' . $_ . '"' } @all);
  my ($ins, $fail) = (0, 0);
  for my $r (@$rows) {
    my $host = unhex($r->{host_key} // "");
    my ($new_hex, $err) = transform_payload(
      $r->{encrypted_value}, $r->{value}, $host, $arc_rk, $hel_rk,
      $src_hash, $dst_hash);
    if ($err) { $fail++; next; }
    my @vals;
    for my $c (@all) {
      if ($c eq "encrypted_value") { push @vals, "X'" . $new_hex . "'"; }
      elsif ($c eq "value") { push @vals, qhex(""); }
      elsif ($c eq "is_persistent" && $FORCE_PERSISTENT) { push @vals, qhex(unpack("H*", "1")); }
      elsif (exists $r->{$c}) { push @vals, qhex($r->{$c}); }
      else { push @vals, qhex(unpack("H*", "" . ($DEFAULTS{$c} // 0))); }
    }
    $sql .= "INSERT OR REPLACE INTO cookies($cols) VALUES(" . join(",", @vals) . ");\n";
    $ins++;
  }
  $sql .= "COMMIT;\n";
  return ($sql, $ins, $fail);
}

sub build_new_db_sql {
  my ($rows, $arc_rk, $hel_rk, $src_hash) = @_;
  my $sql = v24_ddl() . "BEGIN;\n";
  my $cols = join(",", @CANON);
  my ($ins, $fail) = (0, 0);
  for my $r (@$rows) {
    my $host = unhex($r->{host_key} // "");
    my ($new_hex, $err) = transform_payload(
      $r->{encrypted_value}, $r->{value}, $host, $arc_rk, $hel_rk,
      $src_hash, 1);
    if ($err) { $fail++; next; }
    my @vals;
    for my $c (@CANON) {
      if ($c eq "encrypted_value") { push @vals, "X'" . $new_hex . "'"; }
      elsif ($c eq "value") { push @vals, qhex(""); }
      elsif ($c eq "is_persistent" && $FORCE_PERSISTENT) { push @vals, qhex(unpack("H*", "1")); }
      elsif (exists $r->{$c}) { push @vals, qhex($r->{$c}); }
      else { push @vals, qhex(unpack("H*", "" . ($DEFAULTS{$c} // 0))); }
    }
    $sql .= "INSERT OR REPLACE INTO cookies($cols) VALUES(" . join(",", @vals) . ");\n";
    $ins++;
  }
  $sql .= "COMMIT;\n";
  return ($sql, $ins, $fail);
}

# ------------------------------------------------------------------- Main ---
sub main {
  make_path($SUPPORT, { mode => 0700 });
  my $stamp = strftime("%Y-%m-%d_%H-%M-%S", localtime);
  saylog("=" x 66);
  saylog("  ARC  ->  HELIUM   |   Cookie Migration v$VERSION (Perl mode)");
  saylog("  " . strftime("%d.%m.%Y  %H:%M:%S", localtime));
  saylog("=" x 66);

  fatal("This program only runs on macOS.") unless FLAG("ALLOW_NON_MAC") || $^O eq "darwin";
  for my $bin ($SQLITE, $SECURITY) {
    fatal("Required macOS tool missing: $bin") unless -x $bin;
  }

  my $arc = E("ARC_ROOT") || first_existing(@ARC_ROOTS);
  my $hel = E("HELIUM_ROOT") || first_existing(@HEL_ROOTS);
  fatal("Arc profile folder not found.") unless $arc;
  unless ($hel) { $hel = $HEL_ROOTS[0]; make_path($hel); ok("Created Helium profile folder."); }
  saylog("  Arc    : $arc");
  saylog("  Helium : $hel");

  my %arcp = find_dbs($arc);
  my %help = find_dbs($hel);
  fatal("No Arc Cookies database found.") unless keys %arcp;
  saylog("  Found: " . scalar(keys %arcp) . " Arc profile(s), " .
         scalar(keys %help) . " Helium profile(s).");

  my $backup = File::Spec->catdir($SUPPORT, "Backups", $stamp);
  make_path($backup);
  my $backed = 0;
  for my $pair (["Arc", \%arcp], ["Helium-before", \%help]) {
    for my $prof (keys %{$pair->[1]}) {
      for my $p (@{$pair->[1]{$prof}}) {
        my $rel = File::Spec->abs2rel($p, $HOME);
        my $d = File::Spec->catfile($backup, $pair->[0], $rel);
        make_path(dirname($d));
        if (copy($p, $d)) {
          $backed++;
          for my $s ("-wal", "-shm") { copy($p . $s, $d . $s) if -f $p . $s; }
        }
      }
    }
  }
  saylog("  Backup: $backed file(s) in $backup");

  unless (FLAG("SKIP_QUIT")) {
    my @pids;
    for my $line (`/bin/ps -axww -o pid=,command= 2>/dev/null`) {
      my ($pid, $cmd) = $line =~ /^\s*(\d+)\s+(.*)$/ or next;
      next if $pid == $$;
      my $l = lc($cmd);
      push @pids, $pid if index($l, "helium.app/contents/macos/") >= 0;
    }
    if (@pids) {
      saylog("  Quitting Helium ...");
      kill 15, @pids;
      for (1 .. 20) { my @a = grep { kill 0, $_ } @pids; last unless @a; @pids = @a; sleep 0.3; }
      kill 9, @pids if @pids;
    }
  }

  my $cache = cache_load();
  my $tmp = File::Spec->catdir($ENV{TMPDIR} || "/tmp", "arc2helium-pl-" . $$);
  make_path($tmp);

  # Arc snapshots: copy DB + WAL; SQLite replays the WAL when opening
  my (%usable, %arcmeta);
  for my $prof (sort keys %arcp) {
    my (@groups, @metas);
    my $i = 0;
    for my $p (@{$arcp{$prof}}) {
      my $snap = File::Spec->catfile($tmp, "arc_" . $i++ . ".db");
      copy($p, $snap) or next;
      for my $s ("-wal", "-shm") { copy($p . $s, $snap . $s) if -f $p . $s; }
      my @info = @{table_info($snap)};
      next unless grep { $_->{name} eq "host_key" } @info;
      push @metas, meta_version($snap);
      push @groups, hex_sql_select($snap);
      my $rel = File::Spec->abs2rel($p, $HOME) . ".snapshot";
      my $d = File::Spec->catfile($backup, "Arc", $rel);
      make_path(dirname($d)); copy($snap, $d);
    }
    next unless @groups;
    my @rows;
    for my $g (@groups) { push @rows, @$g; }
    next unless @rows;
    $usable{$prof} = \@rows;
    my $m = 0; for (@metas) { $m = $_ if $_ > $m; }
    $arcmeta{$prof} = $m;
  }
  fatal("No readable cookies found in any Arc Cookies database.") unless keys %usable;
  my $total = 0; $total += scalar(@{$usable{$_}}) for keys %usable;
  saylog("  Arc cookies in total: $total (from " . scalar(keys %usable) . " profiles).");

  my $probe = File::Spec->catfile($tmp, "probe.db");
  copy($arcp{(sort keys %arcp)[0]}[0], $probe) or fatal("Arc snapshot failed.");
  my $arc_key = resolve_key(\@ARC_KEYS, $cache->{arc}, $probe, "Arc");
  my $arc_rk = expand_key($arc_key);
  my ($valid, $detected) = probe_key($probe, $arc_key);
  my $src_hash = $valid ? $detected : 0;
  my $maxmeta = 0; for (values %arcmeta) { $maxmeta = $_ if $_ > $maxmeta; }
  $src_hash = ($maxmeta >= 24) unless $valid;
  saylog("  Arc format: " . ($src_hash ? "SHA-256 domain prefix (schema >= 24)"
                                     : "legacy format"));

  my $hel_probe;
  for my $prof (keys %help) {
    for my $p (@{$help{$prof}}) { $hel_probe = $p if scalar(probe_rows($p)); last if $hel_probe; }
    last if $hel_probe;
  }
  my $hel_key = resolve_key(\@HEL_KEYS, $cache->{helium}, $hel_probe, "Helium");
  my $hel_rk = expand_key($hel_key);
  $cache->{arc} = unpack("H*", $arc_key);
  $cache->{helium} = unpack("H*", $hel_key);
  cache_save($cache);

  my ($ins, $fail, $before, $after, $targets) = (0, 0, 0, 0, 0);
  for my $prof (sort keys %usable) {
    my $rows = $usable{$prof};
    my $tgt = (exists $help{$prof} || $prof eq "Default") ? $prof : "Default";
    my @paths = target_paths($hel, $tgt, $help{$tgt});
    saylog("  Profile '$prof' -> Helium '$tgt' (" . scalar(@$rows) .
           " Cookies, " . scalar(@paths) . " target DB(s))");
    for my $t (@paths) {
      make_path(dirname($t));
      my $is_new = !-f $t;
      my ($sql, $n, $f);
      if ($is_new) {
        ($sql, $n, $f) = build_new_db_sql($rows, $arc_rk, $hel_rk, $src_hash);
        unlink $t if -f $t;
      } else {
        $before += count_cookies($t);
        ($sql, $n, $f) = build_sql_for($rows, \@CANON, $t, $arc_rk, $hel_rk, $src_hash);
      }
      sq_exec($t, $sql) or warnl("sqlite3 reported an error for $t");
      $after += count_cookies($t);
      $ins += $n; $fail += $f; $targets++;
      ok(File::Spec->abs2rel($t, $hel) . " : $n written" . ($is_new ? " [created]" : ""));
      # remove orphaned WAL files
      for my $s ("-wal", "-shm") { unlink($t . $s) if -f $t . $s && -s $t . $s < 65536; }
    }
  }

  # Verification
  my $verified = 0;
  my %now = find_dbs($hel);
  for my $prof (keys %now) {
    for my $p (@{$now{$prof}}) {
      my $want = meta_version($p) >= 24;
      for my $r (probe_rows($p)) {
        my $plain = chromium_decrypt(unhex($r->{encrypted_value}), $hel_rk);
        next unless defined $plain;
        next if $want && !(length($plain) >= 32 &&
                           substr($plain, 0, 32) eq host_hash(unhex($r->{host_key})));
        $verified++;
      }
    }
  }
  ok("Verification: $verified cookies decrypted with the Helium key.");

  my @report = ("Arc -> Helium Cookie Migration (Perl mode)",
    "Date: " . strftime("%d.%m.%Y %H:%M:%S", localtime), "",
    "Arc profiles         : " . scalar(keys %usable),
    "Arc cookies          : $total",
    "Rows written         : $ins",
    "Failed               : $fail",
    "Target databases     : $targets",
    "Cookies before       : $before",
    "Cookies after        : $after",
    "Verified             : $verified",
    "Backup               : $backup", "");
  if (open(my $f, ">", File::Spec->catfile($backup, "REPORT.txt"))) {
    print $f join("\n", @report); close $f;
  }
  saylog("");
  saylog("  DONE: $ins cookie rows transferred, $fail errors.");
  saylog("  Backup + report: $backup");
  unless (FLAG("SKIP_RELAUNCH")) {
    my $r = system($OPEN, "-b", "net.imput.helium");
    system($OPEN, "-a", "Helium") if $r != 0;
    ok("Helium is being reopened.");
  }
  remove_tree($tmp);
  return $ins > 0 ? 0 : 1;
}

my $rc = eval { main() };
if ($@) {
  saylog("");
  saylog("  ERROR: " . ($@ =~ s/^FATAL: //r));
  push @LOG, $@;
  $rc = 2;
}
make_path($SUPPORT, { mode => 0700 });
if (open(my $f, ">", $LOGFILE)) { print $f join("\n", @LOG) . "\n"; close $f; }
exit($rc // 0);
__ARC2HELIUM_PERL_EOF__
    RC=$?
else
    echo "  ERROR: Neither Python 3 nor the built-in macOS tools Perl/sqlite3"
    echo "  are available. This should not happen on a normal Mac."
    RC=2
fi

echo ""
echo "  Log     : ~/Library/Application Support/ArcToHelium/last-run.log"
echo "  Backups : ~/Library/Application Support/ArcToHelium/Backups/"
echo ""
if [ "$RC" -eq 0 ]; then
    echo "  Done. Helium has been reopened - you are still signed in everywhere."
else
    echo "  Something went wrong - details are in the log and above in this window."
fi
sleep "${A2H_SLEEP:-4}"
exit "$RC"
