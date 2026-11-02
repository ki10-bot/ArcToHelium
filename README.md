# Arc → Helium Cookie Migrator

Move **all** of your cookies from the [Arc Browser](https://arc.net/) to
[Helium Browser](https://helium.computer/) on macOS — one-to-one, with nothing
lost. Download, unzip, double-click one file. No typing, no configuration, no
installation.

> Unofficial tool. It is not affiliated with or endorsed by The Browser
> Company or the Helium project. It reads your local cookie databases and
> never sends anything anywhere.

---

## Why this exists

Helium has a built-in "Import from Arc" feature, but it can skip cookies
(session cookies, expired rows, unusual profiles, multiple `Cookies` files).
This tool does **not** use the importer. It works directly on the SQLite
`Cookies` databases.

Copying Arc's `Cookies` file into Helium does not work either: both browsers
are Chromium-based, but they use **different macOS Keychain secrets**. Helium
cannot decrypt Arc's `v10` values. This tool therefore:

1. reads Arc's encryption key from the macOS Keychain,
2. decrypts every cookie value with it,
3. re-encrypts every value with Helium's Keychain key,
4. writes the rows into Helium's own database (or creates a fresh v24 one),
5. verifies by decrypting sample rows with Helium's key.

## What is preserved

| | |
|---|---|
| Profiles | Every Arc profile is scanned; `Default` and `Profile 1`, `Profile 2`, … are all handled |
| Rows | **Every** row from **every** `Cookies` / `Network/Cookies` file, including several files in the same profile |
| Session & expired cookies | No filtering by expiry, host, name or `is_persistent` |
| Fields | `creation_utc`, `host_key`, `top_frame_site_key`, `name`, `path`, `expires_utc`, `is_secure`, `is_httponly`, `last_access_utc`, `has_expires`, `is_persistent`, `priority`, `samesite`, `source_scheme`, `source_port`, `last_update_utc`, `source_type`, `has_cross_site_ancestor` |
| Schema | Handles Chromium cookie schema v23 (legacy) and v24 (`SHA-256(host_key)` prefix), plus older/unversioned files |
| Your existing Helium cookies | Merged, not deleted |

Arc itself is **never modified** and is **never quit**. Helium is closed
automatically during the write and reopened afterwards.

Session cookies (`is_persistent = 0`) are marked as persistent on write,
because Chromium otherwise drops them at the next launch. This is the only
intentional change to a field, and it exists so that nothing is lost.

---

## Quick start

1. Download the ZIP from the Releases page (or clone this repository).
2. Unzip it.
3. **Double-click `ArcToHelium.command`.**
4. A Terminal window opens, does everything automatically, and closes after a
   few seconds. You do not need to type anything.

If macOS says the file is from an unidentified developer, right-click the
file and choose **Open → Open** once. Alternatively, in Terminal:

```
xattr -d com.apple.quarantine ArcToHelium.command
```

### One-time macOS permissions

The program itself needs **zero input**, but macOS may ask for two one-time
approvals. These are operating-system security dialogs and cannot be bypassed
with `sudo` or `chmod`:

| Dialog | What to do |
|---|---|
| **Terminal / iTerm needs Full Disk Access** | System Settings → Privacy & Security → Full Disk Access → enable Terminal (or iTerm). Quit and reopen Terminal, then double-click again. |
| **`security` wants to access the keychain** | Click **Always Allow**. On macOS 15+ the prompt may reappear a few times because of the Keychain partition list; clicking *Always Allow* each time makes subsequent runs silent. |

Both are needed because browser cookie databases live inside
`~/Library/Application Support`, which is protected by TCC, and because the
encryption keys live in the Keychain.

Both Arc and Helium must have been launched at least once, so that their
Keychain entries and profile folders exist.

---

## What happens on a run

```
==================================================================
  ARC  ->  HELIUM   |   Cookie Migration
  Fully automatic - please do not type anything.
==================================================================
  Mode: Python 3 (/opt/homebrew/bin/python3)
  ...
  DONE: 1234 cookie rows transferred, 0 errors.
```

1. Helium is quit (via `ps` + signal — no Apple Events, so no extra permission prompt).
2. A **full backup** of every affected Helium `Cookies`, `Cookies-wal` and
   `Cookies-shm` file is written before anything is changed.
3. Arc's databases are copied read-only (WAL replayed via SQLite's backup API),
   so Arc can stay open.
4. Rows are decrypted and re-encrypted, then merged or cloned into Helium.
5. Sample rows are decrypted with Helium's key to confirm success.
6. A report is written and Helium is reopened.

### Where to find things

All generated data stays on your Mac, under
`~/Library/Application Support/ArcToHelium/`:

| Path | Contents |
|---|---|
| `Backups/<timestamp>/` | Exact 1:1 copies of the Helium databases before the run |
| `Backups/<timestamp>/REPORT.txt` | Counts, verification result, any warnings |
| `last-run.log` | Full log of the last run (never contains cookie values or keys) |
| `key-cache.json` | Optional local cache of the two Keychain keys, mode `0600` |

## Emergency: undo the migration

Double-click **`Restore-Backup.command`**. It automatically picks the newest
backup, quits Helium, restores the databases (and removes stale WAL/SHM files
so Helium cannot replay the migrated state), and tells you what it restored.
Open Helium again afterwards.

---

## Two engines, one file

`ArcToHelium.command` is a single self-contained bash script with **both**
implementations embedded. It picks the best one automatically:

| Engine | Requirements | Notes |
|---|---|---|
| Python 3 | Any Python ≥ 3.7 with the standard library | Pure-Python AES-128-CBC and PBKDF2; no `pip`, no OpenSSL CLI |
| Perl + `sqlite3` | `/usr/bin/perl`, `/usr/bin/sqlite3` — both built into macOS | Core modules only |

The launcher checks `xcode-select -p` **without executing** `/usr/bin/python3`,
because on a Mac without Xcode Command Line Tools that binary is a stub that
opens an "install developer tools" dialog. If no usable Python exists, it
silently falls back to the Perl engine. No installation is ever required.

Environment overrides exist for testing only; normal use needs none of them:
`A2H_HOME`, `A2H_ALLOW_NON_MAC`, `A2H_SKIP_QUIT`, `A2H_SKIP_RELAUNCH`,
`A2H_SECURITY`, `A2H_OPEN`, `A2H_SQLITE`, `A2H_ARC_ROOT`, `A2H_HELIUM_ROOT`,
`A2H_FORCE_PERSISTENT`, `A2H_PYTHON`, `A2H_FORCE_PERL`, `A2H_SLEEP`.

---

## Repository layout

```
ArcToHelium.command          built, double-clickable program (committed)
Restore-Backup.command       double-clickable undo (committed)
README.md                    this file
LICENSE                      MIT
.gitignore
src/
  engine.py                  Python engine (also runnable standalone)
  fallback.pl                Perl/sqlite3 engine
  launcher.sh                template for the .command file
  build.py                   rebuilds ArcToHelium.command from the three sources
  tests/
    harness.py               7 scenarios x 2 engines (schema v23/v24, missing DB, multi-DB, plaintext)
    test_command.py          tests the built .command in Python and Perl mode
```

Rebuild and test:

```
python3 src/build.py                 # regenerates ./ArcToHelium.command
python3 src/tests/harness.py         # ALL TESTS PASSED (both engines)
python3 src/tests/test_command.py    # .command PASSED IN BOTH MODES
```

The tests use synthetic, throwaway databases and a fake `security` command;
they never touch your real browser profile. On macOS, `/usr/bin/sqlite3` is
used automatically.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Arc profile folder not found` | Launch Arc once. Check that it is installed in the normal location. |
| `No Arc Cookies database found` | Launch Arc and visit a site once. Grant Terminal Full Disk Access. |
| `Could not read the Arc key` | Click **Always Allow** in the Keychain dialog, or start Arc once and retry. |
| `Could not read the Helium key` | Launch Helium once, then retry. |
| `ERROR: Neither Python 3 nor ... Perl/sqlite3` | Extremely unusual — both ship with macOS. Check System Integrity Protection / a managed Mac. |
| Helium asks you to sign in again | Open the newest backup folder, then run `Restore-Backup.command`. |
| Window closes immediately | Read `~/Library/Application Support/ArcToHelium/last-run.log`. |

## Privacy & security

- No network access, no telemetry, no analytics, no dependencies to download.
- Cookie values and Keychain passwords are never written to the log, the
  report, or the terminal.
- Keys are read from the macOS Keychain. On later runs a Keychain item created
  with `-T /usr/bin/security` (or a `0600` JSON cache) avoids repeat prompts.
- All writes happen locally under your own user account.
- A complete backup is taken before any change, and the restore tool is included.

## Limitations / notes for contributors

- Verification currently samples up to 25 decryptable rows per target database
  and checks that every migrated row was written without error; it does not
  byte-compare every non-value column against the destination.
- The `SHA-256(host_key)` convention is detected once per run from a probe
  connection. Mixed-schema `Cookies` files inside a single Arc profile are
  unusual, but a per-row prefix check would be more robust.
- Destination writes are in-place (after a backup) rather than staged via
  copy + atomic rename.
- Unrecognised `vXX` prefixes are reported as errors, never silently dropped.
- This is a local convenience tool, not a supported migration path of either
  browser. Keep the backup folder until you are sure everything works.

## License

MIT — see [LICENSE](LICENSE).
