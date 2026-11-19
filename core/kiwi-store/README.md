# kiwi-store

The PC-side durable storage engine of Kiwi Transfer.

It receives files from a paired phone, writes them to a destination folder,
proves to itself that they are really on the disk, and keeps a ledger of what
it stored. The phone is allowed to delete its own copy of a photo only on the
strength of what this crate reports. So the crate is built to say **no**
whenever it is not sure.

No networking, no user interface. The transfer layer calls this crate.

Windows is the real target. The crate also builds and runs its tests on Linux
(for CI), with weaker platform primitives; see [Platforms](#platforms).

## The guarantees, in plain words

### When `IncomingFile::finish` returns `Ok`

1. Every byte the sender sent was written to a temp file **in the same folder**
   as the final file, and hashed (BLAKE3) as it arrived.
2. The number of bytes equals the size the sender announced.
3. The temp file was flushed to the device (`FlushFileBuffers`).
4. The file was then **read back from the device** with the operating system's
   cache bypassed (`FILE_FLAG_NO_BUFFERING`, aligned buffer) and hashed again.
5. Three hashes are equal: the hash of what arrived, the hash of what the disk
   gave back, and the hash the sender claims.
6. Only after that did the file get its final name, by a rename that **cannot
   replace anything** and is written through (`MoveFileExW` with
   `MOVEFILE_WRITE_THROUGH`, without `MOVEFILE_REPLACE_EXISTING`).
7. The ledger has a durable record of the file (SQLite, WAL,
   `synchronous=FULL`).

If any step fails, the temp file is deleted, nothing is recorded, and a typed
error says which step it was.

### Always, whatever goes wrong

* **Nothing is ever overwritten.** If the name is taken, the file becomes
  `name (2).ext`, `name (3).ext`, and so on. Names that differ only in case or
  in Unicode normalisation count as the same name.
* **The only files the engine deletes are its own temp files**
  (`.kiwi-tmp-*.part`), and never one that belongs to a transfer in progress.
* **A file never has its final name before it has been verified.** A crash can
  leave a temp file behind (removed at the next start), never a half-written
  photo under a real name.
* **Nothing is written outside the destination root.** Peer-supplied names are
  sanitised; `..`, absolute paths, drive letters, UNC and device paths are
  refused outright.
* **Junctions and symbolic links are never followed** anywhere between the
  root and a file: not when writing, not when verifying, not when cleaning up.
  Besides checking every directory on the way, the engine asks the operating
  system where a freshly created temp file and a freshly verified file really
  are, and refuses if that is not exactly where it expected.
* **The ledger is never believed on its own.** Every "yes" this crate gives
  comes from reading the file back from disk and hashing it. A damaged,
  truncated, replaced or edited ledger can make the engine say "no"; it cannot
  make it say "yes".

### When `verify_for_deletion(hash, min_age_sessions)` returns `Ok`

All of these were true at the moment it returned:

1. The destination, examined again right then, is a **fixed internal disk with
   NTFS or ReFS**, and it is the same volume the store was opened on.
2. Final move is **not blocked** (see below).
3. The clock does not read earlier than a time already recorded in the ledger.
4. A file with exactly this BLAKE3 hash was committed in an **earlier
   session**: at least `min_age_sessions` sessions ago (never fewer than one)
   by the session counter, before the current session began by event sequence
   number, **and** at least 24 hours ago by the clock. All three must hold.
   Restarting the program many times does not help without the 24 hours;
   changing the clock does not help without a later session.
5. That file was read from the device again, in full, with an **unbuffered**
   read, just now, and its hash matched.
6. The ledger durably recorded that this verification took place.

Anything else is a denial with a typed reason: copy-only destination, blocked,
too recent, no record, file missing, file changed, file unreadable, a junction
in the way, cloud placeholder, cached read only, clock went backwards, ledger
damaged. A denial changes nothing on disk.

### What blocks final move

A persistent flag in the ledger. Once set, `verify_for_deletion` denies
everything until `clear_final_move_block` is called explicitly; a restart does
not clear it, and neither does a clean scan. It is set when

* a stored file is found **changed** (always) or **missing** (by default);
* a junction or link is found on the way to a stored file;
* many files changed, vanished or were renamed together (**mass change**: what
  ransomware, a failing disk or a bad sync tool look like);
* the ledger was damaged and reset, or is empty although the folder was used
  before, or the folder lost its identity marker;
* the application calls `block_final_move`.

Clearing the flag vouches for nothing: every later confirmation still re-reads
its file. A problem that was already known does not set the flag again.

## What is *not* guaranteed

Read this part twice.

* **Hardware that lies about flushes.** `FlushFileBuffers` asks the drive to
  empty its write cache. Some drives, USB bridges and RAID controllers
  acknowledge and do nothing. The unbuffered read-back bypasses the operating
  system's cache, **not the drive's own**. This is the main reason a deletion
  is confirmed only after a later session and 24 hours: by then the data has
  had to survive on the medium, not in a cache. A drive that returns stale or
  wrong data consistently cannot be detected from here.
* **Malware or anyone else acting as the user.** A program running with the
  user's rights can change files and the ledger, replace this program, or
  answer the phone itself. The checks here detect *damage* (and say no); they
  are not a defence against an adversary on the PC. In particular, between a
  successful `verify_for_deletion` and the phone actually deleting, the PC is
  not frozen.
* **The future.** `Ok` describes the moment it was returned. Disks die a
  minute later. One copy on one disk is not a backup.
* **Clocks.** The 24-hour rule uses the system clock. A clock set forward
  shortens the wait; the session rule then is the only delay. A clock that
  reads earlier than a time already in the ledger is detected and denies. If
  the clock was once ahead and files were stored then, that denial lasts until
  real time catches up or a person calls `acknowledge_clock_change`, which
  accepts the present reading as correct and makes the affected files age
  again from now.
* **A "session" is one `Store::open`**, not a reboot. Two opens a day apart
  satisfy the rule without the machine ever having been power-cycled.
* **Network shares, USB disks, memory cards, FAT/exFAT, virtual disks, and any
  disk the engine cannot identify** are copy-only. Files are stored and
  verified there with the same pipeline, but a deletion is never confirmed.
  A disk flagged hot-pluggable (eSATA, hot-swap bays, and internal ports with
  hot plug enabled in firmware) is treated as external.
* **Cloud-synced folders.** A file that became an online-only placeholder is
  reported as not verified, but the engine does not try to recognise sync
  roots in general.
* **Bit rot between scans.** A file is known to be intact when it was last
  read. Run the integrity scan.
* **Windows short (8.3) names and hard links** made by other programs inside
  the root are not policed beyond what the checks above catch. A peer-supplied
  short name that aliases another folder is refused.
* **Non-Windows platforms** never confirm a deletion. See below.

## Name safety

Peer-supplied names go through `sanitize_rel_path`:

| Input | Result |
|---|---|
| empty, NUL inside | refused |
| `/abs`, `\abs`, `C:\x`, `C:x`, `\\server\share`, `\\?\`, `\\.\` | refused |
| any `..` component; components of only dots/blanks (`.. `, `...`, ` `) | refused |
| `< > : " \| ? *`, control characters | replaced by `_` (this removes the `:` of alternate data streams) |
| bidirectional overrides, zero-width space, BOM | replaced by `_` |
| trailing dots and spaces | removed |
| `CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, `CONIN$`, `CONOUT$`, `CLOCK$` (any case, with or without extension) | prefixed with `_` |
| names starting with `.kiwi-` (the engine's own) | prefixed with `_` |
| any Unicode | normalised to NFC |
| components longer than 240 UTF-16 units | shortened, extension kept |
| more than 64 levels | refused |

Paths are built under a `\\?\` root, so paths far beyond 260 characters work
and Windows applies no normalisation of its own. Every path read back from the
ledger must sanitise to itself, or it is not used.

## Organisation templates

`StoreConfig::layout` is a `Template`. Tokens: `{year}`, `{month}`, `{day}`
(from the capture time supplied by the caller, else the modification time,
else the single folder `undated`), `{device}` (the device's folder),
`{phone_dir}` (the folders the file was in on the phone). Presets:
`Template::by_date()` = `{year}/{month}`, `Template::per_device()` =
`{device}`, `Template::keep_phone_structure()` = `{device}/{phone_dir}`.
There are no conditionals and no way to name a parent directory; every
rendered segment passes through the sanitiser again.

## API summary

```rust
// Opening
Store::open(StoreConfig::new(root, ledger_dir)) -> Result<Store, StoreError>
Store::reset_corrupt_ledger(cfg)                -> Result<Store, StoreError>   // damaged ledger: move aside, start empty, block
store.destination() -> &Destination             // .supports_final_move(), .final_move_support(), .free_space(), .volume()
store.session() -> u64                          // +1 on every open
store.open_notes() -> &[OpenNote]               // NewDestination, LedgerLost, LedgerReset, MarkerRecreated
store.recovery_report() / store.run_recovery(&cancel)

// Devices and quotas
DeviceId::new("...")                            // A-Z a-z 0-9 . _ -  (1..=128)
store.register_device(&id, display_name, DeviceLimits { max_total_bytes, max_files, max_file_bytes })
store.device(&id) / store.devices()             // limits and current usage

// Receiving one file
store.begin_file(FileRequest { device, name, size, claimed_hash, capture_time, mtime_unix_ns })
    -> Result<IncomingFile, StoreError>         // name safety, quota, free space, no reparse points; then creates the temp file
incoming.write(&bytes)                          // streaming; hashes as it goes
incoming.finish(claimed_hash) -> Result<CommitReceipt, StoreError>
incoming.abort()                                // or just drop it

// Asking
store.find_duplicate(&hash, DedupeScope::Device(&id) | DedupeScope::AnyDevice) -> Result<Option<StoredFile>, _>
store.is_safely_stored(&hash)                   -> Result<StoredStatus, _>     // Verified(file) | NotVerified(reason)
store.verify_for_deletion(&hash, min_age_sessions) -> Result<DeletionProof, DeletionDenied>

// Health
store.integrity_scan(&ScanOptions { max_bytes_per_sec, max_files, restart, skip_unexpected }, &cancel)
    -> Result<ScanReport, _>                    // resumable, rate-limited, cancellable
store.final_move_block() / store.block_final_move(reason) / store.clear_final_move_block(note)
store.acknowledge_clock_change(note)            // after the PC clock was wrong; a person's decision
store.stats() / store.events_after(seq, limit) / store.ledger_path()

// Stand-alone pieces
Destination::open(root)                         // classify a folder without opening a store
sanitize_rel_path(name) / sanitize_component(name)
Template::parse("{year}/{month}/{device}")
ContentHash::from_hex / to_hex / of_bytes
```

Errors are typed (`StoreError`, `LedgerError`, `DeletionDenied`,
`SanitizeError`, `TemplateError`, `DestinationError`) and non-exhaustive.

A commit that finds a file with **identical content already at the target
path** (checked by reading it) records that file and reports
`CommitOutcome::AlreadyPresent` instead of creating ` (2)`. This is what makes
retries idempotent, including after a crash between the rename and the ledger
record, and it is how photos copied by hand before the app was installed
become known.

### What the caller must do

* Register each paired device before its first file.
* Call `find_duplicate` before transferring, to skip files already stored.
  (It reads and hashes the stored file every time; that is the point.)
* Give the capture time if it knows it (the crate does not parse EXIF).
* Put the ledger directory on a local disk (the engine refuses a network
  volume): the application's data directory, or `<root>/.kiwi-store`.
* Open the store once per transfer session if final move should ever become
  possible in a long-running process: "an earlier session" means an earlier
  `Store::open`.
* Treat `StoreError::Ledger(LedgerError::Corrupt)` at open as something to
  tell the user, then call `reset_corrupt_ledger`.
* Show the block reason to the user and call `clear_final_move_block` only on
  their decision.

## On disk

```
<root>/.kiwi-store/id        identity marker of the destination (ties it to its ledger)
<root>/.kiwi-store/lock      held while a store is open (one store per destination)
<root>/**/.kiwi-tmp-*.part   a transfer in progress (or debris, removed at start-up)
<ledger_dir>/ledger.db       the ledger (SQLite); ledger.db.corrupt-N are quarantined copies
```

The ledger is an index: devices, one row per stored file (path, hash, size,
commit sequence number, session and time, a checksum over those fields),
an append-only event log with a strictly increasing sequence number, the
session counter, the block flag, and scan progress. `PRAGMA integrity_check`
runs at every open; schema changes are versioned migrations; a ledger from a
newer version is refused untouched.

## Platforms

| | Windows (target) | Linux / other Unix (tests only) |
|---|---|---|
| Volume classification | drive type, file system, bus, removable, hot-plug | none: every destination is copy-only |
| Verification read | `FILE_FLAG_NO_BUFFERING` | `O_DIRECT` where the file system has it, else cached and reported as such |
| Flush | `FlushFileBuffers` | `fsync` (`F_FULLFSYNC` on macOS) |
| No-replace rename | `MoveFileExW(MOVEFILE_WRITE_THROUGH)` | `renameat2(RENAME_NOREPLACE)`, else `link` + `unlink` |
| Directory flush | `FlushFileBuffers` on the directory handle | `fsync` on the directory |
| Links | every reparse point | symbolic links (mount points are not detected) |
| Case-insensitive names | the file system, plus the engine's own check | the engine's own check only |

## Tests

```
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The tests create their files under Cargo's target directory
(`CARGO_TARGET_TMPDIR`) and nowhere else. `KIWI_STORE_TEST_TMP=<dir>` moves
them, for example onto another volume. `PROPTEST_CASES=<n>` changes the number
of property-test cases.

The `test-util` feature exposes the seams the tests use (a replaceable file
system for fault injection, a settable clock, a forced volume class). It lets
the caller replace the very operations the guarantees rest on. **Never enable
it in a shipping build.**

## Licence

Apache-2.0. Direct dependencies: `blake3` (CC0-1.0 OR Apache-2.0), `rusqlite`
(MIT) with bundled SQLite (public domain), `thiserror` (MIT OR Apache-2.0),
`unicode-normalization` (MIT OR Apache-2.0, with Unicode-3.0 data),
`windows-sys` (MIT OR Apache-2.0), `libc` (MIT OR Apache-2.0); for tests,
`proptest` (MIT OR Apache-2.0). Everything they pull in is MIT, Apache-2.0,
Zlib, Unicode-3.0 or CC0: all free, all compatible with Apache-2.0.
