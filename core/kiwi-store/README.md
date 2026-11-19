# kiwi-store

The PC-side durable storage engine of Kiwi Transfer.

It receives files from paired phones, writes them to a destination folder,
proves to itself that they are really on the disk, keeps a ledger of what it
stored, and can keep a second copy of everything on a second disk. A phone is
allowed to delete its own copy of a photo only on the strength of what this
crate reports. So the crate is built to say **no** whenever it is not sure.

No networking, no user interface. The transfer layer calls this crate. It
implements the store's part of `docs/PROTOCOL.md` (Draft 2): section 7, the PC
half of section 8, and 8.13. What it does not implement of that text is listed
under [Not implemented](#not-implemented-from-protocol-draft-2).

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
   replace anything** (`MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`).
7. **The new name was made durable and confirmed:** the file was flushed under
   its new name, its directory was flushed, the name was resolved again (it
   leads exactly where the engine put it), and the file was read from the
   device once more under that name and still hashed right.
   (`MOVEFILE_WRITE_THROUGH` promises a flush only for a move done as copy and
   delete, not for a rename inside a volume.) On a destination that can ever
   confirm a deletion, a failed flush fails the commit; on a copy-only
   destination whose file system cannot flush a directory, the receipt says
   `dir_synced: false`.
8. The ledger has a durable record of the file (SQLite, WAL,
   `synchronous=FULL`), with the phone's item key, the phone's own commit
   number, and the phone's session.

If any step fails, nothing is recorded and a typed error says which step it
was. A failure before the rename deletes the temp file; a failure after it
leaves the (complete) file under its final name, unrecorded, where a retry
finds it and records it instead of storing a second copy.

`finish_batched` is the same, except that the ledger record is not flushed
before it returns; see [Batched ledger commits](#batched-ledger-commits).

### Always, whatever goes wrong

* **Nothing is ever overwritten, moved or modified.** If the name is taken,
  the file becomes `name (2).ext`, up to `(999)`. Names that differ only in
  case or in Unicode normalisation count as the same name.
* **The only files the engine deletes are its own temp files.** A temp file
  is `.kiwi-tmp-<tag>-<n>-<random>.part`. Every run of the store draws a
  random `<tag>` and writes it to the ledger, flushed, before it creates its
  first temp file. A file is deleted only if its name has exactly that shape,
  its tag is one this ledger recorded, it is a plain file reached through
  plain directories, it does not belong to a transfer in progress, **and it
  is not a committed file whose rename was lost**: if a record of the same
  size, in the same directory, is without its file, the temp file is read and
  hashed first, and if it is that file it is given its final name again. A
  look-alike with an unknown tag is reported (`unowned_temps`) and left alone.
  There is one function in the crate that calls "delete", and it refuses any
  other name.
* **A file never has its final name before it has been verified.**
* **Nothing is written outside the destination root.** Peer-supplied names are
  sanitised; `..`, absolute paths, drive letters, UNC and device paths are
  refused outright. No name from a phone can begin with `.kiwi-`, at any
  depth, so nothing a phone sends can be, or lie inside, one of the engine's
  own objects.
* **Junctions and symbolic links are never followed** anywhere between the
  root and a file: not when writing, not when verifying, not when cleaning up.
* **The ledger is never believed on its own.** Every "yes" this crate gives
  comes from reading the file back from disk and hashing it.
* **Every phone answers for itself.** Each phone's files lie in its own folder,
  whatever the layout. A copy stored by one phone is never used to answer for
  another, not for a duplicate check, not for a deletion, not even when both
  hold the very same bytes. There is no deduplication across phones.
* **Unpairing removes nothing.** `detach_device` marks the phone as unpaired;
  its records, its files and their states stay, are scanned and are mirrored.
  There is no call that removes a device's records or files.

### Sessions

A session is one established connection **of one phone**. Only
`new_session(device, session_seq)` begins one. Starting the program, opening
the store, or another phone connecting is not a session of this phone. The
counter is per device, lives in the ledger, and survives restarts; the number
agreed with the phone is used as it is if it is above the current one.

A file belongs to the session of its phone in which it was recorded (a
transfer that straddles `new_session` belongs to the new one), and is never
confirmed for deletion in that session, however long it lasts.

### When `verify_for_deletion(device, request)` returns `Ok`

The phone names the record exactly: item key, hash, size and commit number.
All of these were true at the moment the call returned:

1. The destination, examined again right then, is a **fixed internal disk
   with NTFS or ReFS** on an allow-listed bus, not hot-pluggable, **outside
   any cloud-synced folder**, not under Downloads, a temp folder or the
   recycle bin, **writable by this account, SYSTEM and Administrators only**,
   and it is the same volume the store was opened on.
2. Final move is **not blocked** (see below).
3. The device is registered and paired.
4. The clock does not read earlier than a time already recorded in the ledger.
5. **This device** has a record with exactly that key, hash, size and commit
   number; the PC user has not acknowledged it as removed; the file it names
   lies **inside this device's own folder**.
6. The record was committed in an **earlier session of this device**: at least
   `min_age_sessions` sessions ago (never fewer than one), before the device's
   current session began by event sequence number, **and** at least 24 hours
   ago by the clock. If the commit happened while this process was running,
   the process also knows how much time can really have passed on a clock
   that cannot be set; a wall clock that jumped ahead does not get past that
   (`ClockDisagrees`).
7. That file was read from the device again, in full, with an **unbuffered**
   read, just now; its size and hash matched; its name is flushed.
8. The ledger recorded the verification in a **flushed transaction of its
   own** before the answer was given (never batched), and marked the file
   "may be the only copy" (`FmState::Reverified`).

The answer carries `proof = MAC(proof_key, content)`: BLAKE3 in keyed mode
over the bytes of the read in step 7, computed in the same pass. The transfer
layer derives the key from a fresh nonce of the phone, so the proof cannot be
answered from the ledger, a cache, an earlier result, a mirror, or another
phone's file. It also carries `copies`: 1 plus the mirrors that hold a verified
second copy.

Anything else is a denial with a typed reason. A denial changes nothing on
disk. The store's delay rule is its own; the transfer layer keeps a second
clock with the phone (the link clock), and both must agree.

### What blocks final move

A persistent flag in the ledger, for **all** phones. Once set,
`verify_for_deletion` denies everything until `clear_final_move_block` is
called explicitly; a restart, a clean scan or a repair does not clear it. It
is set when

* a stored file is found **changed** (always) or **missing** (by default);
* a junction or link is found on the way to a stored file, or a record names
  a file outside its phone's folder;
* many files changed, vanished or were renamed together (**mass change**);
* the ledger was damaged and reset, is empty although the folder was used
  before, or the folder lost its identity marker;
* the ledger was **rolled back** (`BlockKind::LedgerRollback`): a phone names
  a commit number above the device's `commit_hwm`
  (`check_peer_commit_seq`, or inside a verification request), or the
  destination's own note of the commit numbers is ahead of the ledger at
  start (the ledger then also gets a new `ledger_id`);
* **a disk returns a device error** (`BlockKind::DiskFailing`), the
  destination or a connected mirror, while reading or writing; "disk not
  connected" is not an error;
* a second copy on a connected mirror is found missing or changed, or a
  mirror gives back other bytes than it was given;
* the application calls `block_final_move`.

While blocked, receiving and mirroring continue. Clearing the flag vouches for
nothing: every later confirmation still re-reads its file.

### The mirror (second copy on a second disk)

* A mirror is a folder on a **different physical disk** (another partition of
  the destination's disk is refused, and so is a disk that cannot be
  identified), local, NTFS/ReFS/exFAT, not cloud-synced, not overlapping the
  destination. USB disks are fine. At most 4 are active; they may take turns.
* `run_mirror` copies every stored file that has no verified copy on a
  connected mirror: the destination's file is read once, unbuffered, with the
  whole path checked, and **those very bytes** are written to a temp file on
  the mirror; the hash of what was read must equal the ledger's hash; the
  temp file is flushed and read back from the mirror, and that hash must equal
  the ledger's hash too; then rename without replace, flush, re-read under
  the final name, record. If the destination's file does not give the ledger's
  hash, nothing is published and the damage is recorded.
* **The wrong disk is never written to.** Before every run the marker
  (`.kiwi-store/second-id`, a random id plus the destination's id) and the
  volume serial number are compared with the ledger.
* **An absent disk is normal**: reported as `MirrorPresence::Absent` with the
  time and the number of program runs since it was last seen; nothing is
  blocked. When it returns, the copies written by the previous run are read
  back first (a disk pulled out without "eject" may have lost them).
* `scan_mirror` re-reads every recorded copy. A missing or damaged second
  copy is written again from the destination; a file that is missing or
  damaged on the destination is written again from a mirror copy, **after
  that copy has been read back and matched the ledger's hash**. If neither
  disk matches, nothing is repaired. A destination that was lost entirely is
  rebuilt the same way (open the store on the new, empty folder with the same
  ledger, then scan).
* **A repair never overwrites, moves or deletes.** The repaired copy takes the
  original name if it is free, otherwise the next free name, and the ledger
  points at it; the damaged file stays where it is. Every repair is in the
  event log (`primary_repaired`, `mirror_repaired`) with paths and hash. A
  file repaired on the destination keeps its key, hash and commit number, and
  has to age again before it confirms a deletion.
* **Final move does not wait for the mirror**, and a proof never comes from
  it. `oldest_unmirrored_commit(device)` and `copy_counts(device)` let the
  application warn while the phone's trash still holds the original.

### Batched ledger commits

`finish_batched` writes the ledger record with `synchronous=NORMAL`: atomic
and ordered, but not flushed. The next flushed write (`flush_batch`,
`new_session`, any confirmation, a clean shutdown) makes the whole batch
durable at once. The file itself goes through the full pipeline either way.
The receipt says `durable: false`; **do not acknowledge it to the phone before
`flush_batch` has returned**. A power failure before the flush forgets the
records, not the files: the phone, which was never told, sends them again and
they are found on disk and recorded. Nothing that confirms a deletion is ever
batched, and `verify_for_deletion` flushes before it looks.

## What is *not* guaranteed

Read this part twice.

* **Hardware that lies about flushes.** `FlushFileBuffers` asks the drive to
  empty its write cache; some drives and USB bridges acknowledge and do
  nothing. The unbuffered read-back bypasses the operating system's cache,
  **not the drive's own**. This is the main reason a deletion is confirmed
  only after a later session and 24 hours, and why a lost rename is recognised
  by hash at the next start. A drive that returns stale or wrong data
  consistently cannot be detected from here.
* **Malware or anyone else acting as the user.** The checks detect *damage*;
  they are not a defence against an adversary on the PC.
* **The future.** `Ok` describes the moment it was returned. One copy on one
  disk is not a backup; that is what the mirror is for, and final move does
  not wait for it.
* **Clocks.** A wall clock set forward shortens the 24 hours, except for
  files stored while the same process has been running. A restarted process
  has only the wall clock, the session rule, and the phone's own clock to go
  by. A clock that reads earlier than a time in the ledger is detected and
  denies until real time catches up or `acknowledge_clock_change` is called.
* **A session is whatever the caller says it is.** The engine cannot tell
  whether `new_session` was really called once per connection.
* **Network shares, USB disks, memory cards, FAT/exFAT, virtual disks,
  hot-pluggable disks and any disk the engine cannot identify** are copy-only
  as destinations.
* **Sync folders are recognised by what is known about them**: marker files
  of Dropbox, Google Drive, Nextcloud/ownCloud, Syncthing and Resilio in the
  folder or above it, the OneDrive and iCloud folders named by the
  environment, and Windows cloud-files placeholder attributes or reparse
  tags. A sync program that leaves none of these is not recognised.
* **"Emptied by the system"** means: under any user's `Downloads`, under a
  temp folder named by the environment, or in the recycle bin. A relocated
  Downloads folder is not found, and Storage Sense's own settings are not read
  (Downloads is refused whether or not Storage Sense is on).
* **The access list** is read for "allow" entries only: an account listed as
  able to write may still be denied by a "deny" entry; never the other way
  round. The engine never changes permissions by itself;
  `Destination::make_private` does, when the application asks.
* **"A different physical disk"** is the device number Windows reports. Two
  disks behind one RAID or Storage Spaces volume, or two virtual disks on one
  physical disk, look like what the system says they are.
* **Bit rot between scans.** A file is known to be intact when it was last
  read. Run both scans.
* **If the ledger is lost**, the files stay but nothing is known about them;
  a mirror is then only a folder of files. Keep the ledger off the
  destination's disk. (A verified ledger copy on the mirror is not written
  yet.)
* **Non-Windows platforms** never confirm a deletion, and cannot tell disks
  apart (no mirror can be added). See below.

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
| names starting with `.kiwi-` (the engine's own; any case, any depth) | prefixed with `_` |
| **shell-active names** | suffix `.kiwi-blocked` appended |
| any Unicode | normalised to NFC |
| components longer than 240 UTF-16 units (with every prefix and suffix) | shortened, extension kept |
| more than 64 levels | refused |

**Shell-active names.** Explorer reads some files when it merely lists a
folder, which can make the PC contact a remote server and disclose the user's
credentials hash. A component (file or directory) is stored with
`.kiwi-blocked` appended if, without regard to case, its last extension is
`.lnk`, `.pif`, `.url`, `.website`, `.scf`, `.library-ms`,
`.searchconnector-ms`, `.search-ms`, `.appref-ms`, `.settingcontent-ms`,
`.theme`, `.themepack` or `.deskthemepack`; or the whole name is `desktop.ini`,
`autorun.inf` or `thumbs.db`; or its last extension is `.{GUID}`. So `x.url`
is stored as `x.url.kiwi-blocked` (a second file of that name as
`x.url (2).kiwi-blocked`). The content is untouched; the ledger keeps the name
the phone sent (`StoredRecord::source_name`), which is what a restore gives
the file back under; the engine never renames a stored file back. Mirrors
carry the same inert names. The receipt says `neutralised: true`.

Paths are built under a `\\?\` root, so paths far beyond 260 characters work
and Windows applies no normalisation of its own. Every path read back from the
ledger must sanitise to itself, or it is not used.

## Organisation templates

`StoreConfig::layout` is a `Template`. Tokens: `{year}`, `{month}`, `{day}`,
`{device}`, `{phone_dir}`. Presets: `by_date()` = `{device}/{year}/{month}`,
`per_device()` = `{device}`, `keep_phone_structure()` = `{device}/{phone_dir}`.
**Every file lies below its phone's own folder**: a template that does not
begin with `{device}` is applied inside that folder (`{year}/{month}` stores
under `Pixel 8/2024/03`). The folder name is fixed when the phone is first
registered.

## API summary

```rust
// Opening
Store::open(StoreConfig::new(root, ledger_dir)) -> Result<Store, StoreError>
Store::reset_corrupt_ledger(cfg)                -> Result<Store, StoreError>
store.destination() -> &Destination   // .supports_final_move(), .final_move_support(), .warnings(), .volume()
Destination::make_private(folder)     // owner, SYSTEM, Administrators; nothing inherited
store.run_number() -> u64             // +1 on every open; NOT a phone's session
store.ledger_id()                     // renewed when the ledger is found rolled back
store.open_notes() -> &[OpenNote]     // NewDestination, LedgerLost, LedgerReset, MarkerRecreated, LedgerRolledBack
store.recovery_report() / store.run_recovery(&cancel)

// Devices, sessions, rollback
DeviceId::new("...")                                    // A-Z a-z 0-9 . _ -  (1..=128)
store.register_device(&id, display_name, limits)        // also re-attaches an unpaired device
store.detach_device(&id, note)                          // unpair: nothing is removed
store.device(&id) / store.devices()                     // usage, detached, commit_hwm, session_seq
store.new_session(&id, Some(session_seq) | None) -> u64 // the ONLY thing that begins a phone's session
store.commit_hwm(&id) -> u64                            // highest commit number ever issued to the phone
store.check_peer_commit_seq(&id, phone_receipt_hwm) -> RollbackCheck   // RolledBack blocks final move
store.report_rollback(detail)

// Receiving one file
store.begin_file(FileRequest { device, key, name, size, claimed_hash, capture_time, mtime_unix_ns })
incoming.write(&bytes)
incoming.finish(claimed_hash)         -> CommitReceipt { seq /* per-device commit number */, session, durable, neutralised, .. }
incoming.finish_batched(claimed_hash) -> CommitReceipt { durable: false, .. }   // plain copies only
store.flush_batch() / store.pending_batch()
incoming.abort()                      // or just drop it

// Asking (always for one device)
store.find_duplicate(&id, &hash)      -> Option<StoredFile>      // re-reads the file
store.is_safely_stored(&id, &hash)    -> StoredStatus
store.verify_for_deletion(&id, &VerifyRequest { key, hash, size, commit_seq, proof_key, min_age_sessions })
    -> Result<DeletionProof { proof, copies, file, .. }, DeletionDenied>
store.records(&id, &hash)             -> Vec<StoredRecord>       // ledger only (re-anchor look-up)
store.audit(&id, key, &hash, size)    -> AuditStatus             // record + directory entry, no read
store.mark_sole_copy(&id, key, &hash, expires) / store.mark_in_place(&id, key, &hash)
store.acknowledge_removed(file_id, note)                         // PC user: "removed on purpose"
store.records_in_state(&id, FmState::SoleCopy | FmState::Reverified)

// Health
store.integrity_scan(&ScanOptions { .. }, &cancel) -> ScanReport   // resumable, rate-limited
store.final_move_block() / store.block_final_move(reason) / store.clear_final_move_block(note)
store.acknowledge_clock_change(note)
store.stats() / store.events_after(seq, limit) / store.ledger_path()

// Mirror (second copy on a second disk)
store.add_mirror(folder, label) -> MirrorInfo      // also re-attaches a known mirror at a new path
store.remove_mirror(id, note)                      // nothing on the disk is touched
store.mirrors() / store.mirror_presence(id)        // Present | Absent { secs_since_seen, runs_since_seen } | WrongDisk(..)
store.mirror_pending() -> Vec<MirrorPending>       // per mirror and device: files, bytes
store.run_mirror(&cancel) / store.run_mirror_with(&MirrorOptions { mirror, max_bytes_per_sec, max_files, .. }, &cancel)
store.scan_mirror(&MirrorOptions { repair, .. }, &cancel) -> MirrorScanReport
store.rebuild_mirror(new_folder, label, replaces, &cancel)
store.copy_counts(&id) -> CopyCounts { no_copy, one_copy, two_or_more }
store.oldest_unmirrored_commit(&id) -> Option<UnmirroredCommit>
```

Errors are typed (`StoreError`, `LedgerError`, `MirrorError`,
`DeletionDenied`, `SanitizeError`, `TemplateError`, `DestinationError`) and
non-exhaustive.

A commit that finds a file with **identical content already at the target
path** (checked by reading it; never a hidden, system, offline or linked file,
never another phone's) records that file and reports
`CommitOutcome::AlreadyPresent` instead of creating ` (2)`. This is what makes
retries idempotent.

### What the caller must do

* Register each paired device before its first file, and call `new_session`
  for it once per established connection, and only then.
* Send `commit_hwm(device)` to the phone and pass the phone's highest receipt
  number to `check_peer_commit_seq` at every session start.
* Give every file its item key. Call `find_duplicate` before transferring.
* Acknowledge a batched receipt to the phone only after `flush_batch`.
* Derive `proof_key` from a fresh nonce for every verification request.
* Tell the store what the phone reports (`mark_sole_copy`, `mark_in_place`).
* Put the ledger directory on a local disk, not on the destination's disk.
* Show `destination().warnings()` and the block reason to the user; call
  `clear_final_move_block` only on their decision.
* Run `integrity_scan`, then `scan_mirror`, regularly; run `run_mirror` when
  a mirror is connected; tell the user when its report says `completed`.

## On disk

```
<root>/.kiwi-store/id          identity marker of the destination (ties it to its ledger)
<root>/.kiwi-store/lock        held while a store is open (one store per destination)
<root>/.kiwi-store/commits     each device's highest commit number, as of the last ledger flush
<root>/<device folder>/...     the files; .kiwi-tmp-<tag>-<n>-<random>.part while in transfer
<mirror>/.kiwi-store/second-id marker of a mirror (its random id and the destination's id)
<mirror>/<device folder>/...   plain copies under the same paths and names
<ledger_dir>/ledger.db         the ledger (SQLite); ledger.db.corrupt-N are quarantined copies
```

The ledger is an index: devices (session counter, commit high-water mark,
unpaired flag), one row per stored file (device, item key, commit number,
path, hash, size, session and time, final-move state, a checksum over the
fields decisions depend on), an append-only event log with a strictly
increasing sequence number, the temp-file tags, the mirrors and their copies,
the block flag, and scan progress. `PRAGMA integrity_check` runs at every
open; schema changes are versioned migrations (this is schema 3); a ledger
from a newer version is refused untouched.

## Platforms

| | Windows (target) | Linux / other Unix (tests only) |
|---|---|---|
| Volume classification | drive type, file system, bus, removable, hot-plug, device number | none: every destination is copy-only, no mirror can be added |
| Verification read | `FILE_FLAG_NO_BUFFERING` | `O_DIRECT` where the file system has it, else cached and reported as such |
| Flush | `FlushFileBuffers` (file, and file again under its new name) | `fsync` (`F_FULLFSYNC` on macOS) |
| No-replace rename | `MoveFileExW(MOVEFILE_WRITE_THROUGH)` | `renameat2(RENAME_NOREPLACE)`, else `link` + `unlink` |
| Directory flush | `FlushFileBuffers` on the directory handle | `fsync` on the directory |
| Links | every reparse point | symbolic links (mount points are not detected) |
| Hidden / system files | the attributes | none |
| Who else may write | the access list (allow entries) | the mode bits (group, others) |
| Cloud placeholders | attributes and cloud reparse tags | none (marker files only) |

## Tests

```
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

The tests create their files under Cargo's target directory
(`CARGO_TARGET_TMPDIR`) and nowhere else; a "second disk" is a directory there
with its own (pretended) volume. `KIWI_STORE_TEST_TMP=<dir>` moves them.
`PROPTEST_CASES=<n>` changes the number of property-test cases. One test
changes the access list of its own test folder (`icacls` / `chmod`).

The `test-util` feature exposes the seams the tests use (a replaceable file
system for fault injection, a settable clock with a separate monotonic hand, a
forced volume, a volume probe for mirrors, the places where sync folders are
looked for). It lets the caller replace the very operations the guarantees
rest on. **Never enable it in a shipping build.**

Not tested here, because it needs hardware: a real USB or removable disk
(unplugging under load, a bridge that ignores flushes, drive letters changing),
two physical disks and the device number Windows reports for them, exFAT and
ReFS volumes, a real OneDrive / Dropbox folder with placeholders, and a second
Windows account.

## Not implemented from protocol Draft 2

Listed so that nobody assumes them:

* Stage 2 of the verification (the check of an item already in the phone's
  trash, with `min_age`) and the re-anchor write (`records` gives the look-up;
  issuing a new receipt for it is not there).
* Following a file that was moved inside its phone's folder (8.9 rule 2): the
  scan reports it as missing plus "rename suspect" and adopts nothing.
* Discarding a received file because the same phone already has a record with
  that hash elsewhere (6.9 rule 4a): the caller asks `find_duplicate` first.
* Mark-of-the-Web on ad-hoc files; item `kind`; the PC link clock (kept by the
  transfer layer); a per-phone "allow free up space" switch (consent, kept by
  the application); `scan_age`.
* A ledger backup on the mirror; one combined scan over both disks (there are
  two calls); drive failure prediction.
* Unreadable files (in use, access denied) do not block final move; only a
  device error does. The protocol text counts every unreadable file as damage.

## Licence

Apache-2.0. Direct dependencies: `blake3` (CC0-1.0 OR Apache-2.0), `rusqlite`
(MIT) with bundled SQLite (public domain), `thiserror` (MIT OR Apache-2.0),
`unicode-normalization` (MIT OR Apache-2.0, with Unicode-3.0 data),
`windows-sys` (MIT OR Apache-2.0), `libc` (MIT OR Apache-2.0); for tests,
`proptest` (MIT OR Apache-2.0). Everything they pull in is MIT, Apache-2.0,
Zlib, Unicode-3.0 or CC0: all free, all compatible with Apache-2.0. No
dependency was added for this version; only `windows-sys` features.
