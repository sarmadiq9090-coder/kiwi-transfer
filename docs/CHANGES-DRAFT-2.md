# `kiwi/1`: changes from Draft 1 to Draft 2

Status: 2026-11-19. Draft 2 of `docs/PROTOCOL.md` and `docs/THREAT-MODEL.md` applies every finding of
`docs/REVIEW-PROTOCOL-1.md` (KT-01 to KT-34), the reviewer's answers to the 17 open questions where the
manager did not decide otherwise, and the manager's decisions M1 to M12. "P x.y" is a section of
`PROTOCOL.md`; "TM" is the threat model.

Contents: 1 Review findings - 2 Manager decisions - 3 Findings applied differently from the proposal -
4 Open questions - 5 Wire changes at a glance - 6 What the PC store (`core/kiwi-store`) must do -
7 What the approved screens must change.

---

## 1. Review findings

"As proposed" means the reviewer's fix was written into the normative text. "Alternative" means a different
fix with the same or a stronger effect; the reason is in section 3. B = blocking in the review.

| ID | Sev. | Applied | What the text now says | Sections changed |
|---|---|---|---|---|
| KT-01 B | High | As proposed (the "age floor" variant) | Weekly state is `age_base` + `age_lc`, never moved backwards; all arithmetic saturating; `confirm_age` capped at 2^32 on the wire; `confirm_epoch` and `last_session_seq` range-checked (close code 1); "required" is a durable flag `need_confirm` that only a correct code clears; vectors for age 0, 604 799, 604 800, 2^32, 2^64-1, `LC < age_lc`. | P 0 (arithmetic), P 3.2, P 3.3, P 3.4, P 5.3 4(d), P 5.7, P 5.11 `HELLO`, P 11.2 `confirm-state`, `ranges`; TM C3, C5 |
| KT-02 B | High | As proposed, plus | `STATUS.commit_hwm` and `PHONE_STATUS.receipt_hwm`; a lower `commit_hwm` is a ledger rollback (receipts void, phone block, immediate alert for trashed items); a `commit_seq` above `commit_hwm` raises the PC's block and lifts `commit_hwm`; status 6 under the current `ledger_id` is treated as status 2; weekly `AUDIT` of copy-mode items; a restored ledger gets a new `ledger_id`. | P 5.3 step 5, P 5.11 (`Status`, `PHONE_STATUS`, `AUDIT`), P 7 (ledger), P 8.2 item 4, P 8.5, P 8.8, P 8.10, P 8.11 row 36; TM C9, C10, 5.2 L19, 5.3 path 15, R26 |
| KT-03 B | High | As proposed, plus | Release keys have `key_id`; signature over `"kiwi-release-manifest-v1\n" \|\| manifest`; `keys.revoke` / `keys.add`; revoked set stored for ever; `seq` against replay; `min_supported`; manifest fetched at check time so that revocations spread; rotation, lost-key and stolen-key procedures; custody requirements K1-K8 including the Android signing key. | P 10.1, P 10.4 (new), P 11.2 `release`, Appendix B; D22, D39; TM C13, R12 |
| KT-04 B | Med. | As proposed | Normative rustls/quinn settings (no tickets, no session storage, no early data, resumption disabled, no SNI, no `NEW_TOKEN`, Retry always); `HELLO_AUTH` looks the pin up again; negative tests f, g, h (and k). | P 1.3, P 1.4, P 5.3 step 3, P 5.9; D12; TM C3 |
| KT-05 B | Med. | As proposed | The verifier keeps no cross-connection state; every value and the pin come from the connection object of the verified message; strict Ed25519 everywhere; interleaved-pairing test (j) and strictness test (i). | P 0, P 1.4, P 2.3, P 2.4 rules 4-5, P 11.2, P 11.3; TM C2, C3 |
| KT-06 | Med. | Adopted; alternative in one detail | **The PC user types the 6 digits shown on the phone.** The PC shows no number, no name and no Allow button. Method SAS: "Number correct" on the PC, then "Did the PC say the number was correct?" on the phone. `E_BUSY` text for the phone. Detail that differs: the typed number is compared with every candidate connection (section 3). | P 2 intro, P 2.1, P 2.4, P 2.5, P 5.11 `PAIR_*`; D6, D41; TM C2, R10 |
| KT-07 B | Med. | As proposed | Unpairing deletes pin and session state only; the namespace becomes "unlinked": still scanned, marked, mirrored, shown; removable only by an explicit PC action that lists sole copies; the PC warns its own user 7 and 2 days before a sole copy's trash expiry; `REVERIFIED` is shown as "may be the only copy". | P 2.7, P 8.3 (PC states), P 8.9 rule 1, P 8.10 (rows "PC keeps watch", "Unpaired"), I7; TM C10, 5.3 path 13 |
| KT-08 B | Med. | As proposed | `new_epoch = max(epoch_pc, epoch_ph) + 1`; the phone **sets** it; restored-PC case in the vectors; missed-result rule made explicit. | P 3.3 rule 1, P 3.4 rule 5, P 5.11 `RECONFIRM_*`, P 11.2 |
| KT-09 B | Med. | As proposed | `FM_VERIFY_VALIDITY` checked when Android's dialog is launched; after `RESULT_OK` every item is queried again (size, `DATE_MODIFIED`, hash where readable); mismatch: restore at once, alert, excluded; not found: recorded and reported (`FM_STATE` state 3, cause 3). The phone state is named `GONE` with a cause instead of `PURGED`. | P 8.3, P 8.6 (API 30+ rules 1-2, API 24-29 rule 3), P 5.11 `FmEvent`, P 8.11 rows 38-39; TM C9, R20 |
| KT-10 B | Med. | As proposed | A version is size, mtime or content hash; `generation` is a trigger for re-hashing only and is never compared; stage 2 compares size and content. | P 6.2, P 6.3 rule 3, P 6.5 rule 4, P 8.2 item 5, P 5.11 `Media` |
| KT-11 | Med. | As proposed, on every Android version | Trashing (and purging) is blocked unless the phone's wall clock is within 1 h of the PC's and wall time agrees with the link clock since the receipt; warnings scheduled from `DATE_EXPIRES` and from the link clock, whichever is earlier. | P 0 (time), P 3.2 rule 4, P 8.6 rule 2 and API 30+ rule 5, P 8.8, P 8.10, P 8.11 row 37, `HELLO.wall_time`; TM C9, R5 |
| KT-12 B | Med. | As proposed | A failed stage 2 keeps `TRASHED` and sets `hold` (never purged automatically); re-anchor: stage 2 without `commit_seq` matches by (hash, size) in this link's rebuilt ledger and restarts the delays; status 10 "removed by the PC user" raises no block. | P 8.3, P 8.5, P 8.7, P 8.8, P 8.10, P 5.11 (`FmItem`, `FmResult`); TM 5.2 L22 |
| KT-13 B | Med. | Alternative (aligned with the store as built) | Names beginning with `.kiwi-` are reserved at every level; temporary files carry a journaled tag; the PC deletes only its own temporary files and never while a record of that size lacks its file (the file is hashed first: a lost rename is recognised and redone); the "moved" search is limited; the new name is flushed (file and directory) before the ledger commit; crash recovery looks at the temporary file first and never raises a false alert for a pre-existing file. | P 6.8 rule 8, P 7 (steps 1, 9a, deletion rule, crash table), P 8.9 rule 2, P 5.10 rule 4, P 8.11 rows 10, 42; TM C7, 5.3 path 18 |
| KT-14 | Med. | As proposed | Destination rules 7 (not Downloads, temp, Recycle Bin, Storage Sense) and 8 (owner-only DACL, set at creation, checked always; `fm_reason` 7, 8); bus **allow-list**; hot-pluggable disks copy-only. | P 8.2, P 5.11 `Root.fm_reason`; TM C7, R14, 5.3 path 19 |
| KT-15 | Med. | As proposed (helper mandatory, AppContainer) | Thumbnails are decoded only in an AppContainer helper process without capabilities (a low-integrity token alone would still have network access); header dimensions read first; no thumbnails if the helper cannot be restricted. | P 9.3 rule 5; D43; TM C12, R18 |
| KT-16 | Med. | As proposed | `REPAIR_REQUEST` items need `key`; the phone answers only for (key, hash) pairs of its own ledger for that link; rate limit; visible notice. | P 5.7, P 5.11 `REPAIR_*`, P 8.9 rule 5b; TM C9 |
| KT-17 | Med. | Alternative suffix, wider list | Shell-active names are stored with the suffix **`.kiwi-blocked`** (not `.kiwi`); the list also covers `.pif`, `.search-ms`, `.appref-ms`, `.settingcontent-ms`, theme files, `autorun.inf`, `thumbs.db` and `.{GUID}` names; the ledger keeps the original name; Mark-of-the-Web on purpose-2 files; no System/Read-only attribute on directories. | P 6.6 rule 6, P 6.8 rules 9, 13, P 9.1 (phone to PC), P 8.13 rule 4, P 5.11 `Entry.name`; D38; TM C7 |
| KT-18 | Med. | As proposed | The mDNS responder runs only on eligible interfaces, by an explicit enable list, and stops when there is none. | P 4.1, P 4.5 rule 4; TM C4 |
| KT-19 B | Med. | As proposed | One range table (`MAX_FILE_SIZE` 2^42, counters 2^53, durations saturate at 2^32, `Time` out of range is "unknown"); counts and lengths checked against the remaining frame before allocation; canonical CBOR enforced; too many components is `E_NAME`; a bad `resume_offset` restarts from 0. | P 0, P 5.2 rules 4, 8, 9, P 5.7, P 6.4, P 6.5 rule 3, P 6.8 rule 6, P 11.2 `ranges`, `cbor` |
| KT-20 | Med. | As proposed | "Reset this device's identity" on both programs. | P 1.1 rule 6, P 8.10; TM C1, R1 |
| KT-21 | Low | Superseded | The weekly check no longer pauses copying, so `XFER_END`, `FM_STATE` and `ERROR` are allowed by construction; temporary-file expiry is unaffected. | P 3.5 |
| KT-22 | Low | As proposed, plus | Both pins provisional until the first `HELLO_AUTH`; PC tombstones (90 days) and close code 3 as an authenticated "unpaired"; `proof_pc` computed at `PAIR_REVEAL`; the phone may also deliver a late `UNPAIR` ("farewell"). | P 1.4 (modes), P 2.3, P 2.4 rule 8, P 2.7, P 5.3 step 3 |
| KT-23 | Low | As proposed, for both methods | No device name travels before the typed number matched: names moved to `PAIR_RESULT` and `PAIR_DONE`. | P 2.1, P 2.4, P 5.11; TM C2, R29 |
| KT-24 | Low | Alternative (stronger) | A **per-link** `discovery_key` sent in `PAIR_RESULT`; the TXT record carries 8 fixed hint slots. | P 2.6, P 4.2, P 5.11 `PAIR_RESULT`, Appendix B; D31; TM C4, R7 |
| KT-25 | Low | Hop limit as proposed; prefixes: alternative | Hop limit 1 is a MUST on both sides; too-wide on-link prefixes are **narrowed** to /64 or /16 instead of ignored. | P 1.3, P 4.4; D24, D42; TM C3 |
| KT-26 | Low | As proposed, plus | `status` (and the device name) removed from `HELLO`; `STATUS` and the new `PHONE_STATUS` are sent after `HELLO_AUTH`. | P 5.3, P 5.9 rule 5, P 5.11 |
| KT-27 | Low | As proposed | A multi-part response stays outstanding until `more = false`; a part at least every 30 s, 60 s silence fails; every block is re-checked immediately before each trash call. | P 5.4, P 8.6 rule 1, P 8.8, P 8.11 row 43 |
| KT-28 | Low | As proposed | Receipts are validated against what the phone itself sent. | P 6.5 rule 6, P 5.11 `ITEM_RESULT`; TM C6 |
| KT-29 | Low | As proposed (limit value from the store) | Length limit applies to the finished component with every prefix and suffix (240 UTF-16 units, as the store does); paths compared component by component in one normalised form; MediaStore read-back of `DISPLAY_NAME` and `RELATIVE_PATH`. | P 6.8 rules 5, 6, 12, 18, P 6.9 rule 2 |
| KT-30 | Low | As proposed (Windows marker: see section 3) | Boot id not derived from the wall clock; a gap down to -300 s counts as 0; a weekly number is shown only after an explicit click. | P 3.2 rule 3, P 3.4 rule 3; D15 |
| KT-31 | Low | As proposed | Endpoint rows 5 and 6 (connections the operating system or the installer makes on the program's behalf). | P 10.3 |
| KT-32 | Low | As proposed | `kiwi-trash.json` is untrusted: restore only to a cleaned relative path, create-new. | P 8.6 (API 24-29 rule 1), P 8.10; TM B2, R13 |
| KT-33 | Low | As proposed | Restored items enter as `LOCAL` with a cached hash and are upgraded through `have`. | P 9.4 rule 5, P 8.12 rule 6 |
| KT-34 | Low | As proposed | Pre-expiry checks are scheduled from `DATE_EXPIRES` (10 days before), never from an assumed 30 days. | P 8.6 (API 30+ rules 4-5) |

---

## 2. Manager decisions

| # | Decision | How it is encoded | Sections changed |
|---|---|---|---|
| M1 | Networks: Public by per-network opt-in, never Domain; firewall rule; QR on Public with the typed number; SAS Private-only; mDNS on Public only as a secret-keyed hint; hop limit 1 MUST | Eligibility table by Windows category; one-click, per-network switch keyed by network id, no administrator rights; one firewall rule (program, UDP, stored port, `LocalSubnet`, Private and Public); `pm` only on Private; per-link keyed hints; hop limit 1 with no setting; per-user install handling. | P 2 intro, P 2.1, P 4.2, P 4.4, P 4.5, P 4.6, P 5.9; D29; TM C4, R25 |
| M2 | Weekly 2-digit check, narrow scope, per phone | Table of classes: copying, state reports and repair continue; `FM_VERIFY`, purges, browse, thumbnails, fetch, restore, PC-to-phone delivery and clipboard pause. | P 3 intro, P 3.5, P 3.6, P 5.4 (`E_CONFIRM_REQUIRED`), P 6.3 rule 6, P 9 intro; D32; TM C5 |
| M3 | Several phones per PC are first-class; own namespace only; per-device verification | "Namespace" defined; per-phone pairing, folder, settings, quota, weekly code; invariant **I8**: a proof is read from a file that a record of that phone's link names, inside its folder; no cross-phone `have`, `need_hash` or dedup; one record, one file, no hard links between phones (disk sharing left to a later version, which would change no message); browse roots cannot overlap another namespace; a namespace belongs to at most one live link. | P 0, P 2.6, P 3.6, P 5.10, P 6.3 rules 1-2, P 6.9 rules 4-5, P 8.1 I8, P 8.5, P 8.10, P 9.3 rule 1, P 9.4 rule 2, P 11.3; D10, D33; TM A15, B16, C7, C9, C12, 5.3 path 17 |
| M4 | No password, no encryption, no in-app lock for the files on the PC | New section 9.7; Draft 1 had no vault text to remove (checked); stated consequences; the DPAPI protection is said to cover the identity seed only. | P 1.6, P 9.7, P 8.13 rule 4; D34; TM "two properties", A2, C7, R22, R24, R27, MASVS-STORAGE-1 |
| M5 | Second copy on a second disk | New section 8.13: phone transfers to the primary only; final move does not wait; hash-verified copy by the PC alone; absent external disk and catch-up; escalating reminders tied to trash expiry; rotation of up to 4 disks; scan of both with self-repair that never overwrites; a failing disk blocks final moves, copying continues; rebuild; `STATUS.copies` and `FmResult.copies`; warning rules for the phone. | P 8.1, P 8.7 rule 6, P 8.9, P 8.11 rows 45-46 and case C, P 8.13, P 5.11 (`Copies`, `FmResult`); D35; TM C15, 5.1, 5.2 L21, 5.3 path 16, R23 |
| M6 | Keep-on-phone period | New section 8.12: phone setting (1 week, 1 month, 3 months, 1 year, custom; optional per folder); copying immediate; anchor = max(capture time, date added, restored_at); favourites and "keep on phone" never moved; a restore restarts the period; the PC is told `keep_period`, `keep_overrides`, `counts.waiting`, `counts.kept` for display and reminders only; `Media.date_added`. | P 6.1, P 8.1, P 8.2 item 8, P 8.6 rule 3, P 8.12, P 5.11 (`PHONE_STATUS`, `Counts`, `Media`); D36; TM 5.2 L20 |
| M7 | Data backup beyond media | New section 9.6: `Item.kind` 1-7 (media, file, contacts, calendar, app list, APK file, app backup file); snapshot naming, `snapshot_time`, `orig_name`; vCard 3.0, iCalendar, JSON manifest; restore: contacts merge add-only (the only mode), calendar add-only into a new local calendar, APKs saved and never installed; no SMS, no call log; capability 8. | P 5.3 (capabilities), P 5.11 (`Item`, `Entry`), P 8.1, P 8.2 item 2, P 9.5 rule 8, P 9.6; D37; TM A14, B15, C16, R24, R28 |
| M8 | PC-to-phone send; shell-active files | Drag and drop or right-click; one phone or all; outbox with no silent expiry; accept per transfer; optional "always accept from this PC" (default off); pictures and videos to the gallery folders, the rest to `Download/Kiwi Transfer/`; never auto-open. Files from a phone with shell-active names are stored with `.kiwi-blocked` (KT-17). | P 9.1, P 6.8 rules 9, 13, 17, P 5.11 `PHONE_STATUS.auto_accept`; D38, D45; TM C8, R30 |
| M9 | Sync-folder destinations; Android 11+ trash | Copy with a lasting warning (`Root.sync_warning`), final move refused, never the default. Android 11+: the system's period (30 days), warnings at 7 and 2 days; the trash-period setting exists on Android 7-10 only. | P 8.2 rule 4, P 8.6 (API 30+ rules 4-5; API 24-29 rule 6), P 5.11 |
| M10 | "Home" = a paired PC answers | New section 4.8; no Wi-Fi names, no location permission, no allowed-networks list. | P 4.8; D30 |
| M11 | Store facts | A session is explicit (5.3 step 4(d), "What a session is"); hot-pluggable disks are copy-only (8.2 rule 2); a missing file blocks until acknowledged (8.9 rule 3); ledger commits may be batched for copies, never for a final-move confirmation (7 "Batching", 8.5). Also aligned: temporary files next to the final file, name limits 240 / 64, sanitiser rules, "identical file at the target path is recorded", resume optional. | P 5.3, P 6.7, P 6.8, P 6.9 rule 4b, P 7, P 8.2, P 8.5, P 8.9 |
| M12 | Release signing | See KT-03. | P 10.1, P 10.4 |

Housekeeping: the document is "Draft 2"; Decisions D6, D10, D12, D14, D15, D16, D22, D24, D26, D27 updated
and D29-D46 added (P 12); all 17 open questions closed with their answers (P 13.1); message catalogue,
constants and context strings brought in line (P 5.11, Appendix A, Appendix B).

---

## 3. Findings applied differently from the proposal, and why

| Finding | Proposed | Draft 2 | Reason |
|---|---|---|---|
| KT-06 | One consent at a time; another `PAIR_HELLO` gets `E_BUSY` | The typed number is compared with every candidate (at most 2); the single match wins | With one pending dialog, an attacker who answers first still blocks the real phone. Since the number selects the device, arrival order no longer matters. Success per candidate stays 10^-6. |
| KT-13 | `.kiwi-tmp` directory reserved; clean-up needs a `partial` row per file; intent row for the rename | Temporary files next to the final file, reserved prefix `.kiwi-`, a journaled tag per run, a hash check before any temporary file is deleted, and "identical file at the target path is recorded" on retry | This is how the store is built. It closes the same three holes with one durable write per run instead of one per file, and it also survives a drive that lied about the flush (the lost rename is recognised by hash). |
| KT-17 | Suffix `.kiwi` | Suffix `.kiwi-blocked`; longer list; `.{GUID}` names | The suffix should tell the user what happened, and `.kiwi` invites a future file association. |
| KT-24 | One `discovery_key` per PC | One per link, 8 fixed slots | A phone that was unpaired must not be able to track the PC afterwards. |
| KT-25 | Ignore on-link prefixes shorter than /64 or /16 | Narrow them to the /64 or /16 around the interface's own address | Same protection; a home network set up as a /8 keeps working. |
| KT-29 | (limit unspecified, "after all suffixes") | 240 UTF-16 units including the collision suffix; 64 components in total | The store's values; below the NTFS limit of 255. |
| KT-30 | "A kernel boot counter" on Windows | A random marker in a volatile registry key | Windows offers no boot counter to an unelevated program that does not derive from the wall clock; a marker that is lost too often only takes the safe branch (item V9). |
| KT-09 | State `PURGED` for a vanished item | State `GONE` with a cause (purged, expired, not found) | "Purged" claimed an action of the app that did not happen. |
| KT-19 | Durations above the range: implied error | Saturate at 2^32 | A huge age must read as "expired", not close the connection. |
| KT-21 | Allow three more messages in `REQUIRED` | Superseded by the narrow scope (M2) | |

Nothing was left unapplied.

---

## 4. Open questions

The 17 questions of Draft 1 are closed in P 13.1 (answers of the review, overridden by M1, M2, M9, M10 and
M12 where they differ). New in Draft 2:

- **For the manager** (P 13.2): N1 purge on Android 7-10 versus the second copy; N2 final move for
  non-media files; N3 automatic removal of old snapshots (would be an exception to I7); N4 which data sets
  a Google Play build carries; N5 a network share as second disk; N6 shared PC folders kept under "own
  namespace only"; N7 three new controls on the screens; N8 per-user installation and the firewall rule.
- **To verify on devices** (P 13.3): V1 reading trashed items; V2 mDNS on tethering; V3 Android 17
  permission; V4 Android 10 legacy storage; V5 WhatsApp folder access; V6 trash batch size; V7 port 47474;
  V8 gallery favourites in MediaStore; V9 the Windows boot marker.

---

## 5. Wire changes at a glance

| Element | Change |
|---|---|
| `HELLO` | Removed: `device_name` (4), `status` (12), `fm_in_use` (13). Added: `need_confirm` (14). Ranges on 6, 7, 9. |
| `STATUS` | Sent only after `HELLO_AUTH`. Added: `commit_hwm`, `device_name`, `copies`, `block_reason`, `sole_copies`, `fm_allowed`. `Root`: kinds renamed (1 own namespace, 2 shared folder, 3 inherited backup), `fm_reason` 7-10, `sync_warning`. |
| `PHONE_STATUS` (0x0A) | New: name, `fm_in_use`, `receipt_hwm`, keep period, trash kind, counts, `auto_accept`, `fm_block`. |
| Pairing | `PAIR_CONFIRM` (0x13) retired. Names removed from `PAIR_HELLO` and `PAIR_CHALLENGE`; `PAIR_RESULT` gains `device_name`, `discovery_key`; `PAIR_DONE` gains `ok`, `device_name`. |
| `RECONFIRM_*` | `new_epoch` semantics (max + 1; the phone sets it). |
| `Item` | Added: `kind` (required), `orig_name`, `snapshot_time`. `Media`: `date_added`; `generation` informational. |
| `FM_VERIFY` | `FmItem.commit_seq` optional in stage 2 (re-anchor). `FmResult`: status 10, `copies`, `receipt`. Parts: heartbeat rule. |
| `FM_STATE` | State 3 is "gone"; `cause`. |
| `REPAIR_*` | `key` required; reply by (key, available). |
| `AUDIT` / `AUDIT_RESULT` (0x46 / 0x47) | New. |
| `Entry` | `item_kind`, `snapshot_time`; `name` is the original name. |
| Capabilities | 8 `data` added; `AUDIT` is part of capability 1. |
| mDNS TXT | `h` is 8 keyed slots (128 hex); `pm` only on Private interfaces. |
| Encoding | Canonical CBOR enforced; range table; no allocation from declared sizes. |
| Constants | New or changed: `MAX_FILE_SIZE`, `AGE_CAP`, `REQUEST_TIMEOUT`, `ACCEPT_TIMEOUT`, `PAIR_ENTRY_TIME`, `PROVISIONAL_PIN_LIFETIME`, `TOMBSTONE_LIFETIME`, `HINT_SLOTS`, `CLOCK_TOLERANCE`, `CLOCK_AGREE`, `NEUTRAL_SUFFIX`, `FM_BATCH` (500 to 100), `PRE_EXPIRY_CHECK`, keep-on-phone values, `AUDIT_PERIOD`, `MAX_SECOND_DISKS`, `SNAPSHOT_MIN_INTERVAL`, `APP_BACKUP_MIN_INTERVAL`, `OUTBOX_MAX` (the 7-day outbox lifetime is gone), `MAX_RELEASE_KEYS`; hop limit 1; stored-name limits 240 / 64. |

---

## 6. What the PC store (`core/kiwi-store`) must do that it does not do today

Read from its README and public interface at commit `af04aca`; items the other worktree may already cover
are still listed.

1. **Sessions per phone, explicit.** A `new_session(device)` call made by the transfer layer at P 5.3
   step 4(d); "an earlier session" must mean an earlier session **of that phone**, not an earlier
   `Store::open` and not another phone's connection.
2. **Per-device verification.** `verify_for_deletion` must take the device and the record (`key`, `hash`,
   `size`, `commit_seq`), look only at that device's records, require the file to lie inside that device's
   folder, compute `MAC(K_v, content)` in the same unbuffered pass, and commit `REVERIFIED` durably, one
   item per transaction, before it answers. `DedupeScope::AnyDevice` must not feed any answer on the wire.
3. **One folder per phone under every layout.** `Template::by_date()` without `{device}` would let two
   phones' records name one path; every layout must start below the device folder.
4. **Shell-active names**: append `.kiwi-blocked` in the sanitiser (list and `.{GUID}` rule of P 6.8
   rule 9), keep the phone's name in the ledger; Mark-of-the-Web for purpose-2 files.
5. **Temporary files**: a tag journaled before first use; the deletion rule of P 7 (never delete while a
   record of that size has no file, hash first, re-create a lost rename); "moved" search limited to the
   same device folder and never matching `.kiwi-` names, hidden, system, reparse or offline files.
6. **Destination rules**: bus allow-list, owner-only DACL (set at creation, checked at every evaluation),
   not under Downloads / temp / Recycle Bin / Storage Sense, sync-root detection for the warning.
7. **Ledger**: commit numbers counted **per device**, with a per-device `commit_hwm`; item `kind`, `name`, `orig_name`; file states `REVERIFIED`,
   `SOLE_COPY` (with `expires`), `USER_REMOVED`; unlinked devices (records kept after unpairing); a commit
   counter in the destination marker; a new `ledger_id` when a restored ledger is detected; group commit
   for copies.
8. **Queries**: a metadata-only audit (P 8.10), the re-anchor lookup by (hash, size) within one device
   (P 8.7), counts of one-copy and two-copy files per device (`STATUS.copies`), block reasons 6 (rollback)
   and 8 (disk errors).
9. **Second copy** (P 8.13) in full: second-disk eligibility and marker, verified copy, catch-up and
   read-back after reconnection, rotation, scan of both, self-repair that never overwrites or deletes,
   failing-disk block, rebuild of the primary, ledger backup.
10. **Delay rule**: the store's 24-hour rule uses the system clock; P 8.5 also requires the PC link clock
    (kept by the transfer layer). Both must hold.

---

## 7. What the approved screens must change

PC program:

1. Pairing: after the QR, **a number field "Type the 6 digits shown on your phone"** replaces the Allow
   dialog; the PC never shows the number or the phone's name before it matched; method SAS adds "Number
   correct. Now confirm on your phone."
2. Networks: a per-network switch **"Use Kiwi Transfer on this network"** for Public networks, and a list
   of networks with their Windows category. No instruction to change the network to Private.
3. Per phone: **"Allow this phone to free up space using this PC"** (default off); folder, quota, shared
   folders; **"Show the weekly number for <phone>"** as an explicit button (no number on opening).
4. Unpaired phones stay listed with their folder ("unlinked"), their "only copy" counts and trash expiry
   warnings; removing one first lists the sole copies. Files verified a second time are labelled "may be
   the only copy".
5. Second disk: add / status per disk / reminders that escalate with trash expiry / "Rebuild from the
   second copy"; a statement that copies on it are plain files.
6. Sending: drop targets for one phone and "All phones", the Explorer entry "Send to phone", an outbox
   list per phone.
7. Destination: warning for a sync folder; "Make this folder private to my account"; no proposal of a
   sync folder as default; the statement that stored files are plain files without a password.
8. Settings: "Reset this device's identity".

Phone app:

1. Pairing: "Type this number on the PC"; method SAS: "Did the PC say the number was correct?"; the
   `E_BUSY` and "QR already used" texts.
2. Final move: the **keep-on-phone period** (1 week, 1 month, 3 months, 1 year, custom; optional per
   folder), a "keep on phone" mark; favourites are never moved; no trash-period setting on Android 11+
   ("Android keeps removed items for 30 days").
3. Per PC: "N files on two disks, M on one disk", last connection of the second disk; the warnings of
   P 8.13 rule 11; alerts with one-tap restore for `hold` items and after a PC restore (rollback).
4. Weekly check: the message says that backup continues and what waits.
5. Receiving: the accept dialog with **"Always accept from this PC"**; pictures and videos land in the
   gallery.
6. Data sets: switches for contacts, calendars, all files, app list and APKs, WhatsApp backup; restore
   screens (contacts: "N will be added, M already exist"; calendar: new local calendar; apps: list only,
   APKs saved, nothing installed).
7. Settings: "Reset this device's identity".
