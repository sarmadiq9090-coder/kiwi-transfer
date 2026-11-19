# Kiwi Transfer 1.0: threat model

Status: Draft 2, 2026-11-19. Companion to `docs/PROTOCOL.md` (protocol `kiwi/1`, Draft 2). References of the
form "P 8.5" mean section 8.5 of `PROTOCOL.md`. "KT-nn" is a finding of `docs/REVIEW-PROTOCOL-1.md`.

Contents: 0 Scope and method - 1 Assets - 2 Actors and assumptions - 3 Trust boundaries and data flows -
4 STRIDE per component - 5 Data-loss analysis for final move - 6 Residual risks - 7 OWASP MASVS checklist -
8 When to revisit this document.

What changed since Draft 1, in one paragraph: one PC now serves several phones as a first-class case; the
files on the PC are deliberately **plain files with no password and no encryption** (owner decision); the PC
may keep a **second copy** on a second disk, and final move does not wait for it; the phone also backs up
**contacts, calendars, other files, app lists, APK files and WhatsApp's backup**; Public networks can be
enabled per network; pairing is completed by **typing** the phone's number on the PC; the weekly check no
longer stops backup copying. Each of these adds or changes rows below, and section 6 has new residual risks
R22 to R30.

---

## 0. Scope and method

**In scope:** the Android app (minSdk 24, Kotlin/Compose), the Windows program (Rust + WebView2), the shared
Rust core and the PC storage engine, the `kiwi/1` protocol, pairing, discovery, storage of keys and
ledgers, the stored files and their second copy, the data sets beyond media, the update check with its
release keys, and the problem report.

**Out of scope:** the security of Android, Windows, the router, GitHub and the user's mail program
themselves; attackers with root, kernel or administrator rights on a device; hardware attacks; the
project's build infrastructure (it has its own checklist: SLSA provenance, OpenSSF Scorecard), except
where the release keys touch the update check (P 10.4).

**Method:** assets, actors and trust boundaries first; then a STRIDE table per component (Spoofing,
Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege); then a separate
analysis of the one way this product can destroy user data (final move); then residual risks stated without
softening; then a mapping to OWASP MASVS.

**The two properties that matter most**, in order:

1. **No loss of the user's files.** A photo that exists only once must never be destroyed by this software
   acting on wrong information.
2. **No disclosure of the user's files** to anyone but the user's own devices. Draft 2 limits what this
   second property can mean on the PC: the owner chose plain files over any lock (P 9.7), so on the PC
   "the user's own devices" includes everyone who can use that Windows account or hold that disk.

---

## 1. Assets

| Id | Asset | Where | What must be protected |
|---|---|---|---|
| A1 | User files on the phone (photos, videos, documents), including metadata inside them (location, dates) | Phone shared storage | Confidentiality, integrity, **existence** |
| A2 | Copies on the PC, as plain files on the primary destination and on second disks; after a final move, the **only** copies | PC destination folder; second disks | Integrity, **durability**; confidentiality only as far as Windows provides it (P 9.7) |
| A3 | Device identity keys (Ed25519) | Phone: wrapped blob + Keystore key. PC: DPAPI blob | Confidentiality (a copied key is a cloned device) |
| A4 | Pin stores (which device is paired with which), tombstones, per-link discovery keys | App-private storage on both | Integrity (a forged pin is a silent man in the middle) |
| A5 | Ledgers and final-move journals, with their high-water marks | App-private databases on both | Integrity, availability, **freshness** (an old ledger is as wrong as a damaged one) |
| A6 | Short-lived values: pairing secret, pairing number, weekly code | PC screen (QR, weekly code), phone screen (pairing number), memory | Not disclosed or guessable within their lifetime |
| A7 | Metadata about the user: file names, album names, device names, which devices exist on the network, when backups run | Wire, logs, mDNS | Confidentiality |
| A8 | Clipboard text sent between devices | Memory, clipboard | Confidentiality |
| A9 | The rest of the PC's file system and the user's Windows session | PC | Integrity: the program must never write outside its destination or run received content; Explorer must not be made to act on received files |
| A10 | The rest of the phone's storage, its contacts and calendars | Phone | Integrity: received files land only in the app's own folders; a restore never changes or deletes an existing contact or event |
| A11 | The update channel (release keys, release manifest, Android signing key) | Owner, offline; GitHub | Integrity |
| A12 | The user's consent (typed pairing number, accept dialog, trash dialog, final-move switches on phone and PC, per-network switch) | Both UIs | Must not be forged, pre-answered or obtained by confusion |
| A13 | PC resources: disk space, CPU, the listening port | PC | Availability |
| A14 | **Personal data of other people**: the address book and calendar of the phone's user (names, numbers, addresses, appointments), the list of installed apps, WhatsApp's backup | Phone; after backup also the PC, in plain form | Confidentiality; never deleted from the phone by this app |
| A15 | Each phone's namespace on the PC, with respect to the **other** phones of the same PC | PC | Isolation: one phone never reads, lists, or relies on another phone's files |

---

## 2. Actors and assumptions

### 2.1 Adversaries

| Id | Actor | Capabilities |
|---|---|---|
| T1 | **Passive network observer** on the same LAN (guest, neighbour with the Wi-Fi password, a compromised smart device) | Sees all frames on the link: addresses, timing, sizes, mDNS. |
| T2 | **Active network attacker** on the same LAN, including a Public network the user enabled | Everything T1 can, plus: spoof ARP/NDP, DHCP, Router Advertisements and mDNS; run a rogue access point; drop, delay, replay and inject packets; open connections to the PC. |
| T3 | **Malicious or compromised paired peer** (a tampered phone app, or someone holding a stolen phone identity key; symmetrically a compromised PC program) | Is authenticated. Sends any protocol message with any content: hostile names, sizes, hashes, counters, crafted images, crafted vCards. |
| T4 | **Remote internet attacker** | No route to the devices (on-link rule, hop limit 1). Can try: a web page or message carrying a pairing link or QR; a router port-forward; the update channel; a poisoned dependency. |
| T5 | **Thief or finder of the phone** | Phone locked, or phone unlocked. |
| T6 | **Person near the PC** (visitor, colleague) | Sees the screen (QR, weekly code); may use the unlocked PC. |
| T7 | **Malware running as the user on the PC** | Everything the user can do: read and write the user's files, call DPAPI, read the screen, send input to windows. |
| T8 | **Another app on the phone** (no root) | Sends intents and shares; reads and writes shared storage if it holds storage permission; draws overlays; reads the clipboard while in front. |
| T9 | **Ransomware on the PC** | A special case of T7 that encrypts or deletes the user's files. |
| T10 | **Supply-chain attacker** | Compromises a dependency, the build, the GitHub account, or steals a release key. |
| T11 | **Another member of the household** | Uses the same Windows account, or another account on the same PC; owns another phone paired with the same PC; may be curious, careless or hostile. |
| T12 | **Holder of a disk** | Has a second disk that left the house, a discarded or repaired PC, or a stolen PC, and reads it with another computer. |

### 2.2 Non-adversarial hazards

They cause most real data loss and are treated as seriously as attackers.

| Id | Hazard |
|---|---|
| H1 | Disk failure, bit rot, a drive that acknowledges a flush it did not perform, a cable pulled, power loss. |
| H2 | Crashes and forced stops at any instruction; the phone killed by battery management. |
| H3 | Wrong clocks: empty RTC battery, manual changes, time zone changes, a bad network time. |
| H4 | The user: deletes or moves the PC folder, reinstalls Windows or the app, revokes a permission, ignores a warning, unplugs an external drive without ejecting, never connects the second disk. |
| H5 | The operating system: Android empties its trash after 30 days; Windows marks a network Public; a sync client moves files to a cloud; Storage Sense cleans a folder. |
| H6 | Our own bugs. |
| H7 | **Restores**: a system image, a VM snapshot or a file backup brings back an old ledger (and perhaps old files) with the same identity. |

### 2.3 Assumptions

1. The operating systems enforce their own boundaries: the Android app sandbox and Keystore, Windows user
   separation and file permissions.
2. The cryptographic primitives are sound: Ed25519 (verified strictly), X25519, the three TLS 1.3 AEAD
   suites, BLAKE3 (collision and preimage resistance, and its keyed mode as a MAC and its derive-key mode as
   a KDF), SHA-256 for release key ids and asset hashes.
3. rustls, quinn and ring implement TLS 1.3 and QUIC correctly **when configured as P 1.3 prescribes**. The
   project's own verifier and configuration (P 1.3, P 1.4) are the parts that need review and have mandatory
   negative tests.
4. During pairing, the person at the PC keyboard is the person holding the phone, or cooperates with them,
   and types the number shown on that phone.
5. The user's Windows account is not already controlled by an attacker when the program is installed. If it
   is, see residual risk R1.
6. The owner keeps the release keys as P 10.4 requires (K1 to K8).

---

## 3. Trust boundaries and data flows

```
                         B12: the human (scans QR, types the pairing number, reads the weekly code, answers dialogs)
        ......................................................................................
        :                                                                                    :
+-------:---------------- PHONE (Android) ----------+          +------------- PC (one Windows user session) -------:------+
|                                                   |          |                                                          |
|  other apps --B5--> [ Kiwi app: Compose UI ]      |          |   [ WebView2 UI ] --B7-- [ Rust host + core + store ]    |
|   (share sheet,          |  B4 (UniFFI)           |    B1    |                              |        |      |           |
|    intents, overlays)  [ Rust core ] <==== QUIC + TLS 1.3 (mutual pins) ====> listener      |        |     B14          |
|                          |        |               |  (LAN,   |                              |        |  [ thumbnail     |
|        B3: Android Keystore       | B2            |  hotspot,|            B9: DPAPI blob ---+        |    helper,       |
|        (wraps identity seed)      v               |  USB)    |                                  B10  |    restricted ]  |
|   B15: contacts, calendar,  shared storage        |          |   primary destination: one folder per phone (B16),       |
|        package manager      (MediaStore, trash    |          |   plain files; ledger database                           |
|        (read; write only    folder); other apps   |          |   B13: second disks (plain files), may leave the house   |
|        at restore)          can read and write it |          |   B8: every other process of the same user reaches all   |
+---------------------------------------------------+          |       of this (NO boundary enforced by Windows)          |
            B6: mDNS on the link (unauthenticated)             +----------------------------------------------------------+
                                                                         B11: internet, GitHub only (update check)
```

| Id | Boundary | What crosses it | Protection at the crossing |
|---|---|---|---|
| B1 | The link between the devices | Everything | TLS 1.3 with mutual `SPKI` pins and verified handshake signatures; no resumption; signed session transcript; on-link address rule and hop limit 1 (P 1, P 4.4, P 5.3). |
| B2 | App to shared storage | User files, trash folder, trash index | None against other apps with storage access: files are re-checked (size, time, hash) before every decision; the trash index is untrusted (P 6.5, P 8.5, P 8.6). |
| B3 | App to Android Keystore | Wrap/unwrap of the identity seed | Hardware-backed where available (P 1.6). |
| B4 | Kotlin to Rust (UniFFI) | Commands, progress, platform results | Typed interface; the core validates platform inputs as data. |
| B5 | Other apps to the Kiwi app | Shared items, intents | Minimal exported surface; no pairing link; shared URIs validated (P 9.5, component C14). |
| B6 | mDNS | Candidate addresses, hint | Treated as hints only; filter then pin; advertised only on eligible interfaces; hint keyed per link (P 4). |
| B7 | WebView2 UI to native host | UI events, strings for display | Local content only; peer strings as plain text; narrow message interface (C14). |
| B8 | PC program to other processes of the same user | Key blob, ledger, files, window | **No protection exists.** See R1. |
| B9 | PC program to DPAPI | Identity seed | CurrentUser scope, with the limits in P 1.6. |
| B10 | PC program to the destination file system | Files, directories | Reparse-point checks, create-new only, unbuffered re-read, durable rename, neutralised shell-active names, owner-only folder permissions (P 6.8, P 6.9, P 7, P 8.2). |
| B11 | Programs to GitHub | Update check, manifest, download | HTTPS, fixed hosts, manifest signed by a non-revoked release key (P 10.1, P 10.4). |
| B12 | Human to devices | QR, typed pairing number, weekly code, consent | The number is typed, not clicked; commitment scheme; attempt limits; arming by click (P 2, P 3). |
| B13 | PC program to a second disk | Second copies, ledger backup | Hash-verified copy and read-back, marker, re-read after reconnection (P 8.13). **No confidentiality** (R27). |
| B14 | PC program to the thumbnail helper | One read-only file handle in, one JPEG out | Low-privilege process, job limits, no network, no file access of its own (P 9.3). |
| B15 | App to the phone's contacts, calendar and package list | Snapshots out; at restore, new entries in | Read access only while the data set is on; write access only for a user-started restore; add-only (P 9.6). |
| B16 | One phone's namespace to another's, on the same PC | Nothing may cross | Every answer is computed from the asking link's records and files only (P 0, P 6.3, P 8.1 I8). |

Main data flows: (F1) pairing; (F2) session setup; (F3) backup phone to PC, all item kinds; (F4) final move
verification and trashing; (F5) send PC to phone; (F6) browse, thumbnails, fetch, restore; (F7) clipboard;
(F8) discovery; (F9) update check and download; (F10) problem report through the mail program; (F11) second
copy, PC disk to PC disk; (F12) restore of contacts and calendars into the phone.

---

## 4. STRIDE per component

Columns: **Cat** is the STRIDE letter. **Residual** names what remains after the mitigation ("none" means
no practical attack is known within the stated assumptions).

### C1. Identity keys and key storage

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Copy the phone's key from a backup or a cloned data directory, then act as the phone. | Seed wrapped by a non-exportable Keystore key; blob in the no-backup directory; backups and device transfer excluded (P 1.6). | Devices without a hardware-backed Keystore; rooted devices. |
| S | Copy the PC's key and impersonate the PC to the phone. | DPAPI CurrentUser. | **R1**: any program running as the user can do this. |
| S | A key that was copied stays valid after "unpair and pair again". | "Reset this device's identity" creates a new key and voids every pairing (P 1.1 rule 6); recommended after a malware clean-up or a suspected clone. | The user must do it. |
| T | Replace the identity blob or the pin store to redirect a device. | App-private storage; an unwrap failure forces a new identity and voids all pairings (P 1.1 rule 5). | PC: same-user malware (R1). |
| R | A device denies having taken part in a session. | Signed session transcript (P 5.3); not a product goal between a user's own devices. | Accepted. |
| I | Key bytes exposed in memory dumps, logs or crash reports. | Zeroize-on-drop buffer; the logging interface cannot take byte strings (P 10.2); no crash reporter. | A debugger or root on the device. |
| D | Key loss (uninstall, profile reset) breaks the link. | Detected; the user is told to pair again; no data is deleted; the PC keeps the phone's files as an unlinked namespace (P 2.7, P 8.10). | Inconvenience only. |
| E | Use the key from another app. | Android: sandbox. | PC: none (R1). |

### C2. Pairing (QR and SAS)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T2 pretends to be the PC towards the phone during QR pairing. | The phone verifies the PC id from the QR before sending anything; handshake signature verified; `proof_pc` (P 1.4, P 2.4). | None. |
| S | T2, or a bystander who photographed the QR, pretends to be the phone towards the PC. | Needs the one-time 128-bit secret bound by a MAC to both identities and the TLS exporter; **and then the PC accepts only the connection whose number the user typed from their own phone** (P 2.4, P 2.5). The attacker's connection has a different number. | An attacker who can also type on the PC keyboard: R10. |
| S | T2 is a man in the middle during SAS pairing and grinds keys or nonces until the phone shows the number of the attacker's connection. | Commitment scheme: one guess per candidate, success 10^-6, at most 2 candidates and 3 typed numbers per window (P 2.5). SAS pairing only on Private networks (P 2.1). | The user answers "Yes" on the phone although the PC said the number was wrong. |
| S | T2 answers first in SAS mode, or occupies a slot, so that "its" dialog is the one on the PC. | There is no per-device dialog and no Allow button: the typed number selects the connection (decision D41). | T2 can occupy both UNPAIRED slots: nuisance only. |
| S | T4 sends the user a link or QR that pairs the phone with the attacker's PC. | No URI scheme, app link or intent starts pairing; QR accepted only from the in-app scanner; QR addresses must be on-link (P 2.2). | The attacker must already be on the LAN and get the user to scan their QR in the app. |
| S | Interleaved pairing connections make the PC pin the key of connection A on the evidence of connection B. | The verifier keeps no state; every value and the pin come from the connection object of the verified message; a mandatory test (P 1.4, KT-05). | Implementation error caught by the test. |
| T | Replay of pairing messages on another connection. | Proofs and SAS bind the TLS exporter of this connection; fresh nonces. | None. |
| T | A hostile device name in the pairing screens (markup, direction overrides, a name copied from the user's phone model). | No name is sent or shown before the number matched; afterwards cleaning and plain-text rendering (P 2.4, P 5.8). | None. |
| R | "I never paired that phone." | The PC history records pairings with time and name. | Local log, not tamper-proof (R1). |
| I | The pairing secret leaks from the QR after use. | Single use, destroyed at first valid proof or at window end; the QR leaves the screen when a candidate exists (P 2.1, P 2.2). | None. |
| I | Method SAS: the phone dials whichever host advertises `pm=1` and shows it its long-term certificate. | No name is sent before the number matched (KT-23); SAS mode exists only on Private networks, inside a window the user opened. | The phone's public key is disclosed to that host: R29. |
| D | T2 burns the three attempts or occupies the two UNPAIRED slots so the user cannot pair. | Limits; the user reopens the window; the phone explains `E_BUSY`. | Nuisance on a hostile LAN. |
| D | A phone is left half-paired (one side pinned, the other not). | Both pins are provisional until the first `HELLO_AUTH`; expiry after 10 minutes; tombstone gives an authenticated "unpaired" (P 2.4, P 2.7). | None. |
| E | An UNPAIRED connection reaches transfer or browse messages. | UNPAIRED connections accept `PAIR_*` only, 4 KiB frames, one stream, and are never upgraded (P 2.1). | None. |
| E | A standing pairing service is abused later. | There is none: unknown keys are rejected in the handshake when no window is open (P 2.1). | None. |

### C3. Transport and session (QUIC, TLS, `HELLO`)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Present a pinned certificate without owning its key. | `CertificateVerify` must be verified, strictly, with the certificate's key; mandatory negative test; second check by the signed transcript, which looks the pin up again (P 1.4, P 5.3). | Implementation error caught by tests. |
| S | Resume an old session after being unpaired; skip Retry with a stored token. | Tickets, PSK, 0-RTT and `NEW_TOKEN` are switched off **by explicit configuration** (the library defaults enable them), SNI is not sent, and three negative tests check it (P 1.3, P 1.4 f-h, KT-04). | A future library change that re-enables a default: caught by the tests, which are release gates. |
| T | Downgrade to a weaker protocol or to plaintext. | One ALPN, no fallback of any kind; TLS 1.3 only (P 1.3). | None. |
| T | Alter version or capability negotiation, or the link counters. | Inside TLS, and signed over the exporter (P 5.3). | None. |
| T | T3 sends counters at the edge of the integer range to wrap arithmetic (weekly age, epoch, session number). | Range table; saturating or checked arithmetic; no stored value is moved backwards; "required" is a durable flag (P 3.2, P 3.3, P 5.7, KT-01). | None known; covered by vectors. |
| R | Disputes about what was sent. | Local history on both sides. | Accepted. |
| I | T1 reads file content, names or device names. | All of it is inside TLS; device names are never in mDNS, in certificates or in `HELLO` before authentication (P 1.2, P 4.1, P 5.3). | Traffic sizes and timing (R8). Recorded traffic and future quantum computers (R9). |
| I | T2 learns the PC's public key by starting a handshake. | Not preventable in TLS 1.3 (the server authenticates first). The phone's key is not shown to a wrong server in a normal connection (P 1.5). | **R7**. |
| D | Handshake floods, spoofed sources. | Source filter, Retry, handshake limits, nothing allocated before authentication (P 5.9). | A local attacker can still jam the radio or the link (R15). |
| E | Reach the listener from the internet through a port-forward, or by a forged on-link prefix. | Source address must be on-link; wide prefixes narrowed; hop limit 1 is mandatory; sockets only on eligible interfaces (P 4.4, P 4.5). | None. |

### C4. Discovery (mDNS) and listener placement

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T2 advertises a fake PC or answers with its own address. | Candidates only; the pin decides (P 4). | Failed attempts and delay. |
| T | T2 rewrites TXT or SRV data. | Same. | Same. |
| I | The advertisement reveals a device or user name, or lets someone track the PC over time. | Random instance and host names rotated at start, on network change and daily; hints keyed by a **per-link secret** in fixed slots, so neither a prober nor a former phone can link advertisements, and the number of phones is hidden (P 4.2, KT-24). | The presence of "a Kiwi Transfer PC", its port and its MAC address are visible on the link and link the rotations there (R7). |
| I | The PC announces itself on networks where it does not listen (Domain, VPN, a Public network that was not enabled). | The responder runs only on eligible interfaces and stops when there is none (P 4.5, KT-18). | None. |
| I | The phone reveals itself. | It never advertises and never listens. Its browse queries show interest in the service type; probing on foreign networks is spaced out (P 4.3). | T1 learns "a phone here uses Kiwi Transfer". |
| D | mDNS blocked (guest network isolation). | Cached address; QR as a candidate source; the core's own query on tethering interfaces; a troubleshooting screen. | The feature does not work on isolating networks. |
| E | The listener is exposed on a public network (cafe, airport). | Not by default: a Public network is used only after the PC user enabled **that** network; then pinned peers and QR pairing only, no SAS pairing, no `pm`, on-link sources, hop limit 1, Retry (P 4.4, P 5.9). Domain networks never. | **R25**: on an enabled Public network, strangers on that link can reach the pre-authentication surface and read the PC's certificate. |

### C5. Weekly re-confirmation

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T5 keeps a stolen phone useful by guessing the 2-digit code. | A code exists only while a person at the PC asked for it by a click; 3 attempts; a new code needs a click at the PC; failures are displayed there; lockout (P 3.4). | 3 % per armed challenge (R11). |
| T | Roll the clock back to avoid expiry. | Link clock: monotonic, the larger of both devices, anomaly flag, epoch counters, boot id not taken from the wall clock (P 3.2, P 3.3). | Both devices manipulated by their owner. |
| T | Send a huge age or epoch to wrap the stored state into "confirmed". | No wrapping arithmetic; a durable `need_confirm` flag that only a correct code clears (KT-01). | None. |
| T | A code for phone A is used for phone B. | Challenges are per link (P 3.6). | None. |
| T | State that can never be confirmed again (PC restored to an older epoch). | `new_epoch = max(both) + 1`, and the phone sets it (KT-08). | None. |
| R | - | Confirmations are recorded locally with the epoch. | - |
| I | The code is seen by T6. | It is not a secret (P 3.1); it expires in 5 minutes and is useless without the paired phone. | Accepted. |
| D | The user is away for more than 7 days. | **Backup copying continues** (owner decision); only final move, purges, browse/restore, PC-to-phone delivery and clipboard wait; nothing is deleted (P 3.5). | Free-up-space waits until the user returns. |
| E | A paused request class is served anyway while the link is `REQUIRED`. | One table of paused classes; each is refused with `E_CONFIRM_REQUIRED`; tests for every class (P 3.5, P 11.3). | Implementation error caught by tests. |
| E | A holder of a copied phone key uses the open classes while `REQUIRED`. | Open classes only add files to that phone's own folder within its quota, or report state. Nothing can be read out, and nothing on the phone is removed. | Disk space up to the quota (C7). |

### C6. Control protocol: parser, limits, state

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | T3 sends malformed or ambiguous encodings to confuse hashes or signatures. | Strict CBOR profile with the canonical form **enforced**; hashes over received bytes (P 5.2). | None. |
| T | T3 sends messages out of order or for inactive capabilities. | `E_STATE`, `E_UNSUPPORTED`; unknown values read as "failed", never as "delete" (P 5.4, P 11.1). | None. |
| T | A forged or mismatching receipt makes the phone believe an item is stored. | Receipts are validated against what the phone itself sent; a receipt never deletes anything by itself (P 6.5 rule 6, P 8.1 I3). | None. |
| I | Error details leak names or paths into logs or reports. | `ERROR.detail` rule; typed logging (P 5.8, P 10.2). | None. |
| D | Huge frames, deep nesting, thousands of requests, too many streams; a header that announces 2^64 elements; sizes that overflow. | Frame cap checked before reading, depth 8, 32 outstanding requests, stream and rate limits, no allocation from a declared size, one range table (P 5.2, P 5.7). | None. |
| E | Memory-safety bug in the parser. | The parser and all protocol logic are in safe Rust; fuzzing of the frame decoder is a release gate. | Bugs in unsafe code of dependencies (R16). |

### C7. Receiving files on the PC (names, paths, commit, quota)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | T3 writes outside the destination: `..`, absolute paths, drive letters, device names, alternate data streams, trailing dots and spaces. | Components as an array; reject and clean rules; reserved-name rule; extended-length paths built only by the receiver (P 6.8). | None. |
| T | T3 writes into the store's own files (temporary files, marker) so that the PC's clean-up later deletes a real file. | Names beginning with `.kiwi-` are reserved at every level; the PC deletes only its own journaled temporary files; a lost rename is recognised by hash before anything is deleted (P 6.8 rule 8, P 7, KT-13). | None. |
| T | A junction or symbolic link placed inside the destination redirects writes (for example into the Startup folder). | No reparse point is followed below the root; resolved path compared component by component (P 6.8 rule 12). | T7 can do anything anyway (R1). |
| T | T3 overwrites or replaces an existing file, including by a case or normalisation collision. | Create-new rename only; suffix policy (P 6.9). | None. |
| T | Data corrupted between network and disk, or by the disk; a rename undone by a power failure. | Chunk hashes, whole-file hash, flush, unbuffered re-read, flush of the new name before the ledger commit, weekly scan (P 6.4, P 7, P 8.9). | Drive caches (R6). |
| T | **Another Windows account**, or a cleaning feature, deletes or changes stored files. | For final move the folder must be writable only by this account, SYSTEM and Administrators, and must not be in Downloads, a temporary folder or a Storage Sense target; otherwise the destination is copy-only (P 8.2 rules 7, 8, KT-14). | Administrators of the PC; R14. |
| R | - | Ledger records every commit with session number. | - |
| I | Files are stored in a cloud-synchronised folder and uploaded by a sync client. | Detected: lasting warning on both devices for copy, refusal for final move, never proposed as the default (P 8.2 rule 4). | The user chooses such a folder anyway and ignores the warning. |
| I | **Stored files are readable by anyone who can use the Windows account or hold the disk.** | By decision there is no encryption, password or lock (P 9.7). The folder is created owner-only; Windows disk encryption is the user's own choice. | **R22, R24, R27.** |
| I | One phone learns what another phone stored (a `have` answer for content only the other phone uploaded). | Every answer comes from the asking link's records only; no cross-phone deduplication (P 6.3 rules 1, 2). | None. |
| D | T3 fills the disk. | Reserve rule, per-phone quota, declared-size enforcement, temporary-file expiry (P 5.10). | Up to the reserve, or the quota if one is set. |
| E | A received file is executed or opened automatically. | The program never opens, previews or runs received content (P 6.6). | The user opens a hostile file themselves. |
| E | **Explorer acts on a received file when the folder is merely displayed** (`.lnk`, `.url`, `.scf`, `.library-ms`, `desktop.ini`, a `.{GUID}` name): icon or target resolution contacts an attacker's server and discloses the user's Windows credential hash. | Such names are stored with the suffix `.kiwi-blocked`; the program registers no handler for it and never sets the attributes that activate `desktop.ini`; files sent with purpose 2 carry the Mark-of-the-Web (P 6.8 rules 9, 13, KT-17). | A shell-parsed type that is not yet on the list (the list can grow in a minor version). |

### C8. Receiving files on the phone (send, fetch, restore)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Files arrive that the user did not ask for. | Accept dialog for every PC-to-phone offer; fetch and restore only on the phone user's request (P 9.1). "Always accept from this PC" is off by default, per PC, and reset on re-pairing. | With "always accept" on, a compromised PC can place files on the phone without a dialog: R30. |
| T | A hostile name hides a folder (`.nomedia`), escapes the folder, or overwrites a file. | Leading-dot rule, base folder chosen by the phone, cleaning, create-new, MediaStore read-back (P 6.8 rules 14-18, P 6.9). | None. |
| T | A file is placed in the gallery although it is not a picture, to look trustworthy. | Gallery placement is decided by the phone from the cleaned extension against a fixed list, never from the peer's `mime` (P 9.1 rule 5). | A file with a picture extension and other content: the gallery shows a broken thumbnail. |
| T | Corrupted content. | Chunk hashes, re-read and hash before publishing (P 9.1). | None. |
| I | A notification shows file names on the lock screen. | Notifications use private visibility and counts, not names. | None. |
| D | The PC fills the phone. | Free-space floor; accept dialog shows sizes; the floor also holds with "always accept". | None. |
| E | A received APK is installed, or a file is opened without a tap. | Never auto-open; the app does not hold the install permission and never starts an installation (P 9.1 rule 7, P 9.6). | The user installs it deliberately: R28. |

### C9. Final move

Deletion logic is analysed in depth in section 5; the STRIDE view:

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Someone other than the real PC tells the phone "I have your files". | Pinned TLS; weekly check; and the phone decides from a keyed proof it recomputes itself (P 8.5). | T7 on the PC (R1), without gaining the ability to make the phone delete what the PC does not hold. |
| S | **Another phone's copy** of the same photo stands in for this phone's copy. | Invariant I8: the proof is read from a file that a record of this link names, inside this phone's folder; other links' records are never consulted (P 8.1, P 8.5). | None. |
| T | A stale or wrong ledger says a file is present; a restored (older) ledger forgets files. | The ledger is never trusted for deletion; proof over the real bytes with a fresh nonce; rollback detected by `commit_hwm` / `receipt_hwm`; weekly audit of copy-mode items (P 8.1 I3, P 8.10, KT-02). | A copy-mode item whose PC copy vanished in a rollback is unprotected until the next session shows the rollback (at once) or the audit (within 7 days). |
| T | Another app (T8), or the user, changes the phone file between verification and trashing. On Android 11+ that interval includes the time Android's own dialog is open (minutes). | Validity checked when the dialog is launched; after the dialog every item is queried again and, where readable, hashed; a changed item is restored at once and excluded (P 8.6, KT-09). | R20. |
| T | Another app empties or alters the app trash folder or its index (API 24-29). | Shared storage cannot be protected. The index is untrusted and never an authority for deleting; purge decisions use the app's own database (P 8.6, KT-32). | R13. |
| T | A wrong wall clock makes Android's trash expire early or the keep-on-phone period end early. | Trashing is refused while the phone's and the PC's wall clocks disagree, or while wall time and link clock disagree since the receipt; warnings are scheduled from the link clock too (P 8.6 rule 2, KT-11). | A clock that jumps **after** trashing: R5. |
| R | "The app deleted my photos." | Journal of every batch with counts and times; history screen; system dialog on API 30+. | Local records. |
| I | The PC learns the phone's keep-on-phone period and item counts. | Sent inside the authenticated channel for display and reminders only (P 8.12 rule 9). | Readable on the PC by R1, R22. |
| D | T2 or T3 keeps final move from ever running. | Fail-safe direction: nothing is deleted; the phone stays full. | Accepted. |
| E | T3 (a compromised PC program) makes the phone delete everything. | The PC cannot command deletion (P 8.1 I6). It can only answer proofs, which requires holding the bytes. The PC user's own per-phone switch must also be on (P 8.2 rule 9). | A compromised PC that keeps the bytes until the phone copy is gone and then destroys them (R1, R3). |
| E | A compromised PC uses `REPAIR_REQUEST` to pull files it never received, or to test whether the phone holds a known file. | The phone answers only for (key, hash) pairs of its own ledger for that link; rate limit; visible notice (P 8.9 rule 5b, KT-16). | None. |

### C10. Ledgers and journals

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | Corruption or loss of a ledger. | Integrity check at start; loss is detected through `ledger_id`; all receipts become void and purges stop; trashed items are re-anchored before any purge (P 7, P 8.7, P 8.10). | None for deletion safety. |
| T | **Rollback**: an older copy of the ledger (system image, snapshot, file backup, or the ledger backup on a second disk) with the same identity and `ledger_id`. | High-water marks on both sides; a restored ledger gets a new `ledger_id` when the program can tell; alert for trashed items (P 8.10, KT-02). | R26. |
| T | T7 edits the PC ledger. | Not preventable. Deletion on the phone still needs the real bytes (P 8.5). | R1. |
| T | Unpairing erases the PC's knowledge of which files are sole copies. | Unpairing removes the pin and session state only; records, marks, scans and the expiry watch stay (P 2.7, KT-07). | None. |
| D | Ledger on a failing system disk. | Loss handling as above; files are untouched. | Re-indexing time. |
| I | Ledger contains file names, hashes, original names and dates. | Stored in per-user application data; never in logs or reports. | Readable by the same user (R1) and on a ledger backup on a second disk (R27). |

### C11. Clipboard

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Text appears to come from the user's device. | Authenticated, `CONFIRMED` session only; shown with the peer's name. | None. |
| T | A link that opens something dangerous (`intent:`, `file:`, look-alike host). | Never auto-open; only `http`/`https`; full URL and punycode shown; a tap is required (P 9.2). | The user opens a phishing link deliberately. |
| I | Passwords leak into notification previews, clipboard history or cloud clipboard. | Manual send only; sensitive flag honoured on both platforms; no logging of content (P 9.2). | Text the user forgot to mark and that the source did not mark. |
| D | Clipboard spam from T3. | One per second; the user can disable the capability. | None. |
| E | Received text is written to the clipboard without consent and pasted by the user elsewhere. | Copy needs a tap (P 9.2 rule 3). | None. |

### C12. Browsing the PC, thumbnails, fetch, restore

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A new phone claims an old phone's backup. | Handing a namespace over to a new link is done by a person at the PC, and only for a namespace that no live link uses (P 9.4). | T6 or T11 at the unlocked PC. |
| T | T3 (a stolen phone identity) modifies or deletes PC files through browsing. | Read-only by construction: no such message exists (P 9.3). | None. |
| I | T3 reads PC folders the user did not share (traversal, links, hidden files). | Chosen roots only; opaque handles; reparse points, hidden and system entries omitted (P 9.3). | Everything inside this phone's own namespace and its shared folders is readable by this paired, confirmed phone: T5 with an unlocked phone (R2). |
| I | **One phone browses or restores another phone's backup** (a child's phone reading a parent's photos). | Roots are the phone's own namespace, an inherited namespace, and shared folders that may not overlap any namespace; no handle or message reaches another namespace (P 9.3 rule 1). | The PC user hands a namespace over on purpose; and everyone at the PC can read every folder anyway (R22). |
| I | Thumbnails leak location metadata. | Thumbnails are re-encoded without metadata. | None. |
| D | Thumbnail generation exhausts the PC. | Size, pixel, time and concurrency limits; rate limits; job object on the helper (P 9.3, P 5.7). | None. |
| E | **A crafted image that a phone uploaded attacks the Windows codecs when its thumbnail is made** (a holder of a phone key can upload the file and then ask for the thumbnail). A crafted thumbnail attacks the phone's decoder. | Decoding only in a restricted helper process without network or file access; header checks before decoding on both sides; no thumbnails at all if the helper cannot be restricted (P 9.3 rule 5, KT-15). | R18. |

### C13. Update check, release keys and problem report

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A fake release is offered (GitHub account taken over, or TLS interception). | Manifest signed by a release key of the trusted set, with a fixed prefix so that no other signature can be reused; hash and size per asset; Android signature check by the system (P 10.1, P 10.4). | Theft of a release key (R12). |
| S | **A stolen release key is used for ever.** | Keys have ids; a manifest signed by the other key revokes it; revocations are stored for ever on each installation; keys are held offline under K1-K8 (P 10.4, KT-03). | Revocation reaches a program only when it sees the manifest; an attacker who also controls the download can show its own first (R12). |
| T | Downgrade to an old vulnerable version; replay of an older manifest for a version later declared bad. | Version must be greater than the installed one; manifest sequence number; `min_supported` (P 10.4). | A program that never saw the newer manifest can still be offered an older genuine release. |
| T | First download is replaced. | HTTPS from GitHub; published manifest, public keys and provenance for manual checks. | No in-app check is possible for a first install; no Authenticode on Windows (R12). |
| T | The verified installer is swapped before it runs. | Kept in a folder only this account can write; hashed again from the open handle before start (P 10.1). | Same-user malware (R1). |
| I | The check identifies the user or the device. | Constant User-Agent, no identifiers, no parameters; can be turned off (P 10.1). | GitHub sees the IP address (R17); Windows may contact certificate-status servers for that connection (P 10.3 row 5). |
| I | A report leaks private data. | Allow-list of fields; shown in full first; sent by the user's own mail program (P 10.2). | What the user types into the free-text box. |
| D | GitHub unreachable; all release keys lost. | The check fails silently; nothing else depends on it. Lost keys: a manually installed build with new keys, announced on the site. | Users must act by hand. |
| E | The updater runs an unverified installer. | Verification before execution; no "install anyway". | None. |

### C14. User interfaces and inter-process surfaces

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | An overlay on the phone covers the final-move switch, the "PC said correct" question, an accept dialog or the restore confirmation (tapjacking). | Sensitive buttons ignore touches while the window is obscured; the system trash dialog is drawn by Android. | Old Android versions with weaker overlay rules. |
| T | Script injection into the PC window through a device name, file name or clipboard text. | WebView2 loads only local files; every other request refused; peer strings are set as text, never as HTML; content security policy without inline script; a narrow, typed host interface (P 5.8, P 9.5). | None known. |
| T | Another app shares a URI that points into the Kiwi app's own private files, so that "Send to PC" exfiltrates them. | Shared URIs are read only through the content resolver with the caller's grant; `file:` URIs and URIs that resolve to the app's own private directories or its own provider are refused. | None. |
| T | The Explorer entry "Send to phone" is used by another program to make the PC send files. | It only queues files of the user's own account for the user's own phones; the phone still asks before accepting (unless "always accept"). | Same-user malware could do this anyway (R1). |
| I | The weekly code or the QR is captured by T7 from the screen. | Not preventable for same-user malware (R1). The QR is useless after use; the pairing number is never on the PC screen. | R1. |
| D | Dialog flooding to train the user to accept. | Pairing needs a typed number inside a window the user opened; accept dialogs only from paired, confirmed PCs; rate limits. | Fatigue with a compromised paired PC. |
| E | An exported component is driven by another app. | Exported: the launcher activity and the share target only. No exported service, receiver or provider; immutable pending intents; no deep links (P 2.2). | None. |

### C15. Second copy on a second disk

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A different disk with the same drive letter is taken for the second disk. | The disk is recognised by its marker, not by its letter (P 8.13 rule 3). | None. |
| T | A damaged primary file is copied to the second disk and then counts as "two copies". | The source read must give the ledger's hash before anything is published; the copy is read back and compared (P 8.13 rule 4). | None. |
| T | Self-repair overwrites a file the user edited on purpose, or deletes "the bad one". | A repair never overwrites and never deletes: the repaired copy gets a free name and the other file stays (P 8.13 rule 8, I7). | The user sees two files and must choose. |
| T | The last writes to an external disk are lost because it was pulled out. | The files written during the previous connection are read back at the next one (P 8.13 rule 5). | Until then they are counted as two copies although one may be incomplete. |
| T | A second copy makes final move easier or is used for a proof. | Proofs are always read from the primary file; no rule of P 8.4-8.7 depends on a second copy (P 8.13 rule 2). | None. |
| R | - | Ledger records per disk what was copied and verified. | - |
| I | **A second disk is plain files.** It may be stored elsewhere, lent, lost or stolen. | None by design (P 9.7). | **R27.** |
| D | The second disk is never connected, so the second copy never exists. | Escalating reminders on the PC, tied to the trash expiry of the affected files; warnings on the phone at 7 and 2 days (P 8.13 rules 6, 11). | **R23**: final move does not wait. |
| D | A failing second disk stops everything. | It blocks final moves only; copying to the primary continues; an absent disk blocks nothing (P 8.13 rule 9). | None. |
| E | The second-disk folder is used to reach another location (junction, share, sync folder). | Local disk only, a different physical device, no network or sync folder, same reparse rules as the primary (P 8.13 rule 3). | None. |

### C16. Data sets beyond media (contacts, calendars, files, app list, APK files, WhatsApp backup)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A compromised PC returns altered contacts or calendar entries at restore. | Restore is started by the phone's user, shows what will be added, and is add-only: nothing existing is changed or deleted; calendar events go into a new local calendar that can be removed in one step (P 9.6). | Added entries with false content (a wrong number under a familiar name). |
| T | A phone sends a crafted vCard, calendar or manifest to attack a parser on the PC. | The PC never parses them: they are opaque files (P 9.6). | None on the PC. |
| T | A compromised PC sends a crafted vCard or calendar to attack the phone's parser at restore. | Parsed in the app's sandbox by memory-safe code, with size limits; fuzzing of these parsers is a release gate. | Logic bugs in the parser. |
| T | The app deletes or overwrites contacts, events, or another app's files. | There is no code path that deletes a contact or an event; write access is requested only for a restore; files in another app's folder are created new, never replaced (P 9.6). | None. |
| T | A planted APK among the restored files gets installed. | APK files are saved only; the app holds no install permission and starts no installation; Android's installer and its prompts decide (P 9.6). | The user installs a file a compromised PC altered: R28. |
| R | - | Snapshots carry their time; nothing on the PC is overwritten. | - |
| I | **The address book, the calendars and the app list lie on the PC in plain form**, including personal data of other people. | By decision (P 9.7). Each data set is off until the user turns it on; the folder is owner-only; nothing of it goes into logs or reports. | **R24.** |
| I | The app list reveals which apps the user has (health, banking, dating). | Same as above; user apps only; no account names or device identifiers in the manifest. | R24. |
| I | SMS and call log are collected. | Not collected: the app requests neither permission (P 9.6). | None. |
| D | Snapshots accumulate on the PC. | At most one per day and only on change; WhatsApp's database at most once a week by default. The PC user removes old versions by hand. | Disk space over the years (open question N3). |
| E | The broad permissions needed (all-files access, contacts, calendar, app list) are abused by a compromised app build. | Requested only when the data set is turned on; reproducible builds; the update channel of C13. | A compromised build has these permissions: R12, R16. |

---

## 5. Data-loss analysis for final move

Final move is the only feature that removes user data. This section asks one question: **by what paths can
the last copy of an item be destroyed, and what stands in each path?** It applies to media items only:
no other item kind is ever removed from the phone, and contacts and calendar entries are never deleted by
this app at all (P 8.1, P 9.6).

### 5.1 Where the copies are

| Phone state (P 8.3) | Copy on the phone | Copies on the PC | Copies in total | A single fault loses data? |
|---|---|---|---|---|
| `LOCAL`, `SENT` | Original | None, or unverified | 1 | Only the phone's own failure, as before the app existed. |
| `COMMITTED` | Original | Verified once from disk (plus a second disk, when it has caught up) | 2 or 3 | No. |
| `VERIFYING`, `VERIFIED` | Original | Verified twice | 2 or 3 | No. |
| `TRASHED` | In a trash (recoverable) | Verified twice | 2 or 3, one with an expiry | No, while the trash lasts. |
| `GONE`, second copy exists | None | Primary and a second disk | 2 | No. |
| `GONE`, **one PC copy** | None | Primary only | **1** | **Yes: the PC's primary disk.** |

The design goal is therefore: **the app never moves an item from 2 copies to 1 copy on wrong information,
and never from 1 copy to 0.** After `GONE` the PC is, by the user's explicit choice, the only store; with
a second disk it is a two-copy store once that disk has caught up, and a one-copy store until then (the
**one-copy window**, R23).

### 5.2 Layers

| Layer | What it catches | Reference |
|---|---|---|
| L1 | Per-chunk hash: corruption in memory or transit; change of the source between sessions | P 6.4, P 6.7 |
| L2 | Whole-file hash computed in the same pass that streams the bytes; size and time re-check after sending | P 6.5 |
| L3 | Flush, then unbuffered re-read from disk before the receipt | P 7 |
| L4 | Create-new atomic rename made durable; the PC never modifies committed files and deletes only its own journaled temporary files | P 6.9, P 7, P 8.1 I7 |
| L5 | Durable ledger; receipt only after the ledger commit; confirmations never batched | P 7, P 8.5 |
| L6 | Destination must be a fixed, internal, non-hot-pluggable NTFS/ReFS disk on an allow-listed bus, not a share, not cloud-synchronised, not in Downloads or a temporary folder, writable only by the owner | P 8.2 |
| L7 | Copy-only classes on the phone (SAF, SD card, app-owned folders, redacted items, every non-media kind) | P 8.2 |
| L8 | Delay of 24 hours, in a later session, measured on both devices' link clocks and by the store's own rule | P 8.2, P 8.5 |
| L9 | Second verification: fresh nonce, keyed proof over the real bytes on both sides, compared by the phone | P 8.5 |
| L10 | Metadata re-check before, after and immediately before trashing; **re-check and re-hash after Android's dialog** | P 8.5, P 8.6 |
| L11 | Journal before action, outcome read back from the system; an item that vanished is recorded, not assumed in place | P 8.1 I5, P 8.6 |
| L12 | Trash instead of deletion; 30-day undo | P 8.6 |
| L13 | Third verification before purge, with the PC's clock as a second witness (API 24-29); warnings 7 and 2 days before system expiry, scheduled from the link clock too, from the phone **and from the PC** (API 30+) | P 8.7, P 8.6, P 8.10 |
| L14 | Weekly integrity scan of every file, linked or unlinked, on every connected disk; any problem blocks final moves for every phone of that PC | P 8.9 |
| L15 | Weekly presence check; expiry stops verification, trashing and purging (not copying) | P 3.5 |
| L16 | Final move off by default; per-folder opt-in on the phone with an explicit acknowledgement; per-phone opt-in on the PC; system dialog per batch on API 30+ | P 8.1, P 8.2, P 8.6 |
| L17 | **Per-device proof**: only a file recorded for this phone, in this phone's folder, can answer | P 8.1 I8 |
| L18 | **Clocks must agree** before anything is trashed or purged | P 8.6 rule 2 |
| L19 | **Rollback detection** by high-water marks; weekly audit of copy-mode items; re-anchor before any purge after a ledger change | P 8.10, P 8.7 |
| L20 | **Keep-on-phone period**: an item stays in place for the time the user chose (default one month) after it was copied, which is also time for the second copy and for two or more weekly scans | P 8.12 |
| L21 | **Second copy with self-repair**; a failing disk blocks final moves | P 8.13 |
| L22 | `hold`: a trashed item whose check failed is never purged automatically | P 8.7 |

### 5.3 Paths to loss

"Loss" needs both: the phone copy gone **and** every PC copy gone or wrong.

| # | Path | What must fail | Assessment |
|---|---|---|---|
| 1 | The phone trashes an item although the PC copy is wrong or absent. | L9: the PC must produce `MAC(K_v, content)` for a fresh key without having the content. | Not feasible without breaking BLAKE3. A stale ledger, a cached hash or a replayed answer cannot pass. Even then L12 leaves 30 days. |
| 2 | The phone trashes a different file than the one verified (changed in place, identifier reused), in particular while Android's dialog is open. | L10 and L11. | Caught after the dialog where the item is readable: restore is requested at once. Where it is not readable, a change that keeps size and modification time leads to the *new* content being trashed; it stays recoverable for the trash period (R20). |
| 3 | The PC copy is damaged or lost **while the item is in the trash**. | L14 or L13 must fail to notice in time, and the user must not restore; with a second disk, L21 must fail too. | API 24-29: purge needs a third proof, so the item stays in the trash indefinitely (`hold`): **no loss**. API 30+: Android deletes at expiry regardless; loss only if the damage happens and is not acted on within the remaining days (case A, R5). |
| 4 | The PC copy is lost **after the phone copy is gone** (disk failure, ransomware, the user deletes the folder, Windows reinstalled over the data). | With one PC copy: nothing can stand here. With a second copy: both disks must be lost, or the second not yet written (path 16). | **Loss** when there is one copy. The scan detects it afterwards. This is the residual risk of the feature itself (R3, R4). |
| 5 | A crash or power loss at any step. | L4, L5, L11. | Every interrupted step resolves to the earlier state (P 8.11 rows 5, 10, 13, 24, 34, 42). **No loss.** |
| 6 | A wrong clock makes things happen early. | L8 and L13 use two devices' monotonic clocks; L18 refuses to trash while the wall clocks disagree. | The app's own delays cannot be shortened by one wrong clock. What remains is Android's trash, which expires by the phone's wall clock: a forward jump **after** trashing can empty it early (case A, R5). |
| 7 | T2 on the network. | TLS. | Can only block; blocking stops deletion. **No loss.** |
| 8 | T3 as a compromised PC program, or T7 on the PC. | - | It can pass L9 honestly (it has the bytes) and destroy them after the phone copy is gone: the same as path 4. It cannot shorten the path: the phone trashes only what the PC really holds at that moment. No amplification beyond "malware on your PC can delete files on your PC" (R1). |
| 9 | T3 as a compromised phone app, or T5 with the unlocked phone. | - | It can delete the phone's files directly; the app adds nothing. PC copies are unaffected (no delete message exists). |
| 10 | Another phone app or the user empties the trash early, and then path 3 or 4 happens. | Two independent events. | Double fault. |
| 11 | Android strips location data and the stripped copy is treated as the original. | L7 (`redacted` items are never eligible). | **No loss of metadata.** |
| 12 | The destination silently changes character: an external or hot-pluggable disk, a share, a folder taken over by a sync client or by Storage Sense. | L6, re-evaluated at every session and verification; volume identity and marker check. | A sync client that starts after the phone copy is gone is path 4. |
| 13 | Identity or ledger loss on either device (reinstall, reset, unpairing). | `ledger_id`, pins; unlinked namespaces keep their records and marks. | Receipts void, purges stop, restore offered (P 8.10). **No loss by the app.** On API 30+ the system trash keeps running (path 3); the PC keeps the expiry watch and warns its user. |
| 14 | An implementation bug in the state machine. | L11, L12, L20; every row of P 8.11 is a fault-injection test; the feature is off by default on both devices. | The honest residual of any software (H6). The trash gives 30 days to notice. |
| 15 | **Ledger rollback** (H7): the PC is restored to an older state; files committed since are gone from the PC, while the phone holds receipts for them and may already have trashed them. | L19. | Detected at the next session start by both sides. Items in place are sent again. Items in a trash: alert with one-tap restore at once; on API 24-29 they cannot be purged (`hold`, re-anchor); on API 30+ the user has the remaining days (case A). Until the phone next meets the PC nothing is detected, but nothing new is trashed either. |
| 16 | **One-copy window**: the primary disk fails after the phone copy is gone and before the second disk received the file. | L20 (time for the disk to be connected), the reminders and warnings of P 8.13. | **Loss** if the second disk was never connected in that time. By owner decision final move does not wait for it (R23). |
| 17 | **Another phone's file answers** for this phone's item, and that file later disappears with the other phone's folder. | L17. | Not possible: other links' records are never read. |
| 18 | **The PC's own clean-up deletes a committed file** (a temporary-looking name, an adopted partial file, a rename lost after the receipt). | L4: reserved names, journaled temporary files, durable rename before the ledger commit, hash check before any temporary file is deleted. | **No loss** (KT-13). |
| 19 | **Another Windows account, Storage Sense or a cleaner removes sole copies.** | L6 (rules 7 and 8), L14. | Such a destination is copy-only, so no sole copies arise there. If permissions change later: detected at the next evaluation; files already gone from the phone are path 4. |
| 20 | Self-repair or rebuild writes wrong bytes over good ones. | A repair writes a new file, verified against the ledger hash, and never overwrites or deletes (P 8.13 rules 8, 10). | **No loss.** |
| 21 | Contacts or calendar entries are lost through a backup or a restore. | The app has no deleting code path for them; restore is add-only (P 9.6). | **No loss.** |

### 5.4 Conclusions

1. Before `GONE`, no single fault and no single wrong component leads to loss. On API 24-29 not even a
   long absence of the PC does: the trash simply keeps the item.
2. On API 30+ one gap cannot be closed by an app: the system empties its trash on its own schedule and by
   its own clock. The app refuses to trash while clocks disagree, warns from two clocks and from both
   devices, and offers a one-tap restore; it cannot hold the item. Stated to the user where final move is
   enabled.
3. After `GONE`, the PC is the only store. With one disk that is a single copy; **the second disk is the
   only real mitigation**, and it helps only once it has actually received the file. Final move does not
   wait for it (owner decision), so the product has to make the one-copy state visible on both devices and
   to remind before the trash lets go.
4. Consequences for the product: final move stays off by default on both devices; its explanation screen
   names the "only copy" plainly and asks for a second disk; the phone always shows how many of its files
   have one and two copies; the PC shows which files are sole copies, and for which phone, also after that
   phone was unpaired; a problem found by the scan is shown with where another copy still exists and how
   many days remain.

---

## 6. Residual risks

Stated plainly. None of these is hidden behind "secure" wording in the product.

| Id | Risk | Why it remains | What limits it |
|---|---|---|---|
| **R1** | **Malware running as the user on the PC** can read every backed-up file, obtain the PC identity key through DPAPI and impersonate the PC to the paired phones (receiving later backups), read or alter the ledger and the pin store, read the weekly code and the QR from the screen, type into the program, and delete or alter the copies on every connected disk. | Windows gives all programs of one user the same rights. A user-mode program cannot defend itself against its peers; pretending otherwise would be dishonest. | The program adds no new power to such malware: it runs unelevated, executes nothing it receives, and cannot be used to make the phone delete what the PC does not hold. Damage to files is noticed by the weekly scan if the ledger survives; a disconnected second disk is out of its reach. After a clean-up: reset the identity (P 1.1 rule 6). |
| **R2** | **A stolen, unlocked phone** gives the thief the phone's files (without the app), and through the app, while on the same link as the PC: until the weekly check expires (at most 7 days) the phone's own backup on the PC and the folders shared with it, sending files to the PC, and the phone's side of final move; after that only uploading. | The app has no lock of its own in 1.0 and its key is not bound to user presence (background backup needs it). | The thief must be on the same link as the PC; the weekly code needs sight of the PC screen and a click there; the user can unpair the phone at the PC at once; browsing is read-only and never reaches another phone's folder. A locked phone's app data is encrypted by Android. |
| **R3** | **Ransomware on the PC** encrypts or deletes the destination. Items already gone from the phone are lost unless a second disk that was not connected at that time holds them. | After final move the PC holds the only copies. | The weekly scan and every verification detect the change and block further final moves on all phones; items still in a phone trash can be restored or re-sent ("repair"); an external second disk that is connected only now and then is the real protection. |
| R4 | **The PC disk fails** after the phone copy is gone. | Same as R3. | A second copy; the scan gives early warning of a failing disk and blocks final moves. |
| R5 | **Android 11+ system trash expires** while the PC copy could not be re-checked (PC off, user away, phone off), or **expires early because the phone's wall clock jumped forward** after trashing. | The operating system owns that trash and runs it by the wall clock. | Two disk verifications happened before trashing; trashing is refused while the clocks disagree; warnings 7 and 2 days before expiry by wall clock and link clock, on the phone and on the PC, with one-tap restore. |
| R6 | A **drive acknowledges a flush** it has not completed, then loses power. | Firmware behaviour is outside software control. | The 24 h delayed re-read from disk, the keep-on-phone period, the weekly scan, and the hash check that recognises a lost rename. |
| R7 | The **PC's public key and presence are visible** to any host on a link the PC listens on: a prober can recognise the same PC on another network, and mDNS shows that a Kiwi Transfer PC exists and on which port. On one link the PC's MAC address and its stable port link its rotating names. | TLS 1.3 servers authenticate first; a service must be discoverable. | No names are exposed; hints are keyed per link; the phone's identity is never shown to an unpaired server in a normal connection; content stays encrypted. |
| R8 | **Traffic analysis**: sizes and timing reveal when backups run and roughly how much. | No padding or cover traffic. | Local link only. |
| R9 | **Recorded traffic and future quantum computers**: key exchange is X25519. | A hybrid post-quantum group needs a larger crypto library; not in 1.0 (decision D27). | The traffic never leaves the local link; an attacker must have been recording on that LAN. |
| R10 | **Pairing with someone else's phone.** A bystander photographs the QR, or an attacker on the LAN answers first. | The QR is on a screen; the SAS window is announced on the link. | They cannot complete the pairing without **typing their own number on the PC keyboard**, inside the window the user opened. What remains is a person who is both on the LAN and at the unlocked PC (T6, T11) while a pairing window is open. Every paired phone is listed in the PC program and can be unpaired at once. |
| R11 | **The weekly code has 100 values.** | Owner requirement (2 digits). | It is a presence check, armed only by a click at the PC, 3 attempts, failures displayed, lockout. |
| R12 | **Update and first-install authenticity.** Theft of a release key allows a malicious update until the key is revoked, and for longer on a program whose downloads the thief controls. The first download and the Windows installer carry no operating-system signature (no paid certificate), so users will see SmartScreen warnings. Loss of the Android signing key would force an uninstall. | Free tools only; a first install cannot verify itself; revocation needs the program to see a manifest. | Two keys held offline in two places under K1-K8; key ids, monotonic revocation, sequence numbers and `min_supported`; published hashes, keys and build provenance; Android enforces same-signer updates. |
| R13 | **Other phone apps with storage access** can alter or delete user files and, on Android 7-10, the app trash folder and its index. | Shared storage is shared. | Re-checks before every decision; the index is untrusted; the PC copy is unaffected. |
| R14 | **Other programs of the same Windows user, administrators, and (on a copy-only destination) other Windows accounts** can change or delete files in the destination. | Same as R1; and a folder the user chose may be open to other accounts. | For final move the folder must be owner-only (P 8.2 rule 8); changes are detected by the scan; final moves block. |
| R15 | **Denial of service on the LAN** (jamming, mDNS spoofing, floods within the limits). | Local attackers control the medium. | Backups are delayed; nothing is deleted while they cannot run. |
| R16 | **Dependencies**: quinn, rustls, ring, blake3, ed25519 code, SQLite, the CBOR codec, mdns-sd, rcgen, x509-parser, JNA, the QR decoder (C++), the vCard and iCalendar parsers, WebView2. A flaw there is a flaw here. | No project can audit all of its dependencies. | Pinned versions with a lock file, `cargo audit`/OSV checks in CI, minimal features, fuzzing of our own decoders, no parsing of peer data in C or C++ (the QR decoder sees camera frames only), no parsing of phone data on the PC beyond the protocol itself. |
| R17 | **GitHub learns the IP address** of a device that checks for updates. | An HTTPS request has a source address. | Constant request without identifiers; at most daily; can be switched off; absent in store builds. |
| R18 | **Image codecs**: thumbnails are produced by Windows components from files that a phone uploaded, and are decoded by Android's; a crafted image could attack them, and the holder of a phone key can choose that image. | Thumbnails need a decoder. | Decoding only in a restricted helper process (no network, no file access, memory and time limits) that is thrown away; header checks; no thumbnails when the helper cannot be restricted. A codec exploit gains a process that can do almost nothing. |
| R19 | **No app lock** on the phone app in 1.0. | Not in scope for 1.0. | See R2; the Android lock screen is the lock. |
| R20 | **Change of a phone file between verification and trashing.** On Android 7-10 the interval is milliseconds. **On Android 11+ it includes the time Android's own dialog is open**, which can be minutes. | Android offers no atomic "trash this exact content". | After the dialog every item is queried again and, where Android lets the app read a trashed item, hashed; a changed item is restored at once. Where it cannot be read, a change that keeps size and modification time goes unnoticed: the new content is in the trash, not deleted, for the trash period. |
| R21 | **Human error**: the user deletes or moves the PC backup folder, ignores an integrity alert, never connects the second disk, or answers a dialog without reading. | The user owns the files. | Sole copies are marked in the PC program; moved files are followed; missing files block final moves until acknowledged; reminders escalate. |
| **R22** | **The PC store is not encrypted and has no lock, and a household shares PCs.** Everyone who can use that Windows account (a shared family account is common), every administrator of the PC, and every program they run can open, copy, change or delete every phone's photos and files in Explorer. The weekly code and the per-phone folders do not prevent this: they separate phones on the wire, not people at the keyboard. | Owner decision (P 9.7): plain files, so that nothing is ever lost to a forgotten password. | The destination is created owner-only, so **other Windows accounts** without administrator rights are kept out; the product says plainly that the PC's files are as private as that Windows account; Windows disk encryption remains available to the user; one phone can never read another phone's folder **through the app**. |
| **R23** | **The one-copy window.** Between the moment an item leaves the phone's trash and the moment the second disk has received it, the file exists on one disk. If the second disk is external and rarely connected, the window can be weeks. | Owner decision: final move does not wait for the second copy. | The keep-on-phone period (default one month) and the 30-day trash give the second disk two months in the default case; the phone shows one-copy counts permanently and warns 7 and 2 days before the trash lets go; the PC reminds with rising urgency as that date approaches. See open question N1. |
| **R24** | **Contacts, calendars, the app list and WhatsApp's backup lie on the PC in plain form.** They contain personal data of other people (names, numbers, addresses, appointments) and sensitive facts about the user (which apps are installed). Everyone covered by R22 and R27 can read them; a vCard file opens with a double click. | Same decision as R22; and vCard and iCalendar are chosen precisely because any program can read them. | Each data set is off until the user turns it on; nothing of it enters logs or reports; SMS and call log are not collected at all; WhatsApp's database stays encrypted by WhatsApp. |
| R25 | **Public networks the user enabled.** On such a network (a cafe, a hotel, a friend's Wi-Fi, a phone hotspot is the harmless case) every host on the link can send packets to the PC's listener, start handshakes and read the PC's certificate, and so recognise this PC again elsewhere. | Windows marks most networks Public, and the product must work on a hotspot without administrator rights. | Off by default and enabled per network; no SAS pairing and no `pm` there; on-link sources only, hop limit 1, Retry, handshake limits; authentication does not depend on the network. |
| R26 | **A restored PC** (system image, snapshot, file backup): files copied since the image are gone from the PC although the phone holds receipts. | A restore is a legitimate action that software cannot forbid. | Detected by the counters at the next session; copy-mode items are sent again; trashed items raise an immediate alert with restore; the weekly audit covers what the counters cannot. Until the phone and the PC next meet, nothing is detected. |
| R27 | **A second disk outside the house** (kept at work, lent, lost, stolen), or a discarded or repaired PC, is readable by whoever holds it: all files, all contacts, and the ledger backup with names and dates. | Second copies are plain files by the same decision. | Windows disk encryption (BitLocker To Go) if the user turns it on; the program states this when a second disk is added. |
| R28 | **APK files restored from the PC** may have been altered there (R1). If the user installs one by hand, Android's signature check protects an *update* of an installed app but not a fresh installation. | The app saves APK files as the user asked; it cannot vouch for them later. | The app never installs and says at restore that these files are as trustworthy as the PC they come from; where the app is still installed, Android refuses an APK with another signer. |
| R29 | **Pairing without a camera** shows the phone's long-term public key to the host that answered, before anything is verified. | TLS needs a client certificate, and in this method the phone has no pin yet. | No name is sent; Private networks only; only inside a window the user opened; the key alone gives no access. |
| R30 | **"Always accept from this PC"** lets that PC place files on the phone without a dialog. | It is the convenience the owner asked for. | Off by default, per PC, reset on re-pairing; only while `CONFIRMED`; nothing is ever opened or installed; free-space floor; a notification after every delivery. |

---

## 7. OWASP MASVS checklist

MASVS 2.x replaced the levels L1/L2/R of MASVS 1.x by control groups, tested at profiles (MAS-L1, MAS-L2,
MAS-R). This checklist lists every MASVS 2 control, read at the **L1** profile, with the MASVS 1.x category
in brackets. It applies to the Android app; the last column notes the Windows program where the same idea
applies. Status: **D** = satisfied by design in `PROTOCOL.md`, to be confirmed by test; **V** = needs
verification on real devices; **X** = deliberate deviation, explained; **n/a** = not applicable at L1.

| Control | Requirement (short) | How Kiwi Transfer meets it | Status | Windows program |
|---|---|---|---|---|
| MASVS-STORAGE-1 [V2 Data storage] | Sensitive data is stored securely. | Identity seed wrapped by a hardware-backed Keystore AES-GCM key; pins, discovery keys, ledger and journal in app-private, credential-encrypted storage; snapshots of contacts and calendars are built in app-private storage and removed after they were sent; nothing sensitive on shared storage except the user's own files and the visible trash folder (P 1.6, P 8.6, P 9.6). | D | Identity: DPAPI CurrentUser. **Stored user files: plain, by decision (X; R22, R24, R27).** |
| MASVS-STORAGE-2 [V2] | Sensitive data does not leak. | `allowBackup=false` plus extraction rules; typed logging without names; no crash reporter; notifications without file names; sensitive clipboard handling; thumbnails only in the cache directory (P 1.6, P 9.2, P 10.2). | D | Same logging rules; per-user data directory; owner-only destination folder. |
| MASVS-CRYPTO-1 [V3 Cryptography] | Strong, current cryptography used correctly. | TLS 1.3 only; Ed25519 with strict verification; X25519; AES-GCM/ChaCha20-Poly1305; BLAKE3 with separate modes and fixed context strings; constant-time comparisons; CSPRNG from the OS; no home-made primitives (P 0, P 1.3, Appendix B). | D | Same core. |
| MASVS-CRYPTO-2 [V3] | Key management follows best practice. | One identity key per installation, generated on device, never exported or backed up, replaceable by "reset identity"; wrapping key non-exportable; no hard-coded secrets (only public release keys); pairing secret single use; void pairings on key loss; release keys with ids, revocation and offline custody (P 1.1, P 1.6, P 2.1, P 10.4). | D | DPAPI; no hardware binding (stated). |
| MASVS-AUTH-1 [V4 Authentication] | Secure authentication and authorisation protocols. | Mutual TLS with pinned keys, verified handshake signatures and no resumption; signed session transcript; pairing with a one-time secret and a committed number that is typed on the PC; capabilities, per-phone namespaces and per-root authorisation decided by the PC (P 1.4, P 2, P 5.3, P 9.3). | D | Same. |
| MASVS-AUTH-2 [V4] | Local authentication follows platform practice. | The app has no local login in 1.0. The Android lock screen protects the device. | X (R19) | No lock by decision (P 9.7). |
| MASVS-AUTH-3 [V4] | Sensitive operations need additional authentication. | Final move: per-folder opt-in with acknowledgement, a per-phone opt-in on the PC, the weekly presence code from the PC, Android's own dialog per batch on API 30+. Pairing: a number typed at the PC. Contacts and calendar restore: a preview and a confirmation. No biometric prompt in 1.0. | D, partly X | Pairing, handing over a namespace and enabling a network need a person at the PC. |
| MASVS-NETWORK-1 [V5 Network] | All traffic is protected by current best practice. | The only data channel is QUIC with TLS 1.3 from the Rust core (not the platform stack, so old Android TLS defaults do not matter); no cleartext, no fallback; update check over HTTPS with the platform trust store; `usesCleartextTraffic=false` (P 1.3, P 10). | D | Same. |
| MASVS-NETWORK-2 [V5] | Identity pinning for endpoints under the developer's control. | Every peer connection is pinned to the paired `SPKI`. The update endpoint (GitHub) is not under the project's control and is not certificate-pinned; the release manifest signature protects the content instead (P 1.4, P 10.4). | D | Same. |
| MASVS-PLATFORM-1 [V6 Platform] | IPC mechanisms are used securely. | Exported surface: launcher and share target only; no deep links; shared URIs validated and never resolved into app-private data; immutable pending intents; no exported provider, service or receiver; runtime permissions requested when the feature that needs them is turned on, with reasons (C14, P 2.2, P 4.7, P 9.5). | D / V | "Send to phone" passes paths over a per-user channel; no URI protocol handler; no file association. |
| MASVS-PLATFORM-2 [V6] | WebViews are used securely. | The Android app has no WebView (Compose only). | n/a | WebView2: local content only, every remote request refused, content security policy, peer strings as text, narrow host interface, reputation checks and autofill off (C14, P 9.5). |
| MASVS-PLATFORM-3 [V6] | The user interface is used securely. | Touch filtering against overlays on sensitive buttons; consent dialogs name the device and the count; no secrets in notifications or the recent-apps preview of the pairing screen; sensitive clipboard flag (C14, P 9.2). | D / V | Weekly code and QR only inside the program window; the pairing number is never shown on the PC. |
| MASVS-CODE-1 [V7 Code quality] | The app requires an up-to-date platform version. | **minSdk is 24 (Android 7.0)**, chosen so that old phones are served. Compensation: transport security does not depend on the platform TLS stack; Keystore AES-GCM exists since API 23; target SDK is current; behaviour differences per API level are specified (P 8.6). | X | Windows 10/11 with supported WebView2. |
| MASVS-CODE-2 [V7] | A mechanism enforces app updates. | Update check with signed manifest for direct downloads; `min_supported` tells an old program that it is no longer supported; stores update store builds; a protocol major version can refuse old peers (P 10.1, P 10.4, P 11.1). There is no server, so no remote kill switch. | D, partly X | Same. |
| MASVS-CODE-3 [V7] | Only components without known vulnerabilities. | Pinned toolchain and lock files; dependency audit in CI; minimal crate features; ring instead of a larger library; reproducible build for F-Droid (spike section 7). | D (process) | Same. |
| MASVS-CODE-4 [V7] | All untrusted input is validated and sanitised. | Strict CBOR profile with enforced canonical form, one range table, frame and rate limits, state checks; path components as arrays with cleaning rules for both directions; QR payload validation; display cleaning of every peer string; vCard and iCalendar parsed only at a user-started restore, with limits; the trash index treated as untrusted; fuzzing of decoders (P 5, P 6.8, P 2.2, P 8.6, P 9.6, C6). | D | Same, plus reparse-point checks, neutralised shell-active names, and no parsing of phone data files at all. |
| MASVS-RESILIENCE-1..4 [V8 Resilience] | Integrity checks, anti-tampering, anti-analysis. | Not part of L1. The project is open source and does not obfuscate. Android enforces same-signer updates. | n/a | n/a |
| MASVS-PRIVACY-1 | Minimise access to sensitive data and resources. | Base permissions: media, camera (QR only, while scanning), local network, notifications. **Optional, each requested only when the user turns that data set on:** contacts and calendar (read; write only for a restore), all-files access, the installed-apps list. Never: location (decision D30), SMS, call log, accounts, install-packages. `ACCESS_MEDIA_LOCATION` only to copy originals unmodified (P 6.2, P 9.5, P 9.6). | D / V; the optional sets are broad by nature (N4) | Reads only its destination, its second disks and folders the user shared. |
| MASVS-PRIVACY-2 | Prevent identification of the user. | No account, no identifiers sent anywhere, random rotating mDNS names with per-link keyed hints, constant update User-Agent, no telemetry; app-list manifests carry no account or device identifier (P 4.1, P 4.2, P 9.6, P 10). | D | Same. |
| MASVS-PRIVACY-3 | Be transparent about data collection and use. | Nothing is collected by the project. The report screen shows exactly what would be sent; the endpoint list is complete and published, including connections the operating system makes on the program's behalf; the product states that PC copies are plain files (P 9.7, P 10.2, P 10.3). | D | Same. |
| MASVS-PRIVACY-4 | Give the user control over their data. | Per-folder modes and per-data-set switches; keep-on-phone period; favourites and "keep on phone"; unpair at any time from either side; trash and restore; update check can be switched off; the diagnostic log is off by default and local (P 2.7, P 8, P 8.12, P 9.6, P 10). | D | Per-phone folders, quota and final-move switch; per-network switch; the files stay usable without the program. |

Deviations to accept or revisit: **STORAGE-1 on the PC** (plain files: owner decision), **AUTH-2 / AUTH-3**
(no app lock, no biometric step before enabling final move), **CODE-1** (minSdk 24), **CODE-2** (no forced
update). Each is a product decision recorded here so that it is a choice and not an oversight.

---

## 8. When to revisit this document

- Any change to pairing, the verifier or the TLS configuration, the final-move state machine, the trash
  rules, the second-copy rules, the item kinds or the endpoint list.
- Adding a lock, a password or encryption for the PC files (it would change R22, R24, R27 and add the risk
  the owner excluded: loss by a forgotten password).
- Adding a network mode beyond the local link, a second listener, a URI scheme, or a cloud feature.
- Adding the iOS client (different trash and background rules).
- A new Android or Windows version that changes storage, trash, local-network, contacts or clipboard
  behaviour, or the list of file types that Explorer parses.
- A finding from the release gates (bug hunter, torture tools, code-blind user tester) that touches a row
  of P 8.11 or a residual risk above.
- When the open items of `PROTOCOL.md` section 13 are settled: N1 (purge and the second copy) changes R23
  and path 16; N3 (automatic removal of old snapshots) touches invariant I7; N4 (store builds) changes
  MASVS-PRIVACY-1; N5 (network share as second disk) changes C15; V1 (reading trashed items) changes R20;
  V4 (Android 10) changes the scope of the trash folder; V8 (favourites) changes what "never moved" covers.
