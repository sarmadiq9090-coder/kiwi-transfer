# Kiwi Transfer 1.0: threat model

Status: Draft 1, 2026-11-19. Companion to `docs/PROTOCOL.md` (protocol `kiwi/1`). References of the form
"P 8.5" mean section 8.5 of `PROTOCOL.md`.

Contents: 0 Scope and method - 1 Assets - 2 Actors and assumptions - 3 Trust boundaries and data flows -
4 STRIDE per component - 5 Data-loss analysis for final move - 6 Residual risks - 7 OWASP MASVS checklist -
8 When to revisit this document.

---

## 0. Scope and method

**In scope:** the Android app (minSdk 24, Kotlin/Compose), the Windows program (Rust + WebView2), the shared
Rust core, the `kiwi/1` protocol, pairing, discovery, storage of keys and ledgers, the update check and the
problem report.

**Out of scope:** the security of Android, Windows, the router, GitHub and the user's mail program
themselves; attackers with root, kernel or administrator rights on a device; hardware attacks; the
project's build and release infrastructure (it has its own checklist: SLSA provenance, OpenSSF Scorecard),
except where the release key touches the update check.

**Method:** assets, actors and trust boundaries first; then a STRIDE table per component (Spoofing,
Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege); then a separate
analysis of the one way this product can destroy user data (final move); then residual risks stated without
softening; then a mapping to OWASP MASVS.

**The two properties that matter most**, in order:

1. **No loss of the user's files.** A photo that exists only once must never be destroyed by this software
   acting on wrong information.
2. **No disclosure of the user's files** to anyone but the user's own two devices.

---

## 1. Assets

| Id | Asset | Where | What must be protected |
|---|---|---|---|
| A1 | User files on the phone (photos, videos, documents), including metadata inside them (location, dates) | Phone shared storage | Confidentiality, integrity, **existence** |
| A2 | Copies on the PC; after a final move, the **only** copies | PC destination folder | Confidentiality, integrity, **durability** |
| A3 | Device identity keys (Ed25519) | Phone: wrapped blob + Keystore key. PC: DPAPI blob | Confidentiality (a copied key is a cloned device) |
| A4 | Pin stores (which device is paired with which) | App-private storage on both | Integrity (a forged pin is a silent man in the middle) |
| A5 | Ledgers and final-move journals | App-private databases on both | Integrity, availability (they drive deletion decisions) |
| A6 | Short-lived values: pairing secret, SAS, weekly code | PC screen, memory | Not disclosed or guessable within their lifetime |
| A7 | Metadata about the user: file names, album names, device names, which devices exist on the network, when backups run | Wire, logs, mDNS | Confidentiality |
| A8 | Clipboard text sent between devices | Memory, clipboard | Confidentiality |
| A9 | The rest of the PC's file system and the user's Windows session | PC | Integrity: the program must never write outside its destination or run received content |
| A10 | The rest of the phone's storage | Phone | Integrity: received files land only in the app's own folders |
| A11 | The update channel (release signing key, release manifest) | Maintainer, GitHub | Integrity |
| A12 | The user's consent (pairing dialog, accept dialog, trash dialog, final-move switch) | Both UIs | Must not be forged, pre-answered or obtained by confusion |
| A13 | PC resources: disk space, CPU, the listening port | PC | Availability |

---

## 2. Actors and assumptions

### 2.1 Adversaries

| Id | Actor | Capabilities |
|---|---|---|
| T1 | **Passive network observer** on the same LAN (guest, neighbour with the Wi-Fi password, a compromised smart device) | Sees all frames on the link: addresses, timing, sizes, mDNS. |
| T2 | **Active network attacker** on the same LAN | Everything T1 can, plus: spoof ARP/NDP, DHCP and mDNS; run a rogue access point; drop, delay, replay and inject packets; open connections to the PC. |
| T3 | **Malicious or compromised paired peer** (a tampered phone app, or someone holding a stolen phone identity key; symmetrically a compromised PC program) | Is authenticated. Sends any protocol message with any content: hostile names, sizes, hashes, counters. |
| T4 | **Remote internet attacker** | No route to the devices (on-link rule). Can try: a web page or message carrying a pairing link or QR; a router port-forward; the update channel; a poisoned dependency. |
| T5 | **Thief or finder of the phone** | Phone locked, or phone unlocked. |
| T6 | **Person near the PC** (visitor, family member, office colleague) | Sees the screen (QR, SAS, weekly code); may use the unlocked PC. |
| T7 | **Malware running as the user on the PC** | Everything the user can do: read and write the user's files, call DPAPI, read the screen, send input to windows. |
| T8 | **Another app on the phone** (no root) | Sends intents and shares; reads and writes shared storage if it holds storage permission; draws overlays; reads the clipboard while in front. |
| T9 | **Ransomware on the PC** | A special case of T7 that encrypts or deletes the user's files. |
| T10 | **Supply-chain attacker** | Compromises a dependency, the build, the GitHub account, or steals the release key. |

### 2.2 Non-adversarial hazards

They cause most real data loss and are treated as seriously as attackers.

| Id | Hazard |
|---|---|
| H1 | Disk failure, bit rot, a drive that acknowledges a flush it did not perform, a cable pulled, power loss. |
| H2 | Crashes and forced stops at any instruction; the phone killed by battery management. |
| H3 | Wrong clocks: empty RTC battery, manual changes, time zone changes. |
| H4 | The user: deletes or moves the PC folder, reinstalls Windows or the app, revokes a permission, ignores a warning, unplugs an external drive. |
| H5 | The operating system: Android empties its trash after 30 days; Windows changes a network to Public; a sync client moves files to a cloud. |
| H6 | Our own bugs. |

### 2.3 Assumptions

1. The operating systems enforce their own boundaries: the Android app sandbox and Keystore, Windows user
   separation.
2. The cryptographic primitives are sound: Ed25519, X25519, the three TLS 1.3 AEAD suites, BLAKE3 (collision
   and preimage resistance, and its keyed mode as a MAC and its derive-key mode as a KDF).
3. rustls, quinn and ring implement TLS 1.3 and QUIC correctly. The project's own verifier (P 1.4) is the
   part that needs review and has mandatory negative tests.
4. During pairing, the person at the PC and the person holding the phone are the same person or cooperate,
   and they read the dialog.
5. The user's Windows account is not already controlled by an attacker when the program is installed. If it
   is, see residual risk R1.

---

## 3. Trust boundaries and data flows

```
                         B12: the human (reads QR, SAS, weekly code, dialogs)
        ......................................................................................
        :                                                                                    :
+-------:---------------- PHONE (Android) ----------+          +------------- PC (one Windows user session) -------:------+
|                                                   |          |                                                          |
|  other apps --B5--> [ Kiwi app: Compose UI ]      |          |   [ WebView2 UI ] --B7-- [ Rust host + core ]            |
|   (share sheet,          |  B4 (UniFFI)           |    B1    |                              |          |                |
|    intents, overlays)  [ Rust core ] <==== QUIC + TLS 1.3 (mutual pins) ====> listener      |          |                |
|                          |        |               |  (LAN,   |                              |          |                |
|        B3: Android Keystore       | B2            |  hotspot,|            B9: DPAPI blob ---+          | B10            |
|        (wraps identity seed)      v               |  USB)    |                                         v                |
|                    shared storage (MediaStore,    |          |   destination volume (files) and ledger database         |
|                    trash folder), other apps      |          |   B8: every other process of the same user can reach     |
|                    can read and write it          |          |       all of this (NO boundary enforced by Windows)      |
+---------------------------------------------------+          +----------------------------------------------------------+
            B6: mDNS on the link (unauthenticated)                       B11: internet, GitHub only (update check)
```

| Id | Boundary | What crosses it | Protection at the crossing |
|---|---|---|---|
| B1 | The link between the devices | Everything | TLS 1.3 with mutual `SPKI` pins and verified handshake signatures; signed session transcript; on-link address rule (P 1, P 4.4, P 5.3). |
| B2 | App to shared storage | User files, trash folder | None against other apps with storage access: files are re-checked (size, time, generation, hash) before every decision (P 6.5, P 8.5, P 8.6). |
| B3 | App to Android Keystore | Wrap/unwrap of the identity seed | Hardware-backed where available (P 1.6). |
| B4 | Kotlin to Rust (UniFFI) | Commands, progress, platform results | Typed interface; the core validates platform inputs as data. |
| B5 | Other apps to the Kiwi app | Shared items, intents | Minimal exported surface; no pairing link; shared URIs validated (4, component C14). |
| B6 | mDNS | Candidate addresses, hint | Treated as hints only; filter then pin (P 4). |
| B7 | WebView2 UI to native host | UI events, strings for display | Local content only; peer strings as plain text; narrow message interface (C14). |
| B8 | PC program to other processes of the same user | Key blob, ledger, files, window | **No protection exists.** See R1. |
| B9 | PC program to DPAPI | Identity seed | CurrentUser scope, with the limits in P 1.6. |
| B10 | PC program to the destination file system | Files, directories | Reparse-point checks, create-new only, unbuffered re-read (P 6.8, P 6.9, P 7). |
| B11 | Programs to GitHub | Update check, download | HTTPS, fixed hosts, signed manifest (P 10.1). |
| B12 | Human to devices | QR, SAS, weekly code, consent | Dialog wording, commitment scheme, attempt limits (P 2, P 3). |

Main data flows: (F1) pairing; (F2) session setup; (F3) backup phone to PC; (F4) final move verification and
trashing; (F5) send PC to phone; (F6) browse, thumbnails, fetch, restore; (F7) clipboard; (F8) discovery;
(F9) update check and download; (F10) problem report through the mail program.

---

## 4. STRIDE per component

Columns: **Cat** is the STRIDE letter. **Residual** names what remains after the mitigation ("none" means
no practical attack is known within the stated assumptions).

### C1. Identity keys and key storage

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Copy the phone's key from a backup or a cloned data directory, then act as the phone. | Seed wrapped by a non-exportable Keystore key; blob in the no-backup directory; backups and device transfer excluded (P 1.6). | Devices without a hardware-backed Keystore; rooted devices. |
| S | Copy the PC's key and impersonate the PC to the phone. | DPAPI CurrentUser. | **R1**: any program running as the user can do this. |
| T | Replace the identity blob or the pin store to redirect a device. | App-private storage; an unwrap failure forces a new identity and voids all pairings (P 1.1 rule 5). | PC: same-user malware (R1). |
| R | A device denies having taken part in a session. | Signed session transcript (P 5.3); not a product goal between a user's own devices. | Accepted. |
| I | Key bytes exposed in memory dumps, logs or crash reports. | Zeroize-on-drop buffer; the logging interface cannot take byte strings (P 10.2); no crash reporter. | A debugger or root on the device. |
| D | Key loss (uninstall, profile reset) breaks the link. | Detected; the user is told to pair again; no data is deleted (P 8.10). | Inconvenience only. |
| E | Use the key from another app. | Android: sandbox. | PC: none (R1). |

### C2. Pairing (QR and SAS)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T2 pretends to be the PC towards the phone during QR pairing. | The phone verifies the PC id from the QR before sending anything; handshake signature verified (P 1.4, P 2.4). | None. |
| S | T2 pretends to be the phone towards the PC. | Needs the one-time 128-bit secret from the QR, bound by a MAC to both identities and the TLS exporter; then the Allow dialog (P 2.3, P 2.4). | T6 who photographs the QR and wins the race: see R10. |
| S | T2 is a man in the middle during SAS pairing and grinds keys or nonces until both screens show the same 6 digits. | Commitment scheme: one guess per attempt, success 10^-6, three attempts per window (P 2.5). | The user confirms without comparing. |
| S | T4 sends the user a link or QR that pairs the phone with the attacker's PC. | No URI scheme, app link or intent starts pairing; QR accepted only from the in-app scanner; QR addresses must be on-link (P 2.2). | The attacker must already be on the LAN and get the user to scan their QR in the app. |
| T | Replay of pairing messages on another connection. | Proofs and SAS bind the TLS exporter of this connection; fresh nonces. | None. |
| T | Hostile device name in the consent dialog (markup, direction overrides, very long). | Cleaning and plain-text rendering (P 5.8). | None. |
| R | "I never allowed that phone." | The PC history records pairings with time and name. | Local log, not tamper-proof (R1). |
| I | The pairing secret leaks from the QR after use. | Single use, destroyed at first valid proof or at window end (P 2.1). | None. |
| I | The PC's name is told to unpaired devices in SAS mode. | Only inside a user-opened SAS window. | Accepted. |
| D | T2 burns the three attempts or occupies the two UNPAIRED slots so the user cannot pair. | Limits; the user reopens the window. | Nuisance on a hostile LAN. |
| E | An UNPAIRED connection reaches transfer or browse messages. | UNPAIRED connections accept `PAIR_*` only, 4 KiB frames, one stream, and are never upgraded (P 2.1). | None. |
| E | A standing pairing service is abused later. | There is none: unknown keys are rejected in the handshake when no window is open (P 2.1). | None. |

### C3. Transport and session (QUIC, TLS, `HELLO`)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Present a pinned certificate without owning its key. | `CertificateVerify` must be verified with the certificate's key; mandatory negative test; second check by the signed transcript (P 1.4, P 5.3). | Implementation error caught by tests. |
| S | Resume an old session after being unpaired. | No tickets, no PSK, no 0-RTT (P 1.3). | None. |
| T | Downgrade to a weaker protocol or to plaintext. | One ALPN, no fallback of any kind; TLS 1.3 only (P 1.3). | None. |
| T | Alter version or capability negotiation, or the link counters. | Inside TLS, and signed over the exporter (P 5.3). | None. |
| R | Disputes about what was sent. | Local history on both sides. | Accepted. |
| I | T1 reads file content, names or device names. | All of it is inside TLS; device names are never in mDNS or in certificates (P 1.2, P 4.1). | Traffic sizes and timing (R8). Recorded traffic and future quantum computers (R9). |
| I | T2 learns the PC's public key by starting a handshake. | Not preventable in TLS 1.3 (the server authenticates first). The phone's key is not shown to a wrong server (P 1.5). | **R7**. |
| D | Handshake floods, spoofed sources. | Source filter, Retry, handshake limits, nothing allocated before authentication (P 5.9). | A local attacker can still jam the radio or the link (R15). |
| E | Reach the listener from the internet through a port-forward. | Source address must be on-link; hop limit 1; Private-profile interfaces only (P 4.4, P 4.5). | None. |

### C4. Discovery (mDNS) and listener placement

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T2 advertises a fake PC or answers with its own address. | Candidates only; the pin decides (P 4). | Failed attempts and delay. |
| T | T2 rewrites TXT or SRV data. | Same. | Same. |
| I | The advertisement reveals a device or user name, or lets T1 track the PC over time. | Random instance and host names rotated at start, on network change and daily; the hint is a MAC that changes with the name; no names in TXT (P 4.1, P 4.2). | The presence of "a Kiwi Transfer PC" and its port are visible (R7). |
| I | The phone reveals itself. | It never advertises and never listens. Its browse queries show interest in the service type. | T1 learns "a phone here uses Kiwi Transfer". |
| D | mDNS blocked (guest network isolation). | Cached address; QR as a candidate source; a troubleshooting screen. | The feature does not work on isolating networks. |
| E | The listener is exposed on a public network (cafe, airport). | Binds only to interfaces with the Windows Private category; firewall rule scoped to Private and LocalSubnet (P 4.5). | The user marks a hostile network as Private. Authentication still holds. |

### C5. Weekly re-confirmation

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | T5 keeps a stolen phone useful by guessing the 2-digit code. | A code exists only while shown to a person at the PC; 3 attempts; a new code needs a click at the PC; failures are displayed there; lockout (P 3.4). | 3 % per armed challenge (R11). |
| T | Roll the clock back to avoid expiry. | Link clock: monotonic, the larger of both devices, anomaly flag, epoch counters (P 3.2, P 3.3). | Both devices manipulated by their owner. |
| T | A code for phone A is used for phone B. | Challenges are per link (P 3.6). | None. |
| R | - | Confirmations are recorded locally with the epoch. | - |
| I | The code is seen by T6. | It is not a secret (P 3.1); it expires in 5 minutes and is useless without the paired phone. | Accepted. |
| D | The user is away; backups pause after 7 days. | By design; nothing is deleted; resumes after one code (P 3.5). | Backup gap until the user returns. |
| E | Expiry is bypassed by a request that is not checked. | One rule: every data-plane request is refused when the link is `REQUIRED` (P 3.5). | Implementation error caught by tests. |

### C6. Control protocol: parser, limits, state

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | T3 sends malformed or ambiguous encodings to confuse hashes or signatures. | Strict CBOR profile; hashes over received bytes (P 5.2). | None. |
| T | T3 sends messages out of order or for inactive capabilities. | `E_STATE`, `E_UNSUPPORTED`; unknown values read as "failed", never as "delete" (P 5.4, P 11.1). | None. |
| I | Error details leak names or paths into logs or reports. | `ERROR.detail` rule; typed logging (P 5.8, P 10.2). | None. |
| D | Huge frames, deep nesting, thousands of requests, too many streams. | Frame cap checked before reading, depth 8, 32 outstanding requests, stream and rate limits (P 5.7). | None. |
| E | Memory-safety bug in the parser. | The parser and all protocol logic are in safe Rust; fuzzing of the frame decoder is a release gate. | Bugs in unsafe code of dependencies (R16). |

### C7. Receiving files on the PC (names, paths, commit, quota)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | T3 writes outside the destination: `..`, absolute paths, drive letters, device names, alternate data streams, trailing dots and spaces. | Components as an array; reject and clean rules; reserved-name rule; extended-length paths built only by the receiver (P 6.8). | None. |
| T | A junction or symbolic link placed inside the destination redirects writes (for example into the Startup folder). | No reparse point is followed below the root; final path checked against the root (P 6.8 rule 11). | T7 can do anything anyway (R1). |
| T | T3 overwrites or replaces an existing file, including by a case or normalisation collision. | Create-new rename only; suffix policy (P 6.9). | None. |
| T | Data corrupted between network and disk, or by the disk. | Chunk hashes, whole-file hash, flush, unbuffered re-read, weekly scan (P 6.4, P 7, P 8.9). | Drive caches (R6). |
| R | - | Ledger records every commit with session number. | - |
| I | Files are stored in a cloud-synchronised folder and uploaded by a sync client. | Detected: warning for copy, refusal for final move (P 8.2). | The user ignores the warning (open question Q4). |
| D | T3 fills the disk. | Reserve rule, optional per-phone quota, declared-size enforcement, partial-file expiry (P 5.10). | Up to the reserve. |
| E | A received file is executed or opened automatically. | The program never opens, previews or runs received content (P 6.6). | The user opens a hostile file themselves. |

### C8. Receiving files on the phone (send, fetch, restore)

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Files arrive that the user did not ask for. | Accept dialog for every PC-to-phone offer; fetch and restore only on the phone user's request (P 9.1). | None. |
| T | A hostile name hides a folder (`.nomedia`), escapes the folder, or overwrites a file. | Leading-dot rule, fixed base folder, cleaning, create-new (P 6.8 rules 12-15, P 6.9). | None. |
| T | Corrupted content. | Chunk hashes, re-read and hash before publishing (P 9.1). | None. |
| I | A notification shows file names on the lock screen. | Notifications use private visibility and counts, not names. | None. |
| D | The PC fills the phone. | Free-space floor; accept dialog shows sizes. | None. |
| E | A received APK is installed, or a file is opened without a tap. | Never auto-open, never request installation of received files (P 9.1 rule 5). | The user installs it deliberately. |

### C9. Final move

Deletion logic is analysed in depth in section 5; the STRIDE view:

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Someone other than the real PC tells the phone "I have your files". | Pinned TLS; weekly check; and the phone decides from a keyed proof it recomputes itself (P 8.5). | T7 on the PC (R1), without gaining the ability to make the phone delete what the PC does not hold. |
| T | A stale or wrong ledger says a file is present. | The ledger is never trusted for deletion; proof over the real bytes with a fresh nonce (P 8.1 I3). | None. |
| T | Another app (T8) changes the phone file between verification and trashing. | Metadata re-checked immediately before the trash call; item goes to a trash, not to deletion (P 8.6). | A change inside that last instant: the changed file is trashed, recoverable for 30 days (R20). |
| T | Another app empties or alters the app trash folder (API 24-29). | None possible: shared storage. Index kept in the app database; purge decisions never rely on the folder index. | R13. |
| R | "The app deleted my photos." | Journal of every batch with counts and times; history screen; system dialog on API 30+. | Local records. |
| I | - | No new exposure. | - |
| D | T2 or T3 keeps final move from ever running. | Fail-safe direction: nothing is deleted; the phone stays full. | Accepted. |
| E | T3 (a compromised PC program) makes the phone delete everything. | The PC cannot command deletion (P 8.1 I6). It can only answer proofs, which requires holding the bytes. | A compromised PC that keeps the bytes until the purge and then destroys them (R1, R3). |

### C10. Ledgers and journals

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| T | Corruption or loss of a ledger. | Integrity check at start; loss is detected through `ledger_id`; all receipts become void and purges stop (P 7, P 8.10). | None for deletion safety. |
| T | T7 edits the PC ledger. | Not preventable. Deletion on the phone still needs the real bytes (P 8.5). | R1. |
| D | Ledger on a failing system disk. | Loss handling as above; files are untouched. | Re-indexing time. |
| I | Ledger contains file names and hashes. | Stored in per-user application data; never in logs or reports. | Readable by the same user (R1). |

### C11. Clipboard

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Text appears to come from the user's device. | Authenticated session only; shown with the peer's name. | None. |
| T | A link that opens something dangerous (`intent:`, `file:`, look-alike host). | Never auto-open; only `http`/`https`; full URL and punycode shown; a tap is required (P 9.2). | The user opens a phishing link deliberately. |
| I | Passwords leak into notification previews, clipboard history or cloud clipboard. | Manual send only; sensitive flag honoured on both platforms; no logging of content (P 9.2). | Text the user forgot to mark and that the source did not mark. |
| D | Clipboard spam from T3. | One per second; the user can disable the capability. | None. |
| E | Received text is written to the clipboard without consent and pasted by the user elsewhere. | Copy needs a tap (P 9.2 rule 3). | None. |

### C12. Browsing the PC, thumbnails, fetch, restore

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A new phone claims an old phone's backup. | Attaching a backup to a new link is done by a person at the PC (P 9.4). | T6 at the unlocked PC. |
| T | T3 (a stolen phone identity) modifies or deletes PC files through browsing. | Read-only by construction: no such message exists (P 9.3). | None. |
| I | T3 reads PC folders the user did not share (traversal, links, hidden files). | Chosen roots only; opaque handles; reparse points, hidden and system entries omitted (P 9.3). | Everything inside shared roots is readable by a paired, confirmed phone: T5 with an unlocked phone (R2). |
| I | Thumbnails leak location metadata. | Thumbnails are re-encoded without metadata. | None. |
| D | Thumbnail generation exhausts the PC. | Size, pixel, time and concurrency limits; rate limits (P 9.3, P 5.7). | None. |
| E | A crafted image stored on the PC attacks the Windows codecs when a thumbnail is made; a crafted thumbnail attacks the phone's decoder. | Operating-system codecs only, with limits; header checks before decoding on the phone. | Codec vulnerabilities (R18). |

### C13. Update check and problem report

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | A fake release is offered (GitHub account taken over, or TLS interception). | Detached Ed25519 signature by a release key compiled into the program; hash and size per asset; Android signature check by the system (P 10.1). | Theft of the release key (R12). |
| T | Downgrade to an old vulnerable version. | Version must be greater than the installed one. | None. |
| T | First download is replaced. | HTTPS from GitHub; published manifest and provenance for manual checks. | No in-app check is possible for a first install; no Authenticode on Windows (R12). |
| I | The check identifies the user or the device. | Constant User-Agent, no identifiers, no parameters; can be turned off (P 10.1). | GitHub sees the IP address (R17). |
| I | A report leaks private data. | Allow-list of fields; shown in full first; sent by the user's own mail program (P 10.2). | What the user types into the free-text box. |
| D | GitHub unreachable. | The check fails silently; nothing else depends on it. | None. |
| E | The updater runs an unverified installer. | Verification before execution; no "install anyway". | None. |

### C14. User interfaces and inter-process surfaces

| Cat | Threat | Mitigation | Residual |
|---|---|---|---|
| S | An overlay on the phone covers the final-move switch, the SAS confirmation or an accept dialog (tapjacking). | Sensitive buttons ignore touches while the window is obscured; the system trash dialog is drawn by Android. | Old Android versions with weaker overlay rules. |
| T | Script injection into the PC window through a device name, file name or clipboard text. | WebView2 loads only local files; peer strings are set as text, never as HTML; content security policy without inline script; no remote navigation; a narrow, typed host interface (P 5.8). | None known. |
| T | Another app shares a URI that points into the Kiwi app's own private files, so that "Send to PC" exfiltrates them. | Shared URIs are read only through the content resolver with the caller's grant; `file:` URIs and URIs that resolve to the app's own private directories or its own provider are refused. | None. |
| I | The weekly code or the QR is captured by T7 from the screen. | Not preventable for same-user malware (R1). The QR is useless after use. | R1. |
| D | Dialog flooding to train the user to click Allow or Accept. | One pairing dialog at a time, only inside a window the user opened; accept dialogs only from paired, confirmed PCs; rate limits. | Fatigue with a compromised paired PC. |
| E | An exported component is driven by another app. | Exported: the launcher activity and the share target only. No exported service, receiver or provider; immutable pending intents; no deep links (P 2.2). | None. |

---

## 5. Data-loss analysis for final move

Final move is the only feature that removes user data. This section asks one question: **by what paths can
the last copy of an item be destroyed, and what stands in each path?**

### 5.1 Where the copies are

| Phone state (P 8.3) | Copy on the phone | Copy on the PC | Copies | A single fault loses data? |
|---|---|---|---|---|
| `LOCAL`, `SENT` | Original | None, or unverified | 1 | Only the phone's own failure, as before the app existed. |
| `COMMITTED` | Original | Verified once from disk | 2 | No. |
| `VERIFYING`, `VERIFIED` | Original | Verified twice | 2 | No. |
| `TRASHED` | In a trash (recoverable) | Verified twice | 2, one with an expiry | No, while the trash lasts. |
| `PURGED` | None | Verified three times (API 24-29) or twice (API 30+) | **1** | **Yes: the PC copy.** |

The design goal is therefore: **the app never moves an item from 2 copies to 1 copy on wrong information,
and never from 1 copy to 0.** After `PURGED` the product is, by the user's explicit choice, a single-copy
store, and says so.

### 5.2 Layers

| Layer | What it catches | Reference |
|---|---|---|
| L1 | Per-chunk hash: corruption in memory or transit; change of the source between sessions | P 6.4, P 6.7 |
| L2 | Whole-file hash computed in the same pass that streams the bytes; size and time re-check after sending | P 6.5 |
| L3 | Flush, then unbuffered re-read from disk before the receipt | P 7 |
| L4 | Create-new atomic rename; the PC never modifies committed files | P 6.9, P 8.1 I7 |
| L5 | Durable ledger with intent rows; receipt only after the ledger commit | P 7 |
| L6 | Destination must be a fixed NTFS/ReFS disk, not removable, not a share, not cloud-synchronised | P 8.2 |
| L7 | Copy-only classes on the phone (SAF, SD card, app-owned folders, redacted items) | P 8.2 |
| L8 | Delay of 24 hours, in a later session, measured on both devices' link clocks | P 8.2, P 8.5 |
| L9 | Second verification: fresh nonce, keyed proof over the real bytes on both sides, compared by the phone | P 8.5 |
| L10 | Metadata re-check before, after and immediately before trashing | P 8.5, P 8.6 |
| L11 | Journal before action, outcome read back from the system | P 8.1 I5 |
| L12 | Trash instead of deletion; 30-day undo | P 8.6 |
| L13 | Third verification before purge, with the PC's clock as a second witness (API 24-29); warning before system expiry (API 30+) | P 8.7, P 8.6 |
| L14 | Weekly integrity scan of every file; any problem blocks final moves for every phone of that PC | P 8.9 |
| L15 | Weekly presence check; expiry stops verification, trashing and purging | P 3.5 |
| L16 | Final move off by default; per-folder opt-in with an explicit acknowledgement; system dialog per batch on API 30+ | P 8.1, P 8.6 |

### 5.3 Paths to loss

"Loss" needs both: the phone copy gone **and** the PC copy gone or wrong.

| # | Path | What must fail | Assessment |
|---|---|---|---|
| 1 | The phone trashes an item although the PC copy is wrong or absent. | L9: the PC must produce `MAC(K_v, content)` for a fresh key without having the content. | Not feasible without breaking BLAKE3. A stale ledger, a cached hash or a replayed answer cannot pass. Even then L12 leaves 30 days. |
| 2 | The phone trashes a different file than the one verified (changed in place, identifier reused). | L10 and L11 within the same seconds. | A change in the last instant leads to the *new* content being trashed; it stays recoverable for the retention period (R20). |
| 3 | The PC copy is damaged or lost **while the item is in the trash**. | L14 or L13 must fail to notice in time, and the user must not restore. | API 24-29: purge needs a third proof, so the item stays in the trash indefinitely: **no loss**. API 30+: Android deletes at expiry regardless; loss only if the damage happens and is not acted on within the remaining days (case A, R5). |
| 4 | The PC copy is lost **after the purge** (disk failure, ransomware, the user deletes the folder, Windows reinstalled over the data). | Nothing can stand here: there is one copy. | **Loss.** The scan detects it afterwards. This is the residual risk of the feature itself (R3, R4). |
| 5 | A crash or power loss at any step. | L5, L11. | Every interrupted step resolves to the earlier state (P 8.11 rows 5, 10, 13, 24, 34). **No loss.** |
| 6 | A wrong clock makes things happen early. | L8 and L13 use two devices' monotonic clocks; anomaly forces the weekly check. | At worst the delay is shorter than intended; every verification still runs. **No loss by itself.** |
| 7 | T2 on the network. | TLS. | Can only block; blocking stops deletion. **No loss.** |
| 8 | T3 as a compromised PC program, or T7 on the PC. | - | It can pass L9 honestly (it has the bytes) and destroy them after the purge: the same as path 4. It cannot shorten the path: the phone trashes only what the PC really holds at that moment. No amplification beyond "malware on your PC can delete files on your PC" (R1). |
| 9 | T3 as a compromised phone app, or T5 with the unlocked phone. | - | It can delete the phone's files directly; the app adds nothing. PC copies are unaffected (no delete message exists). |
| 10 | Another phone app or the user empties the trash early, and then path 3 or 4 happens. | Two independent events. | Double fault. |
| 11 | Android strips location data and the stripped copy is treated as the original. | L7 (`redacted` items are never eligible). | **No loss of metadata.** |
| 12 | The destination silently changes character: an external disk, a share, a folder taken over by a sync client that then removes local content. | L6, re-evaluated at every session and verification; volume identity check. | A sync client that starts after the purge is path 4. |
| 13 | Identity or ledger loss on either device (reinstall, reset). | `ledger_id`, pins. | Receipts void, purges stop, restore offered (P 8.10). **No loss by the app.** On API 30+ the system trash keeps running (path 3). |
| 14 | An implementation bug in the state machine. | L11, L12; every row of P 8.11 is a fault-injection test; the feature is off by default. | The honest residual of any software (H6). The trash gives 30 days to notice. |

### 5.4 Conclusions

1. Before `PURGED`, no single fault and no single wrong component leads to loss. On API 24-29 not even a
   long absence of the PC does: the trash simply keeps the item.
2. On API 30+ one gap cannot be closed by an app: the system empties its trash on schedule. The app can
   warn and offer a one-tap restore; it cannot hold the item. Stated to the user where final move is
   enabled.
3. After `PURGED`, the PC is a single copy. The only real mitigation is the user's second copy on another
   drive; the PC program recommends it and the weekly scan tells the user early when a disk starts to fail.
4. Consequences for the product: final move stays off by default; its explanation screen names the "only
   copy" plainly; the PC shows which files are sole copies; a problem found by the scan is shown with where
   another copy still exists and how many days remain.

---

## 6. Residual risks

Stated plainly. None of these is hidden behind "secure" wording in the product.

| Id | Risk | Why it remains | What limits it |
|---|---|---|---|
| **R1** | **Malware running as the user on the PC** can read every backed-up file, obtain the PC identity key through DPAPI and impersonate the PC to the paired phones (receiving later backups), read or alter the ledger and the pin store, read the weekly code and the QR from the screen, click Allow, and delete or alter the copies. | Windows gives all programs of one user the same rights. A user-mode program cannot defend itself against its peers; pretending otherwise would be dishonest. | The program adds no new power to such malware: it runs unelevated, executes nothing it receives, and cannot be used to make the phone delete what the PC does not hold. Damage to files is noticed by the weekly scan if the ledger survives. |
| **R2** | **A stolen, unlocked phone** gives the thief the phone's files (without the app), and through the app, while on the home LAN and until the weekly check expires (at most 7 days): the PC folders the user shared for browsing, sending files to the PC, and the phone's side of final move. | The app has no lock of its own in 1.0 and its key is not bound to user presence (background backup needs it). | The thief must be on the same link as the PC; the weekly code needs sight of the PC screen; the user can unpair the phone at the PC at once; browsing is read-only and limited to chosen folders. A locked phone's app data is encrypted by Android. |
| **R3** | **Ransomware on the PC** encrypts or deletes the destination. Items already purged from the phone are lost. | After a purge the PC holds the only copy. | The weekly scan and every verification detect the change and block further final moves on all phones; items still in a phone trash can be restored or re-sent ("repair"); the product recommends a second copy on another drive, which is the only real protection. |
| R4 | **The PC disk fails** after a purge. | Same as R3. | Same; the scan gives early warning of a failing disk. |
| R5 | **Android 11+ system trash expires** while the PC copy could not be re-checked (PC off, user away, phone off). | The operating system owns that trash. | Two disk verifications happened before trashing; warnings 7 and 2 days before expiry with one-tap restore. |
| R6 | A **drive acknowledges a flush** it has not completed, then loses power. | Firmware behaviour is outside software control. | The 24 h delayed re-read from disk, and the weekly scan. |
| R7 | The **PC's public key and presence are visible** to any host on the link: a prober can recognise the same PC on another network, and mDNS shows that a Kiwi Transfer PC exists and on which port. | TLS 1.3 servers authenticate first; a service must be discoverable. | No names are exposed; instance names rotate; the phone's identity is never shown to an unpaired server; content stays encrypted. |
| R8 | **Traffic analysis**: sizes and timing reveal when backups run and roughly how much. | No padding or cover traffic. | Local link only. |
| R9 | **Recorded traffic and future quantum computers**: key exchange is X25519. | A hybrid post-quantum group needs a larger crypto library (open question Q10). | The traffic never leaves the local link; an attacker must have been recording on that LAN. |
| R10 | **A bystander photographs the pairing QR** and pairs their own phone first. | The secret is on a screen. | They must be on the same LAN within the window; the PC shows the Allow dialog with a name and the SAS; the real phone then fails to pair, which the user notices; unpairing is immediate. |
| R11 | **The weekly code has 100 values.** | Owner requirement (2 digits). | It is a presence check, armed only at the PC, 3 attempts, failures displayed, lockout. |
| R12 | **Update and first-install authenticity.** Theft of the release key allows a malicious update. The first download and the Windows installer carry no operating-system signature (no paid certificate), so users will see SmartScreen warnings. | Free tools only; a first install cannot verify itself. | Signed manifest with a reserve key; published hashes and build provenance; Android enforces same-signer updates. |
| R13 | **Other phone apps with storage access** can alter or delete user files and, on Android 7-10, the app trash folder. | Shared storage is shared. | Re-checks before every decision; the PC copy is unaffected. |
| R14 | **Other programs of the same Windows user** can change files in the destination. | Same as R1. | Detected by the scan; final moves block. |
| R15 | **Denial of service on the LAN** (jamming, mDNS spoofing, floods within the limits). | Local attackers control the medium. | Backups are delayed; nothing is deleted while they cannot run. |
| R16 | **Dependencies**: quinn, rustls, ring, blake3, SQLite, the CBOR codec, mdns-sd, rcgen, x509-parser, JNA, the QR decoder (C++), WebView2. A flaw there is a flaw here. | No project can audit all of its dependencies. | Pinned versions with a lock file, `cargo audit`/OSV checks in CI, minimal features, fuzzing of our own decoders, no parsing of peer data in C or C++ (the QR decoder sees camera frames only). |
| R17 | **GitHub learns the IP address** of a device that checks for updates. | An HTTPS request has a source address. | Constant request without identifiers; at most daily; can be switched off; absent in store builds. |
| R18 | **Image codecs**: thumbnails are produced by Windows components and decoded by Android's; a crafted image could attack them. | Thumbnails need a decoder. | Size, pixel and time limits; header checks; operating-system codecs that receive security updates; only for folders the user shared. |
| R19 | **No app lock** on the phone app in 1.0. | Not in scope for 1.0. | See R2; the Android lock screen is the lock. |
| R20 | **Last-instant change** of a phone file between the final re-check and the trash call. | Android offers no atomic "trash this exact content". | The window is milliseconds; the item goes to a trash, not to deletion. |
| R21 | **Human error**: the user deletes or moves the PC backup folder, or ignores an integrity alert. | The user owns the files. | Sole copies are marked in the PC program; moved files are followed; missing files block final moves until acknowledged. |

---

## 7. OWASP MASVS checklist

MASVS 2.x replaced the levels L1/L2/R of MASVS 1.x by control groups, tested at profiles (MAS-L1, MAS-L2,
MAS-R). This checklist lists every MASVS 2 control, read at the **L1** profile, with the MASVS 1.x category
in brackets. It applies to the Android app; the last column notes the Windows program where the same idea
applies. Status: **D** = satisfied by design in `PROTOCOL.md`, to be confirmed by test; **V** = needs
verification on real devices; **X** = deliberate deviation, explained; **n/a** = not applicable at L1.

| Control | Requirement (short) | How Kiwi Transfer meets it | Status | Windows program |
|---|---|---|---|---|
| MASVS-STORAGE-1 [V2 Data storage] | Sensitive data is stored securely. | Identity seed wrapped by a hardware-backed Keystore AES-GCM key; pins, ledger and journal in app-private, credential-encrypted storage; nothing sensitive on shared storage except the user's own files and the visible trash folder (P 1.6, P 8.6). | D | DPAPI CurrentUser; limits stated (R1). |
| MASVS-STORAGE-2 [V2] | Sensitive data does not leak. | `allowBackup=false` plus extraction rules; typed logging without names; no crash reporter; notifications without file names; sensitive clipboard handling; thumbnails only in the cache directory (P 1.6, P 9.2, P 10.2). | D | Same logging rules; per-user data directory. |
| MASVS-CRYPTO-1 [V3 Cryptography] | Strong, current cryptography used correctly. | TLS 1.3 only; Ed25519; X25519; AES-GCM/ChaCha20-Poly1305; BLAKE3 with separate modes and fixed context strings; constant-time comparisons; CSPRNG from the OS; no home-made primitives (P 0, P 1.3, Appendix B). | D | Same core. |
| MASVS-CRYPTO-2 [V3] | Key management follows best practice. | One identity key per installation, generated on device, never exported or backed up; wrapping key non-exportable; no hard-coded secrets (only public release keys); pairing secret single use; void pairings on key loss (P 1.1, P 1.6, P 2.1). | D | DPAPI; no hardware binding (stated). |
| MASVS-AUTH-1 [V4 Authentication] | Secure authentication and authorisation protocols. | Mutual TLS with pinned keys and verified handshake signatures; signed session transcript; pairing with a one-time secret or a committed SAS and explicit consent; capabilities and per-root authorisation decided by the PC (P 1.4, P 2, P 5.3, P 9.3). | D | Same. |
| MASVS-AUTH-2 [V4] | Local authentication follows platform practice. | The app has no local login in 1.0. The Android lock screen protects the device. | X (R19) | - |
| MASVS-AUTH-3 [V4] | Sensitive operations need additional authentication. | Final move: per-folder opt-in with acknowledgement, weekly presence code from the PC, Android's own dialog per batch on API 30+. Pairing: consent at the PC. No biometric prompt in 1.0. | D, partly X | Pairing and "attach old backup" need a person at the PC. |
| MASVS-NETWORK-1 [V5 Network] | All traffic is protected by current best practice. | The only data channel is QUIC with TLS 1.3 from the Rust core (not the platform stack, so old Android TLS defaults do not matter); no cleartext, no fallback; update check over HTTPS with the platform trust store; `usesCleartextTraffic=false` (P 1.3, P 10). | D | Same. |
| MASVS-NETWORK-2 [V5] | Identity pinning for endpoints under the developer's control. | Every peer connection is pinned to the paired `SPKI`. The update endpoint (GitHub) is not under the project's control and is not certificate-pinned; the release manifest signature protects the content instead (P 1.4, P 10.1). | D | Same. |
| MASVS-PLATFORM-1 [V6 Platform] | IPC mechanisms are used securely. | Exported surface: launcher and share target only; no deep links; shared URIs validated and never resolved into app-private data; immutable pending intents; no exported provider, service or receiver; runtime permissions requested when needed, with reasons (C14, P 2.2, P 4.7). | D / V | Single-instance pipe (if any) restricted to the user; no URI protocol handler. |
| MASVS-PLATFORM-2 [V6] | WebViews are used securely. | The Android app has no WebView (Compose only). | n/a | WebView2: local content only, no remote navigation, content security policy, peer strings as text, narrow host interface (C14). |
| MASVS-PLATFORM-3 [V6] | The user interface is used securely. | Touch filtering against overlays on sensitive buttons; consent dialogs name the device and the count; no secrets in notifications or the recent-apps preview of the pairing screen; sensitive clipboard flag (C14, P 9.2). | D / V | Weekly code only inside the program window. |
| MASVS-CODE-1 [V7 Code quality] | The app requires an up-to-date platform version. | **minSdk is 24 (Android 7.0)**, chosen so that old phones are served. Compensation: transport security does not depend on the platform TLS stack; Keystore AES-GCM exists since API 23; target SDK is current; behaviour differences per API level are specified (P 8.6). | X | Windows 10/11 with supported WebView2. |
| MASVS-CODE-2 [V7] | A mechanism enforces app updates. | Update check with signed manifest for direct downloads; stores update store builds; a protocol major version can refuse old peers (P 10.1, P 11.1). There is no server, so no remote kill switch. | D, partly X | Same. |
| MASVS-CODE-3 [V7] | Only components without known vulnerabilities. | Pinned toolchain and lock files; dependency audit in CI; minimal crate features; ring instead of a larger library; reproducible build for F-Droid (spike section 7). | D (process) | Same. |
| MASVS-CODE-4 [V7] | All untrusted input is validated and sanitised. | Strict CBOR profile, frame and rate limits, state checks; path components as arrays with cleaning rules for both directions; QR payload validation; display cleaning of every peer string; fuzzing of decoders (P 5, P 6.8, P 2.2, C6). | D | Same, plus reparse-point checks. |
| MASVS-RESILIENCE-1..4 [V8 Resilience] | Integrity checks, anti-tampering, anti-analysis. | Not part of L1. The project is open source and does not obfuscate. Android enforces same-signer updates. | n/a | n/a |
| MASVS-PRIVACY-1 | Minimise access to sensitive data and resources. | Permissions limited to media, camera (QR only, while scanning), local network and notifications; no location permission (open question Q6), no contacts, no accounts; `ACCESS_MEDIA_LOCATION` only to copy originals unmodified (P 6.2). | D / V | Reads only chosen folders. |
| MASVS-PRIVACY-2 | Prevent identification of the user. | No account, no identifiers sent anywhere, random rotating mDNS names, constant update User-Agent, no telemetry (P 4.1, P 10). | D | Same. |
| MASVS-PRIVACY-3 | Be transparent about data collection and use. | Nothing is collected. The report screen shows exactly what would be sent; the endpoint list is complete and published (P 10.2, P 10.3). | D | Same. |
| MASVS-PRIVACY-4 | Give the user control over their data. | Per-folder modes; unpair at any time from either side; trash and restore; update check can be switched off; the diagnostic log is off by default and local (P 2.7, P 8, P 10). | D | Same. |

Deviations to accept or revisit: **AUTH-2 / AUTH-3** (no app lock, no biometric step before enabling final
move), **CODE-1** (minSdk 24), **CODE-2** (no forced update). Each is a product decision recorded here so
that it is a choice and not an oversight.

---

## 8. When to revisit this document

- Any change to pairing, the verifier, the final-move state machine, the trash rules or the endpoint list.
- Adding a network mode beyond the local link, a second listener, a URI scheme, or a cloud feature.
- Adding the iOS client (different trash and background rules).
- A new Android or Windows version that changes storage, trash, local-network or clipboard behaviour.
- A finding from the release gates (bug hunter, torture tools, code-blind user tester) that touches a row
  of P 8.11 or a residual risk above.
- When the open questions in `PROTOCOL.md` section 13 are answered: Q1 (network profile), Q2 (scope of the
  weekly check), Q3 (system trash), Q4 (cloud-synchronised destinations), Q5 (release key custody) and Q10
  (post-quantum key exchange) each change rows in sections 4 to 6.
