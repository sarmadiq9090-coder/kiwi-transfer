# Kiwi Transfer 1.0 — screen list

Each screen has one primary action (the filled / accent button, or the thing the screen waits for). IDs match the mock-ups: open `phone.html#s=<id>` or `pc.html#s=<id>`. Screenshots: `review/<device>-<id>-ar-light.png`, contact sheets `review/contact-phone.png` and `review/contact-pc.png`.

Not in 1.0 (cut on purpose): internet / remote mode and an encrypted vault. Pairing is by QR; the 6-digit comparison code shown on both screens is the fallback and the confirmation.

## Phone (Android)

| ID | Screen | Primary action | Features covered |
|---|---|---|---|
| `onb1` | First launch 1/3: install the PC program | Installed, next | Link to the free PC program; "send the link to myself" |
| `onb2` | First launch 2/3: scan the code | (camera scans the QR) | QR pairing; "nothing goes through the internet"; way out to troubleshooting |
| `onb2b` | Pairing: waiting for the PC | (waits for Allow on the PC) | 6-digit comparison code shown on both screens |
| `onb3` | First launch 3/3: what to back up | Start backup | Folder choice with counts and sizes; safe defaults (camera + screenshots, copy) |
| `home` | Home | Back up now | One status line «صورك في أمان على حاسوبك», last backup, PC connected; shortcuts to Free up space and PC photos; History and Settings in the app bar |
| `backup` | Backup in progress | Pause | Photo visibly travelling phone → PC; count, time left, progress; runs in background; every file verified on arrival |
| `folders` | What to back up | Done | Per-folder mode: Off / Copy / Final move; final move off by default |
| `folder` | Folder sheet: copy or final move | Done | Choose mode for one folder; Final move opens the explanation. WhatsApp and SD-card folders show Copy only |
| `move` | Final move explained | Turn on final move (enabled only after the checkbox) | PC becomes the only copy; delete only after the PC confirms; 30-day trash; weekly code; "keep a second copy" |
| `weekly` | Weekly check | Confirm | Enter the 2-digit code shown on the PC, once a week, before final moves |
| `freeup` | Free up space | Free up 3.2 GB | Only items already on the PC and verified; filter by age |
| `freeupc` | Free up space: confirm | Remove from phone | Count, place, undo (trash 30 days) |
| `trash` | Trash | Put all back on the phone | 30-day trash with days left per item |
| `share` | Send from the share sheet | Send | "Send to PC" share target; choose PC |
| `receive` | Receive from PC | Accept | Accept prompt with file names, sizes and save folder |
| `browse` | Photos on your PC | Restore N to phone | Grid by month, multi-select, restore |
| `history` | History | — (read only) | Backups, received, sent, freed space, retried failures |
| `settings` | Settings | — (list) | Grouped: Backup, PC, Space, Appearance, Help; Advanced collapsed |
| `settingsAdv` | Settings, advanced open | — | Allowed Wi‑Fi networks, charging only, videos on Wi‑Fi only, trash duration, weekly check, diagnostic log |
| `trouble` | Can't find my PC | Try again | Same Wi‑Fi, program open, Windows firewall, router/guest isolation, battery optimisation |
| `update` | Update available | Update now | Version, size, signed release, what's new |
| `report` | Report a problem | Open in mail app | Shows exactly what will be sent; log optional; nothing sent without the user seeing it |
| `about` | About | Check for updates | Version, privacy (collects nothing), source code, licences, FastKiwi |

## PC (Windows)

| ID | Screen | Primary action | Features covered |
|---|---|---|---|
| `first` | First run | (waits for the phone to scan) | Pairing QR; "get the phone app" QR that downloads the APK; 6-digit code fallback |
| `approve` | Pairing request | Allow | «الهاتف "هاتف سارة" يريد الربط. أتسمح؟» with the 6-digit comparison code |
| `home` | Home | Choose files (drop zone) | Status line, last backup, devices (online / offline), storage used, drop zone to send files to the phone |
| `weekly` | Weekly code | Close | Large 2-digit code, changes after 5 minutes |
| `dest` | Where files go | (choose drive / layout) | Destination folder; year/month, per phone, or custom template with live preview; final move only to fixed drives, removable = copy only |
| `history` | History | — (read only) | Backups, sends, restores, final moves, file checks, pairings |
| `scanOk` | File check: all good | Check now | Weekly integrity check of every file; final moves on |
| `scanBad` | File check: problem found | Repair from the phone | Changed files listed with where another copy exists; final moves paused; second-copy advice |
| `settings` | Settings | — (list) | Phones (paired, pair new), Start with Windows, language, appearance, help; Advanced collapsed |
| `settingsAdv` | Settings, advanced open | — | Port (firewall on private networks only), weekly file check schedule, diagnostic log |
| `tray` | Tray menu | Open Kiwi Transfer | Status, send files, show weekly number, pause 1 hour, quit |
| `update` | Update available | Update now | Version, size, signed release, what's new |
| `report` | Report a problem | Open in mail program | Exact preview of what is sent, copy text, log optional |
| `about` | About | Check for updates | Version, privacy, source, licences |

## Tucked into Settings on purpose

These exist but never compete with the main flow:

- **Phone, Settings:** when to back up (automatic on Wi‑Fi), final move per folder, pair another PC, trash, language, appearance, troubleshooting, report, about.
- **Phone, Advanced (collapsed):** allowed Wi‑Fi networks, back up only while charging, videos on Wi‑Fi only, trash duration (default 30 days), weekly check, diagnostic log (off, stays on the phone).
- **PC, Settings:** paired phones (rename, unpair), start with Windows, language, appearance, report, about.
- **PC, Advanced (collapsed):** port (automatic), weekly file check schedule, diagnostic log (off, stays on the PC).
- **PC, Where files go:** destination and folder layout are a nav item, not a setup step: the default (largest fixed drive, year/month) works with zero setup.
