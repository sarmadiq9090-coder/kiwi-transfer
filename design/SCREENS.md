# Kiwi Transfer 1.0 — screen list

Each screen has one primary action (the filled / accent button, or the thing the screen waits for). IDs match the mock-ups: open `phone.html#s=<id>` or `pc.html#s=<id>`. Screenshots: `review/<device>-<id>-ar-light.png`; contact sheets `review/contact-phone.png`, `review/contact-pc.png` and `review/contact-icons.png`.

**New or changed after the owner approved the screens** are marked ★ here, tagged «جديد» in the mock-ups' index, and collected alone in `review/contact-new.png` for a quick review.

"Home" in this app means: the paired PC answers on the network the phone is on. Pairing is by QR; the phone then shows a 6-digit number that the PC user **types** on the PC to confirm.

## Phone (Android)

| ID | Screen | Primary action | Features covered |
|---|---|---|---|
| `onb1` | First launch 1/4: install the PC program | Installed, next | Link to the free PC program; "send the link to myself" |
| `onb2` | First launch 2/4: scan the code | (camera scans the QR) | QR pairing; "nothing goes through the internet"; way out to troubleshooting |
| `onb2b` ★ | Pairing: type the number on the PC | (waits for the PC) | 6-digit number shown on the phone, typed on the PC |
| `newPhone` ★ | New phone: full restore | Restore it to this phone | The PC already holds a copy of an earlier phone: restore everything, or start as a new phone; the new phone carries on in the same folder |
| `onb3` ★ | First launch 3/4: what to back up | Next | Folder choice with counts and sizes; "everything is copied straight away" |
| `onb4` ★ | First launch 4/4: what stays on the phone | Next | «أبقِ على هاتفي آخر»: 1 week / 1 month / 3 months / 1 year / custom, chosen once; one-line explanation; favourites and «أبقِه على الهاتف» never move |
| `move` ★ | Moving off the phone explained | Start backup (enabled only after the checkbox) | Delete only after the PC confirms; 30-day trash; weekly code; second disk on the PC; "just copy for now, decide later" |
| `home` ★ | Home | Back up now | «صورك في أمان على حاسوبك»; calm summary «على هاتفك: آخر شهر · على حاسوبك: كل شيء»; copies line «نسختان · نسخة واحدة»; Free up space, Photos on your PC |
| `homeCode` ★ | Home: weekly code due | Enter this week's code | Copying continues; final moves, browsing/restoring and receiving from the PC pause until the code is entered |
| `backup` | Backup in progress | Pause | Photo travelling phone → PC; count, time left; every file verified on arrival |
| `keep` ★ | Settings › Keep on my phone | Done | Change the period; per-folder period; what never moves |
| `keepMark` ★ | The «أبقِه على الهاتف» mark | Keep them on the phone | Select items → keep; pin mark on kept items, heart on favourites, legend |
| `folders` ★ | What to back up | Done | Per folder: its period, copy only, or off; WhatsApp and SD card copy only |
| `folder` ★ | Folder sheet: its own period | Done | Don't back up / like everything / its own period / keep everything on the phone |
| `weekly` ★ | Weekly check | Confirm | 2-digit code from the PC; what pauses (and what continues) without it |
| `freeup` ★ | Free up space | Free up 3.2 GB | Only items on the PC and checked; favourites and kept items excluded |
| `freeupc` | Free up space: confirm | Remove from phone | Count, place, undo (trash 30 days) |
| `trash` | Trash | Put all back on the phone | 30-day trash with days left per item |
| `data` ★ | Back up your data | Done | Switches: contacts, calendar, files, WhatsApp backups, apps (list + install files); a permission explanation appears only under a switch just turned on; honest note: app data and system settings can't be backed up |
| `restore` ★ | Restore to phone: what | Restore | Choose what comes back; contacts and calendar are merged, never deleted from the phone; apps need a confirmation each |
| `restoreRun` ★ | Restore in progress | Pause | Progress per kind of data |
| `share` | Send from the share sheet | Send | "Send to PC" share target |
| `receive` ★ | Receive from PC | Accept | File names, sizes, save folder; «اقبل دائماً من هذا الحاسوب» |
| `browse` ★ | Photos on your PC | Bring N back to phone | Grid by month, select → «أعد إلى الهاتف» |
| `history` ★ | History | — (read only) | Copies line at the top; backups, data backups, moves off the phone, received, sent |
| `settings` ★ | Settings | — (list) | Backup (what, when, keep on my phone), Your data (back up, restore), PC, Space, Appearance, Help; Advanced collapsed |
| `settingsAdv` ★ | Settings, advanced open | — | Charging only, trash period, weekly check, receiving from the PC, diagnostic log |
| `trouble` ★ | Can't find my PC | Try again | Same Wi‑Fi, program open, a "Public" network in Windows, router isolation, battery saver |
| `update` | Update available | Update now | Version, size, signed release, what's new |
| `report` ★ | Report a problem | Open in mail app | Exactly what will be sent; log optional |
| `about` ★ | About | Check for updates | Chosen app icon; version, privacy, source, licences |

## PC (Windows)

| ID | Screen | Primary action | Features covered |
|---|---|---|---|
| `first` ★ | First run | (waits for the phone to scan) | Pairing QR; "get the phone app" QR; manual fallback |
| `approve` ★ | Pairing request: type the number | Pair | The PC user types the 6-digit number shown on the phone (replaces the Allow button) |
| `netPublic` ★ | Public network prompt | Allow on this network | One click when Windows marks the network Public; one-line plain explanation |
| `home` ★ | Home: several phones | Choose files (drop zone) | One card per phone: status, copies line, keep period, «افتح المجلد», weekly code, phone settings; «أضف هاتفاً»; drop zone to send to a phone |
| `phone` ★ | A phone's folder | Send N to the phone | Browse the phone's photos, select → «أرسل إلى الهاتف»; open folder |
| `phoneSettings` ★ | Phone settings | — (list) | Name, folder + «افتح المجلد», weekly code, keep period (set on the phone), data backup, detach |
| `detach` ★ | Detach a phone: confirm | Detach phone | Files stay in the phone's folder; nothing deleted |
| `addPhone` ★ | Add a phone | (waits for the new phone to scan) | Each phone gets its own folder, weekly code and settings |
| `weekly` ★ | Weekly code | Close | Large 2-digit code; what pauses (and what continues) without it |
| `disk2` ★ | Second disk | Use this disk | None / internal / external; every file saved twice; external: plug in weekly |
| `homeRemind` ★ | Home: calm reminder | Choose files (unchanged); the reminder offers only Later | External disk not connected for 9 days |
| `homeRemind2` ★ | Home: firmer reminder | Choose files (unchanged) | The phone's 30-day trash is close to expiring for files with one copy |
| `diskBad` ★ | Home: disk problem | Choose a new disk to rebuild the copy | Final moves paused, copying continues |
| `rebuild` ★ | Home: rebuilding the copy | (progress; Pause) | Rebuild on the new disk; final moves resume when done |
| `sendTo` ★ | Send to: one phone or all | Send | Choose one phone or all; offline phones queue |
| `queued` ★ | Home: waiting for the phone | Choose files | «ينتظر اتصال الهاتف» on the offline phone's card |
| `ctxMenu` ★ | Windows right-click menu | (menu) | Explorer «أرسل إلى الهاتف» › one phone / all phones |
| `dataPc` ★ | Phone data backup | Restore to the phone… | Same switches as on the phone; a switch turned on from the PC says the phone will ask for the permission |
| `restorePc` ★ | Restore to the phone: what | Restore to phone | Choose items; merged, never deleted |
| `dest` ★ | Where files go | (choose drive / layout) | Root folder; one folder per phone; layout inside it; first copy on a fixed drive, external disk as the second copy |
| `history` ★ | History | — (read only) | Backups, data backups, second copy, file checks, final moves, sends, pairings |
| `scanOk` | File check: all good | Check now | Weekly integrity check |
| `scanBad` ★ | File check: problem found | Repair all 3 files | Repair from the phone, the phone's trash or the second disk; final moves paused |
| `settings` ★ | Settings | — (list) | Phones (each → phone settings, add a phone), Storage (where files go, second disk), General, Help; Advanced collapsed |
| `settingsAdv` ★ | Settings, advanced open | — | Port (firewall: private networks and networks you allow), weekly file check (both disks), diagnostic log |
| `tray` ★ | Tray menu | Open Kiwi Transfer | Status, send files to a phone, weekly code, pause 1 hour, quit |
| `update` | Update available | Update now | Version, size, signed release |
| `report` ★ | Report a problem | Open in mail program | Exact preview, copy text, log optional |
| `about` ★ | About | Check for updates | Chosen app icon; version, privacy, source, licences |

## Tucked into Settings on purpose

These exist but never compete with the main flow:

- **Phone, Settings:** what to back up, when, keep on my phone (and per-folder periods), back up your data, restore, pair another PC, free up space, trash, language, appearance, troubleshooting, report, about.
- **Phone, Advanced (collapsed):** back up only while charging, trash period (default 30 days), weekly check, receiving from the PC (ask / always accept from a PC), diagnostic log (off, stays on the phone).
- **PC, Settings:** phones (each with its own settings, detach), add a phone, where files go, second disk, start with Windows, language, appearance, report, about.
- **PC, Advanced (collapsed):** port (automatic), weekly file check schedule, diagnostic log (off, stays on the PC).
- **PC, per phone:** folder, weekly code, data backup, detach. Folders have no passwords or locks: files are plain and open from Explorer.
