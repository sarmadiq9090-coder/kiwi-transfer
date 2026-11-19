# Kiwi Transfer 1.0 — design system

Kiwi Transfer copies or moves photos, videos and files from an Android phone to a Windows PC over the home Wi‑Fi. No cloud, no account, no ads, open source.

The mock-ups are the reference: `phone.html` (Android) and `pc.html` (Windows). Open them in any browser; ع / EN switches language and the moon/sun switches theme. `SCREENS.md` lists every screen and what it is for.

## 1. Principles

The owner asked for a design that is "premium, simple and clear, like Apple's design philosophy". We take the principles, not the look: no Apple fonts, icons, SF Symbols or layouts. Controls stay native: Material 3 on Android, Fluent on Windows.

1. **Clarity first.** Every screen answers one question ("are my photos safe?", "what will be deleted?") in a single sentence, in large type.
2. **One clear action per screen.** One filled button. Other actions are text buttons, list rows or tucked into Settings.
3. **Works with zero setup.** Defaults are safe and useful: copy (never delete), camera and screenshots on, back up automatically on Wi‑Fi, year/month folders on the largest fixed drive. Final move is off everywhere until the user turns it on per folder.
4. **Defer to content.** Photos and the status line are the heroes. Chrome is quiet: no gradients on controls, no decorative borders, one accent colour.
5. **Depth with meaning.** Shadows only for things that float (dialogs, sheets, menus). Cards are flat on light, tinted on dark.
6. **Calm, meaningful motion.** Motion shows where something goes (a photo travels phone → PC) or where something came from (a sheet rises from the bottom). Nothing bounces, spins for fun or celebrates.
7. **Honest about risk.** Anything that deletes says so in plain words before it happens, shows the count, and says how to undo it (trash, 30 days).
8. **Generous whitespace.** 24 dp side margins on the phone, 36 px on the PC. When in doubt, remove an element instead of shrinking it.

## 2. Colour tokens

Derived from the FastKiwi site tokens (`sarmadiq9090-coder.github.io/style.css`: `--bg #fbfdf8`, `--text #14200f`, `--muted #4a5a42`, `--brand-dark #2f6f10`, `--border #e2ead8`). One accent: FastKiwi green. Amber and red are for warnings and destructive actions only.

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#FBFDF8` | `#0F150C` | Screen / page background |
| `surface` | `#FFFFFF` | `#172014` | Cards, dialogs, sheets |
| `surface-2` | `#F2F8EB` | `#1E2A19` | Notes, icon wells, chips |
| `surface-3` | `#E8F0DF` | `#26331F` | Selected nav, progress track, switch off |
| `line` | `#E2EAD8` | `#2B3826` | Dividers, card borders |
| `outline` | `#75856C` | `#8A9A82` | Control outlines (3:1 or better) |
| `text` | `#14200F` | `#EAF2E3` | Primary text |
| `text-2` | `#4A5A42` | `#A9B8A0` | Secondary text |
| `accent` | `#2F6F10` | `#8FD14F` | Primary buttons, selection, links |
| `on-accent` | `#FFFFFF` | `#0F1A08` | Text on accent |
| `accent-soft` | `#E8F3DC` | `#22331A` | Tonal buttons, "OK" pills, hero circle |
| `on-accent-soft` | `#1F4A0A` | `#CBEFA6` | Text on accent-soft |
| `warn` / `warn-soft` | `#8A5A00` / `#FFF4DC` | `#F2C063` / `#2E2610` | Problems, "copy only", "no other copy" |
| `danger` / `danger-soft` | `#B3261E` / `#FCE8E6` | `#FFB4AB` / `#3A1A17` | Destructive confirmation only |
| `mica` (PC) | `#F3F6EF` | `#121A0F` | Window title bar and navigation pane |

Icon-only colours (never used for text): forest `#123B2A` / `#2F6249`, apricot `#FFC27A`, lime `#B9F34A`.

**Contrast (WCAG 2.2, measured):**

| Pair | Light | Dark |
|---|---|---|
| text on bg | 16.5 | 16.2 |
| text-2 on bg | 7.2 | 8.9 |
| text-2 on surface-3 | 6.3 | 6.4 |
| accent on bg | 6.0 | 10.1 |
| on-accent on accent | 6.2 | 9.7 |
| on-accent-soft on accent-soft | 9.0 | 10.6 |
| warn on warn-soft | 5.4 | 8.9 |
| danger on bg | 6.4 | 10.9 |
| outline on bg (non-text, needs 3:1) | 3.9 | 6.2 |

All text pairs pass AA (4.5:1); most pass AAA.

## 3. Typography

**One typeface: IBM Plex Sans Arabic** (SIL Open Font License 1.1, see `licenses/OFL-IBM-Plex-Sans-Arabic.txt`). It contains matching Arabic and Latin, so Arabic and English look like one family. Weights: 400 and 700 only. It is bundled with both apps (no download at run time). Digits are Western (0–9) in both languages.

Monospace (report preview only): the platform's own (Cascadia Mono on Windows, the system monospace on Android).

| Role | Phone (sp) | PC (px) | Weight |
|---|---|---|---|
| Display (home status) | 28 / 1.3 | 28 / 1.3 | 700 |
| Headline (screen question) | 26 / 1.3 | 20 / 1.35 | 700 |
| Title (app bar, dialog) | 20–22 | 20 | 700 |
| Body | 16 / 1.55 | 14 / 1.6 | 400 |
| Label (buttons, row titles) | 16 | 14 | 700 |
| Caption | 13 / 1.5 | 13 | 400 |
| Big number (code, space saved) | 40–56 | 34–84 | 700 |

Rules: never below 13 for Arabic. All sizes in sp on Android so text scales to 200 %; layouts use wrapping rows and scrolling content, never fixed-height text boxes. Long titles wrap; they are not truncated, except in the app bar where the full title is also the screen's headline.

## 4. Spacing, radius, elevation

**Spacing:** 4-point grid. Steps 4, 8, 12, 16, 24, 32, 48. Phone side margin 24 dp; PC content padding 36 px horizontal, 28 px vertical. Space between groups (24) is always larger than space inside a group (8–12).

**Size:** touch targets ≥ 48 dp on the phone (primary button 56 dp, rows ≥ 64 dp, icon buttons 48 dp). PC controls follow Fluent: buttons 34–40 px, nav items 40 px, rows ≥ 64 px (WCAG 2.5.8 needs 24 px).

| Radius | Phone | PC |
|---|---|---|
| Buttons | 28 (full pill) | 5 |
| Cards | 24 | 8 |
| Dialogs | 28 | 8 |
| Sheets | 28 top corners | — |
| Window | — | 8 |
| Photo tiles | 4 (12 when selected) | 4 |
| Drop zone | — | 12 |

**Elevation:** two levels only.
- Level 1 (`sh-1`): resting cards on light. On dark, cards are separated by a lighter surface instead of a shadow.
- Level 3 (`sh-3`): dialogs, sheets, menus. Always with a scrim (`rgb(20 32 15 / .42)` light, black 60 % dark) when modal.

## 5. Motion

| What | Duration | Easing |
|---|---|---|
| Press feedback (button scales to 98 %) | 120 ms | standard `cubic-bezier(.2,0,0,1)` |
| Switch, selection, fade | 200–250 ms | standard |
| Dialog / sheet / menu enters | 250–350 ms | emphasised decelerate `cubic-bezier(.05,.7,.1,1)` |
| Progress bar update | 600 ms | standard |
| Backup "photo flight" loop | 3.2 s per photo, 3 photos staggered | `cubic-bezier(.45,0,.3,1)` |

Rules:
- Motion explains direction or cause. The photo flies from the phone to the PC along a soft arc and shrinks as it lands; in Arabic the scene is mirrored so it still reads start → end.
- Exits are faster than entrances. Nothing bounces or overshoots.
- `prefers-reduced-motion` / Android "Remove animations": all loops stop; the backup screen shows one photo resting at the top of the arc, the QR scanner line sits still.

## 6. Icons

- **Android:** Material Symbols Rounded, weight 400, grade 0, 24 dp (Apache License 2.0).
- **Windows:** Fluent UI System Icons, Regular, 20 px (MIT License).
- The mock-ups draw simplified line glyphs of the same meaning so the files stay self-contained; production swaps them 1:1.
- Icons always sit beside a text label, except universally known ones in the app bar (back, settings, history), which carry an accessible label.
- Directional icons (back, chevrons) mirror in Arabic; media, clock and check icons do not.

**App icon** (`icon.svg`, chosen by the owner; 256 grid, adaptive-icon safe zone respected): a phone, a lime arrow and a computer side by side on one line, on FastKiwi forest green, plus the small lime FastKiwi leaf in the corner. It reads left to right in every language (it is a picture, not text, so it does not mirror). Readable at 48, 32 and 24 px (see `review/contact-icons.png`). `icon-mono.svg` is the same drawing in one colour, without the tile and leaf, enlarged to the safe zone: the template for the Android 13 themed icon, notifications and the Windows tray (tinted by the system; white on dark). The mock-ups use `icon.svg` wherever the app icon appears (About, title bar, tray). The rejected directions are kept in `icon-alternatives/` for comparison.

## 7. Wording

Voice: a calm, competent friend. Short sentences, everyday words, second person. Say what happens, then why, in that order.

| Do | Don't |
|---|---|
| «صورك في أمان على حاسوبك» / "Your photos are safe on your PC" | «اكتملت عملية المزامنة بنجاح» / "Synchronisation completed successfully" |
| «انسخ الآن» / "Back up now" | «بدء النسخ الاحتياطي» / "Initiate backup" |
| «سيصبح حاسوبك النسخة الوحيدة» / "Your PC becomes the only copy" | «سيتم حذف الملفات المصدر» / "Source files will be deleted" |
| «لا أجد حاسوبي» / "I can't find my PC" | «خطأ في الاتصال: 0x80072EFD» / "Connection error 0x80072EFD" |
| «تنتظر في سلة المهملات 30 يوماً» / "They wait in the trash for 30 days" | «يمكن استرجاع العناصر المحذوفة» / "Deleted items are recoverable" |
| «حدّث الآن» · «لاحقاً» / "Update now" · "Later" | «موافق» · «إلغاء» for everything / "OK" · "Cancel" everywhere |

Rules:
1. Buttons are verbs that name the result: «احذف من الهاتف» / "Remove from phone", never «نعم» / "Yes".
2. Numbers are exact and Western digits: «1,976 عنصراً», "1,976 items". Sizes: «3.2 غيغابايت» in Arabic, "3.2 GB" in English.
3. Destructive actions always state count, place and undo: "Remove 1,976 items from this phone? … You can bring them back from the trash within 30 days."
4. No jargon in the main flow: "Wi‑Fi", "PC", "phone", "trash" — not "LAN", "host", "client", "hash". The technical words live only in Settings › Advanced and in the report preview.
5. Arabic is written natively (Modern Standard, light and friendly), not translated word by word. Use «حاسوب», «هاتف», «نسخ», «نقل نهائي», «سلة المهملات» consistently.
6. Errors say what to do next: «جرّب الشبكة الرئيسية» / "Try your main network".
7. Device names are the user's own; sample data uses invented names only (هاتف سارة / Sara's phone, هاتف كريم / Karim's phone, حاسوب البيت / Home PC).

## 8. Platform notes

**Android (Material 3):** top app bar, filled / tonal / text buttons, list rows, switches, radio buttons, bottom sheets, dialogs, segmented buttons. Edge-to-edge with the gesture bar. The share-sheet entry ("Send to PC") is a normal Android share target.

**Windows (Fluent):** Mica title bar and navigation pane, accent button, standard buttons, toggle switches, radio buttons, ContentDialog with the action bar at the bottom, an expander for advanced settings, and a tray icon with a context menu. Caption buttons and the whole layout mirror in Arabic, as Windows does.

**Both:** light and dark follow the system by default; Arabic first (RTL), English second; text scales to 200 %.
