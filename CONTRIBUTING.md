# Contributing | المساهمة

## العربية

- **المشكلات (Issues) مرحّب بها**: الأخطاء والاقتراحات. لا ترفق ملفات أو صورًا شخصية؛ الصفحات عامة.
- **طلبات الدمج (Pull requests)**: افتح مشكلة أولًا تصف التغيير ونتفق على الاتجاه قبل كتابة الشيفرة.
- الترجمات: راجع `TRANSLATING.md`. الثغرات الأمنية: راجع `SECURITY.md` ولا تنشرها علنًا.
- بالمساهمة توافق على ترخيص مساهمتك بموجب Apache-2.0 (القسم 5 من الرخصة).
- نلتزم بـ `CODE_OF_CONDUCT.md`.

## English

- **Issues are welcome**: bugs and suggestions. Never attach real files or personal photos; issues are public.
- **Pull requests**: open an issue first describing the change so we agree on the direction before you write code.
- Translations: see `TRANSLATING.md`. Security problems: see `SECURITY.md`, do not post them publicly.
- By contributing you license your contribution under Apache-2.0 (section 5 of the licence).
- We follow `CODE_OF_CONDUCT.md`.

## Checks a change must pass

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check

cd android
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug
```

CI runs the same checks on Windows and Linux.

## Conventions

- Version numbers follow [SemVer 2.0.0](https://semver.org/); the Git tag is `vX.Y.Z`.
- Every user-visible change gets a line under "Unreleased" in `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- Every source file starts with an SPDX header (see "Licence headers" below).
- Free and open-source dependencies only. Every new dependency must pass `cargo deny` (licence allow-list in `deny.toml`) and be justified in the pull request.
- No telemetry, no accounts, no network traffic other than the transfer itself.
- Keep the Arabic and English texts in step.

## Licence headers (REUSE)

The project follows the [REUSE](https://reuse.software/) specification. Each source file begins with these two lines, in the file's own comment syntax:

```
SPDX-FileCopyrightText: 2026 FastKiwi (Sarmad)
SPDX-License-Identifier: Apache-2.0
```

Files that cannot carry a header (images, lock files, generated files) are covered by `REUSE.toml`. Third-party files keep their own licence and copyright lines. Contributors may add their own `SPDX-FileCopyrightText` line to files they change substantially.
