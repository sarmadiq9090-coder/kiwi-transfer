# Security policy | سياسة الأمان

## الإبلاغ عن ثغرة

نرجو **عدم** نشر الثغرات في مشكلات (Issues) عامة.

1. استعمل الإبلاغ الخاص عن الثغرات في GitHub: تبويب **Security** في هذا المستودع ثم **Report a vulnerability**.
2. إن تعذّر ذلك: <https://fastkiwi.app/support/> (اذكر أن البلاغ أمني ولا تنشر التفاصيل علنًا).

نردّ خلال 7 أيام ونتفق معك على موعد النشر (إفصاح منسّق، عادةً خلال 90 يومًا من الإبلاغ أو بعد صدور الإصلاح). لا ترفق ملفات أو بيانات شخصية حقيقية؛ عيّنة تجريبية تكفي.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

1. Use GitHub private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**.
2. If that is not possible: <https://fastkiwi.app/support/> (say it is a security report and do not post details publicly).

We reply within 7 days and agree a disclosure date with you (coordinated disclosure, normally within 90 days of the report or once a fix is released). Please do not send real files or personal data; a synthetic sample is enough.

## Scope | النطاق

- The Android app, the Windows program and the shared Rust core in this repository, latest release (once there is one).
- Of special interest: breaking device pairing or mutual authentication, reading or altering a transfer in flight, writing outside the chosen destination folder (path traversal), and supply-chain issues in the build and release pipeline.

## Supported versions

Only the latest release receives security fixes.
