# Kiwi Transfer | كيوي ترانسفر

[العربية](#العربية) | [English](#english)

## العربية

**كيوي ترانسفر** تطبيق مفتوح المصدر لإرسال الملفات بين الأجهزة (أندرويد وويندوز) مباشرةً عبر الشبكة المحلية، بسرعة وتشفير كامل، دون حسابات ودون سحابة ودون وسيط.

> **الحالة: قيد التطوير، لم يُصدَر بعد.** لا توجد نسخ للتنزيل حتى الآن، وقد يتغير كل شيء.

### وعد الخصوصية

- لا حسابات، ولا إعلانات، ولا تتبّع، ولا تحليلات.
- الملفات تنتقل مباشرةً من جهاز إلى جهاز ومشفّرة (QUIC مع TLS 1.3 وتوثيق متبادل)، ولا تمر عبر أي خادم.
- لا يرسل التطبيق أي بيانات عنك أو عن ملفاتك إلى أي جهة.
- الشيفرة كاملة هنا، والإصدارات تُبنى علنًا مع قائمة مكوّنات (SBOM) وإثبات المصدر.

### المكوّنات

| المجلد | المحتوى |
|---|---|
| `android/` | تطبيق أندرويد (Kotlin وCompose، الحد الأدنى API 24، المعرّف `app.fastkiwi.transfer`) |
| `windows/` | برنامج ويندوز (Rust مع WebView2) |
| `core/` | النواة المشتركة بـ Rust (النقل، التشفير، البروتوكول) |
| `docs-build/` | وثائق البناء وإعادة إنتاج الإصدارات |

### البناء

المتطلبات: Rust (النسخة مثبّتة في `rust-toolchain.toml`)، وJDK 21، وAndroid SDK 36 مع NDK `27.3.13750724`.

```
# ويندوز والنواة
cargo build
cargo test

# أندرويد (من مجلد android)
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest :app:lintDebug
```

إصدار أندرويد النهائي يُوقَّع بمفتاح ليس في المستودع؛ دون المفتاح يُوقَّع البناء بمفتاح التصحيح ولا يصلح للتوزيع. التفاصيل: `docs-build/REPRODUCIBLE.md`.

### المساهمة والترجمة والأمان

راجع `CONTRIBUTING.md` و`TRANSLATING.md` و`SECURITY.md`. الرخصة: Apache-2.0.

## English

**Kiwi Transfer** is an open-source app for sending files directly between devices (Android and Windows) over the local network: fast, fully encrypted, with no accounts, no cloud and no middleman.

> **Status: in development, not released.** There are no downloads yet, and everything may change.

### Privacy promise

- No accounts, no ads, no tracking, no analytics.
- Files travel straight from device to device, encrypted (QUIC with TLS 1.3 and mutual authentication), never through a server.
- The app sends no data about you or your files to anyone.
- All the code is here, and releases are built in the open with an SBOM and build provenance.

### Layout

| Folder | Contents |
|---|---|
| `android/` | Android app (Kotlin and Compose, minSdk 24, package `app.fastkiwi.transfer`) |
| `windows/` | Windows program (Rust with WebView2) |
| `core/` | Shared Rust core (transfer, crypto, protocol) |
| `docs-build/` | Build notes and reproducible-build documentation |

### Building

Requirements: Rust (version pinned in `rust-toolchain.toml`), JDK 21, Android SDK 36 with NDK `27.3.13750724`.

```
# Windows program and core
cargo build
cargo test

# Android (from the android folder)
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest :app:lintDebug
```

The release Android build is signed with a key that is not in the repository; without it the build is signed with the debug key and is not fit for distribution. Details: `docs-build/REPRODUCIBLE.md`.

### Contributing, translating, security

See `CONTRIBUTING.md`, `TRANSLATING.md` and `SECURITY.md`. Licence: Apache-2.0.
