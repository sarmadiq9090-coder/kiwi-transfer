# Translating | الترجمة

Arabic is the default language and English is the second. Other languages are welcome.

## الأندرويد

- النصوص في `android/app/src/main/res/values/strings.xml` (العربية، اللغة الافتراضية) و`values-en/strings.xml` (الإنجليزية).
- للغة جديدة أنشئ المجلد `values-<رمز اللغة>/strings.xml` (مثل `values-fr`) وانسخ إليه كل المفاتيح من الملف الافتراضي، ثم أضف الرمز إلى `androidResources.localeFilters` في `android/app/build.gradle.kts`.
- حافظ على العناصر النائبة كما هي (`%1$s` و`%d`) وعلى ترتيب معانيها.

## Android

- Strings live in `android/app/src/main/res/values/strings.xml` (Arabic, the default) and `values-en/strings.xml` (English).
- For a new language create `values-<language code>/strings.xml` (for example `values-fr`), copy every key from the default file, and add the code to `androidResources.localeFilters` in `android/app/build.gradle.kts`.
- Keep placeholders (`%1$s`, `%d`) intact and in the same order of meaning.

## Windows

The Windows program will have its own string tables, documented here when its interface lands. Until then, translate the Android strings: the wording is shared.

## Guidelines

- Translate meaning, not word by word; keep it short, plain and friendly.
- Right-to-left languages must be checked on a device in that language.
- Never put personal data, real file names or real device names in a string.
- Send a pull request, or open an issue with the file attached if you do not use Git. By submitting you license your translation under Apache-2.0.
