<!--
SPDX-FileCopyrightText: 2026 FastKiwi (Sarmad)
SPDX-License-Identifier: Apache-2.0
-->
# Reproducible builds

Goal: anyone can rebuild a release from the tagged source and get the same bytes (F-Droid verifies
this before it ships our APK as its own). This follows the F-Droid guidance at
<https://f-droid.org/docs/Reproducible_Builds/> and the spike report (`docs/SPIKE-REPORT.md`, section 7).

## What is pinned

| Thing | Pin | Where |
|---|---|---|
| Rust compiler | `1.100.0` | `rust-toolchain.toml` (also in the workflows) |
| Rust crates | exact versions, `Cargo.lock` committed, builds use `--locked` | `Cargo.lock` |
| Android NDK | `27.3.13750724` | `ndkVersion` in `android/app/build.gradle.kts`; `ndk:` in the F-Droid recipe |
| Android Gradle Plugin / Kotlin | `8.13.2` / `2.2.21` | `android/gradle/libs.versions.toml` |
| Gradle | `8.14.3`, wrapper with `distributionSha256Sum` | `android/gradle/wrapper/` |
| JDK | 21 (Temurin) | CI and this document |
| UniFFI / JNA | `0.32.2` / `5.17.0` | Rust crate (later) / `libs.versions.toml` (later) |
| GitHub Actions | full commit SHAs | `.github/workflows/` |

## Rust settings

In the workspace `Cargo.toml` release profile: `codegen-units = 1`, `lto = true`, `opt-level = "s"`,
`strip = true`, `panic = "abort"`. A single codegen unit removes the ordering nondeterminism of
parallel code generation.

Environment for a release build (the release workflow sets these):

```
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
# Paths must not leak into the binary: remap the checkout and the cargo home.
export RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$CARGO_HOME=/cargo"
cargo build --release --locked
```

Also for F-Droid-style builds:

- Use a constant `CARGO_HOME` and `CARGO_TARGET_DIR`.
- Android targets: link with the NDK's clang wrappers, add `-C link-arg=-Wl,--build-id=none`, and strip
  the `.comment` section (the NDK's `llvm-strip` does this with `--strip-all`).
- Windows (MSVC): add `-C link-arg=/Brepro` so the PE header carries no timestamp.
- Generate the UniFFI Kotlin bindings during the build from an unstripped library; never commit generated
  bindings or prebuilt `.so` files (`android/app/src/main/jniLibs/` stays empty in git).

## Android settings

- `dependenciesInfo { includeInApk = false; includeInBundle = false }`: no signed dependency blob in the APK.
- `useLegacyPackaging = false`: native libraries are stored uncompressed and aligned; no timestamps from
  compression.
- Use build-tools 36.0.0 (`apksigner`, `zipalign`) for signing and verification; AGP 8.8+ produces
  reproducible APKs from identical inputs.
- Signing: the release key lives only in the `release` GitHub Environment and in the maintainer's
  git-ignored `android/keystore/`. A reproducible-build check compares the APK contents with the
  signature removed (F-Droid's `AllowedAPKSigningKeys` / `Binaries` flow), so the signing step does not
  have to be reproducible.

## Checking a release yourself

1. Check out the tag, install the pinned toolchain (`rustup` reads `rust-toolchain.toml`; JDK 21; NDK above).
2. Build with the commands above (Windows exe: `cargo build --release --locked -p kiwi-transfer`; Android:
   `./gradlew :app:assembleRelease` in `android/`).
3. Compare with the release asset: `sha256sum`, or `diffoscope` for the differences. Verify the release
   asset's provenance with `gh attestation verify <file> --repo <owner>/<repo>`.

## Status

The skeleton builds; byte-for-byte reproducibility has not been verified yet. It will be tested twice
(two clean machines) before the first release, and any difference recorded here.

## Licences of dependencies

`deny.toml` holds the allow-list (permissive licences only). JNA is dual-licensed LGPL-2.1-or-later OR
Apache-2.0; Kiwi Transfer uses it under Apache-2.0, so distribution stays Apache-2.0.
