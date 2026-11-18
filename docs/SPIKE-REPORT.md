# Kiwi Transfer technical spike - report (2026-11-18)

Host: Windows 11, i9-10900, rustc/cargo 1.100.0 (stable), NDK 27.3.13750724 (already in kiwi-scan `.tools`, 2.3 GB, no install needed),
JDK 21, Gradle 8.14.3, AGP 8.13.2, Kotlin 2.2.21. Sources: `core/` (Rust crate `kiwi_core` + bins `xfer`, `mdns`, `uniffi-bindgen`), `kt-module/` (Gradle lib).

## 1. Rust core on Android (API 24)
Crate: quinn 0.11.12, rustls 0.23.46 (custom `ServerCertVerifier` + `ClientCertVerifier` pinning BLAKE3(SPKI), TLS1.3 only, client auth mandatory),
blake3 1.8.7, rcgen 0.14, x509-parser 0.18, tokio 1.54, uniffi 0.32.2, mdns-sd 0.22.
Plain cargo + NDK clang wrappers as linker/CC (no `cargo-ndk` needed; script `core/build-android.sh`). First try succeeded for all targets.

Release (opt-level s, LTO, codegen-units 1, strip, panic abort), `.so` size in bytes:

| target | ring | aws-lc-rs |
|---|---|---|
| aarch64-linux-android | 2,075,400 | 2,688,032 |
| armv7-linux-androideabi | 1,269,456 | 1,700,660 |
| x86_64-linux-android | 2,443,312 | 3,236,328 |

Both providers build cleanly with NDK r27 clang on a Windows host (aws-lc-sys 0.47 found cmake/needed no NASM for these targets). ring is ~25% smaller and
needs no cmake. Not run on a device (no emulator). Notes: `.so` has NEEDED only libdl/libm/libc (good for API 24). LOAD segments are 4 KB aligned: for
Google Play's 16 KB page-size requirement add `-C link-arg=-Wl,-z,max-page-size=16384` (not tested here). x86_64 Android is only for emulators/Chromebooks; could be skipped.

## 2. UniFFI
Version 0.32.2 (proc-macro API, `uniffi-bindgen` built from the same crate, library mode). Exposed: `hash_file(path)`, `new_identity()`, `fingerprint()`,
callback interface `ProgressListener.on_progress(done,total)`, and `async fn send(...)` (feature `tokio`, `#[uniffi::export(async_runtime="tokio")]`).
Generated `kiwi_core.kt` (1377 lines) became `suspend fun send(...)`, `interface ProgressListener`, `sealed class XferException`. It compiled in an Android library
module (minSdk 24, `:lib:assembleRelease` BUILD SUCCESSFUL, aar with arm64 .so) with `net.java.dev.jna:jna:5.17.0@aar` + `kotlinx-coroutines-android:1.10.2`.
Friction: (a) bindgen needs UniFFI metadata, which a *stripped* .so does not contain; generate from an unstripped build or the host .dll (worked from the Windows dll);
(b) `#[uniffi::export(callback_interface)]` params must be `Box<dyn Trait>`, not `Arc<dyn Trait>` (needs `with_foreign` for Arc); (c) ktlint absent => unformatted output (harmless);
(d) the async runtime and JNA add runtime weight. JNA 5.17.0 aar: 522 KB compressed, `libjnidispatch.so` 124-176 KB per ABI, licence LGPL-2.1-or-later OR Apache-2.0 (choose Apache-2.0; pom lists LGPL).
Runtime not verified on a device.

## 3. PC loopback test (127.0.0.1, two processes, mutual auth, 1 GiB random file, BLAKE3)
Mutual auth works; wrong pin is rejected at handshake ("SPKI pin mismatch"). File byte-identical (`cmp`), stream hash == disk hash.

Run on NVMe C: (Samsung 980 Pro):
- Transfer phase (receiver, QUIC read + BLAKE3 + write to page cache): 3.99 s = **~269 MB/s**.
- CPU: sender 5.8 s CPU, receiver 6.5 s CPU (user+kernel, incl. the receiver's two verify reads); about 1.5 cores busy during the 4 s transfer. Single-stream, loopback; QUIC encryption + hashing in one task is the limit, not the disk.
- Commit (FlushFileBuffers on 1 GiB + `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`): 4.17 s (flush of dirty cache at ~255 MB/s).
- Verify read with FILE_FLAG_NO_BUFFERING (4 MiB, 4096-aligned buffer): 0.76 s = **~1.4 GB/s**; normal cached read+hash: 0.51 s (2.1 GB/s). Cost of uncached verify: +~0.25 s/GiB here.
On HDD E: (WD10EZEX): transfer 3.93 s (cache), commit 10.10 s, unbuffered verify 10.25 s (~105 MB/s, disk-bound), cached re-read 8.17 s; total wall 33 s.
Result: NO_BUFFERING + FlushFileBuffers + MoveFileEx(WRITE_THROUGH) all work on NTFS. Caveats: reads must use aligned buffer and sector-multiple sizes (tail read at EOF is fine);
this bypasses the OS cache but not the drive's own cache; for write-path durability also consider FILE_FLAG_WRITE_THROUGH. Dominant cost is the flush (disk speed), not the verify read.

## 4. mDNS on Windows (`mdns-sd` 0.22.0)
Advertise + browse `_kiwixfer._udp.local.` in one process: resolved in ~0.97 s with address 192.168.0.55, port 5555, TXT `fp=ab12`. Enumerated 2 interfaces
(Ethernet + loopback), also returned loopback/link-local addresses (filter them). Only same-host test; no second device available.
Firewall (read-only inspection, nothing changed): all three profiles enabled. Windows ships a built-in enabled inbound rule group "mDNS (UDP-In)" (UDP 5353, Domain/Private/Public)
and outbound "mDNS (UDP-Out)", so mDNS needs no app-specific rule. A prompt could not be observed from a non-interactive shell. The QUIC listener (inbound UDP on a chosen port, 0.0.0.0)
is what would trigger the "Allow app" prompt for a new exe on first bind; the installer should add an inbound UDP rule for the exe (Private profile) or the app should explain the prompt. Binding only to 127.0.0.1 (as in the test) never prompts.

## 5. PAKE for the 6-digit code
No audited Rust CPace/SPAKE2 exists (checked crates.io + READMEs):
- `spake2` (RustCrypto/PAKEs), 0.5.0-pre.0 (Jan 2026), ~2M downloads, used by magic-wormhole; README says "never received an independent third party audit" and "USE AT YOUR OWN RISK"; implements draft-irtf-cfrg-spake2-10 (Ed25519 only), not RFC 9382.
- `pake-cpace` (jedisct1) 0.1.7, Dec 2023, ~80k downloads, port of libsodium CPace, draft-haase-cpace-01 (old), no audit statement.
- `pakery-cpace/-spake2` 0.6.2 (Oct 2026), CPace draft / RFC 9382, README: "not independently audited", 2 stars, single maintainer.
- `opaque-ke` is audited (NCC) but is an asymmetric PAKE (needs a server record) - wrong shape.
Recommendation: ship v1 with QR (carries the SPKI fingerprint, so TLS pinning needs no PAKE) plus manual fingerprint/SAS comparison (e.g. 6 words or digits derived from both fingerprints) as fallback. Drop the typed 6-digit PAKE path from v1.
If wanted later: RustCrypto `spake2` bound to the QUIC TLS exporter, one attempt per code, 60 s expiry, flagged as unaudited.

## 6. Android rules (verified)
- Compose UI 1.12.1 (stable, 2026-09-09): AAR manifest minSdk 23 (verified in the aar from dl.google.com). Setup page still says API 21+: https://developer.android.com/develop/ui/compose/setup , releases: https://developer.android.com/jetpack/androidx/releases/compose-ui
- WorkManager 2.12.0 (2026-09-23): minSdk raised 23 -> **24** in this release (aar manifest 24 verified) - exactly our floor, any later bump breaks us: https://developer.android.com/jetpack/androidx/releases/work
- CameraX 1.6.2 (2026-08-26): minSdk 23 (default raised 21->23 in 1.5.0): https://developer.android.com/jetpack/androidx/releases/camera
- zxing-cpp Android wrapper `io.github.zxing-cpp:android:3.1.1` (Maven Central, Apache-2.0): minSdk 21, ships arm64-v8a/armeabi-v7a/x86/x86_64 .so (1.2-1.85 MB each); takes CameraX `ImageProxy`: https://github.com/zxing-cpp/zxing-cpp/tree/master/wrappers/android
- Delete media: API <=28 WRITE_EXTERNAL_STORAGE + MediaStore/File delete (works for other apps' files); API 29 needs targetSdk<=29 opt-out OR `requestLegacyExternalStorage="true"` (doc says the flag is ignored only on Android 11+ devices, so it still applies on 10 devices for a higher targetSdk; otherwise RecoverableSecurityException per file); API 30+ `MediaStore.createDeleteRequest()` (permanent) / `createTrashRequest()` (to system trash), both show a user dialog unless MANAGE_MEDIA (API 31+) is granted. https://developer.android.com/training/data-storage/shared/media , https://developer.android.com/training/data-storage/use-cases
- Visible trash folder on shared storage: API 24-28 yes (WRITE_EXTERNAL_STORAGE, any path under /sdcard); API 29 yes only with the legacy opt-out (requestLegacyExternalStorage) - not verified on a device; API 30+ no (legacy flag ignored, only MediaStore collections / app-specific dirs / SAF). So a self-made trash folder is an API 24-29 feature; use system trash on 30+.

## 7. F-Droid and Rust
- Build must be from source with FLOSS toolchain; rustup/Rust binaries are an explicitly allowed prebuilt source: https://f-droid.org/docs/Inclusion_Policy/
- Reproducibility guidance (pin NDK exactly; Rust: pin toolchain via `rustup-init.sh -y --default-toolchain <ver>`, `codegen-units = 1`, `--remap-path-prefix`, constant `CARGO_HOME`/`CARGO_TARGET_DIR`, `SOURCE_DATE_EPOCH`, linker `--build-id=none`, strip/`.comment` removal; apksigner build-tools 34; AGP 8.8+): https://f-droid.org/docs/Reproducible_Builds/
- Metadata: `ndk:` field, `srclibs`, `prebuild` (no compiling) vs `build` (compile), `commit` full hash, `AllowedAPKSigningKeys`/`Binaries`: https://f-droid.org/docs/Build_Metadata_Reference/ . The docs never mention Rust beyond the reproducibility page, so recipes copy existing apps.
- Example: Delta Chat (`com.b44t.messenger`, Rust deltachat-core): https://gitlab.com/fdroid/fdroiddata/-/raw/master/metadata/com.b44t.messenger.yml - uses `srclibs: rustup@...`, `sudo` apt install, `rustup-init.sh -y`, `scripts/install-toolchains.sh`, NDK on PATH, `scripts/ndk-make.sh <abi>`, `submodules: true`.
Implication: keep the Rust build a single script (`build-android.sh`-style) with pinned rust-toolchain.toml, Cargo.lock committed + `--locked`, vendored or crates.io only; generated UniFFI Kotlin should be built in the recipe (not committed binaries).

## Recommendations
- Crypto provider: **ring** (smaller, no cmake, builds clean); aws-lc-rs is a working fallback.
- NDK: **r27.3.13750724** (works, already installed). Pin it in the F-Droid recipe (`ndk:`) and Gradle `ndkVersion`.
- UniFFI: **0.32.2**, proc-macros, Box callback interfaces; JNA 5.17.0 aar (Apache-2.0 option); generate from unstripped lib.
- mDNS crate: **mdns-sd 0.22** (works on Windows; same crate compiles for Android, but on Android prefer NsdManager/ multicast lock from Kotlin and pass results to the core).
- PAKE: none audited - **QR + manual fingerprint compare for v1**; optional later `spake2` flagged unaudited.
- Verified-read: NO_BUFFERING works on NTFS, cost small on SSD; commit flush is the real cost.
Not tested: any on-device run, cross-device mDNS, multi-stream/real-network throughput.
