# Device authentication spike — 2026-10-26

This detached crate tests the transport choice required by
[ADR-017](../../../design-docs/20-adr.md) and [roadmap D1](../../../design-docs/19-roadmap.md).
It is not linked into either host and does not make the existing TCP transport authenticated.

## Hypothesis and scope

An identity approved out of band can use standard mutual TLS 1.3 to prove possession of its private key on a real
connection, without a custom certificate verifier or a homegrown cryptographic handshake.

The experiment uses rustls 0.23.45 with the ring provider and rcgen 0.14.10 for self-signed credentials. Each side's trust
store contains only the approved peer credential, rather than operating-system roots. Certificate names are deliberately
identical for all devices: knowing the public name does not authenticate a device. The normal WebPKI verifiers check
certificates and TLS handshake signatures. Connections select TLS 1.3 and the experimental `synra/1` ALPN; resumption,
session tickets and early application data are disabled. TLS 1.2 is compiled only for the negative client test.

Library references: [rustls configuration](https://docs.rs/rustls/0.23.45/rustls/struct.ConfigBuilder.html),
[rustls providers and platform support](https://docs.rs/rustls/0.23.45/rustls/index.html),
[rcgen credential generation](https://docs.rs/rcgen/0.14.10/rcgen/fn.generate_simple_self_signed.html).

## Observed results

Host: Windows x86_64, Rust 1.99.1 (`58cf8f9c3`, 2026-10-13); Android target: aarch64-linux-android,
NDK r28b (`28.1.13356709`), API 24.

| Scenario | Evidence |
| --- | --- |
| Persisted credential reconnects | Certificate and PKCS#8 key are written in an isolated temporary directory and reopened before a real loopback exchange |
| Payload confidentiality | Captured writes on the actual TCP sockets contain neither application request nor response marker; both endpoints observe TLS 1.3 |
| Server key replaced with the same certificate name | Client rejects; server never reaches the application boundary |
| Unpaired client key with the same certificate name | Server rejects before delivering any application request |
| Client omits its certificate | Server rejects before delivering any application request |
| Plain TCP request | TLS endpoint rejects, with no plaintext fallback or application admission |
| TLS 1.2 client | TLS 1.3 endpoint rejects before application admission |
| Copied public certificate with a different private key | Both client and server configuration reject the mismatched local identity |
| Android dependency graph | `cargo check` passes with the selected provider and NDK |
| Android test executable | All seven test cases compile and link into an Android AArch64 executable; not executed on Android |

Windows: seven tests pass; strict clippy and formatting pass. Socket connection, reads and writes have three-second
timeouts; ports are selected by the operating system. Rejection tests separately assert that the application boundary
was never reached, rather than treating any later I/O error as proof of authentication failure.

## Reproduction

Run from the core repository root:

```powershell
cargo clippy --manifest-path spike/device-authentication/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path spike/device-authentication/Cargo.toml
cargo fmt --manifest-path spike/device-authentication/Cargo.toml -- --check
```

For Android, point these process-local variables at the installed NDK, then run:

```powershell
$env:CC_aarch64_linux_android='C:/Android/ndk/28.1.13356709/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android24-clang.cmd'
$env:AR_aarch64_linux_android='C:/Android/ndk/28.1.13356709/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-ar.exe'
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$env:CC_aarch64_linux_android
cargo check --locked --manifest-path spike/device-authentication/Cargo.toml --target aarch64-linux-android --target-dir spike/device-authentication/target-android
cargo test --locked --manifest-path spike/device-authentication/Cargo.toml --target aarch64-linux-android --target-dir spike/device-authentication/target-android --no-run
```

The lockfile fixes the spike's dependency graph independently of the production workspace. Build directories are ignored.

## What this does not prove

**Production follow-up (2026-10-26):** the workspace now contains
[`synra-net::authentication`](../../crates/synra-net/src/authentication/mod.rs), with device-named credentials,
exact certificate pins, a bounded approved-peer list and a total handshake deadline. Its Windows tests and Android
compile/link evidence are recorded [separately](../../../design-docs/history/2026-10-26-device-authentication.md).
The limitations below describe this isolated experiment; host integration, protected storage, initial verification
and revocation still remain incomplete in the product.

The desktop result supports continuing with standard mutual TLS; it does not complete D1. Android compilation and linking
do not prove runtime randomness, filesystem access or socket behavior on a phone, and no Android execution was performed.
Neither `adb` on PATH nor the previously documented SDK's `platform-tools/adb.exe` was available during this experiment.

The next implementation must define initial out-of-band identity verification and cancellation, bind the authenticated
key to the application device id, protect and atomically persist private credentials, and handle credential loss,
unpairing, revocation and certificate lifetime. The DER files in this test are only a restart fixture, not a production
credential-storage policy. The spike assumes peer credentials have already been securely approved; it does not implement
an unauthenticated enrollment service, trust first discovery packets or permit business traffic during pairing.

Multiple peers, connection/session lifetimes, bounded handshake work and both hosts' production dispatch must still be
integrated and tested, including revocation during an existing connection. The existing transport remains unchanged.
