# CLAUDE.md - Complete Development Context for JavaCrypt

> **IMPORTANT**: This file contains ALL context needed for Claude AI to understand and work on JavaCrypt.
> If you're a new Claude session or different account, READ THIS FILE FIRST.

---

## 🎯 Project Summary (TL;DR)

**JavaCrypt** is a Jasypt-like encryption library for Java, the 6th member of a cross-language encryption family.

```
Owner       : Fariz Fadian (github.com/farizfadian)
Repository  : github.com/farizfadian/javacrypt
Maven       : io.github.farizfadian:javacrypt
Package     : io.github.farizfadian.javacrypt   (Automatic-Module-Name: the same)
CLI         : the library jar itself  ->  java -jar javacrypt-1.0.0.jar <command>
Env var     : JAVACRYPT_PASSWORD
Language    : Java 8 bytecode, built with JDK 17+ (CI builds with JDK 25)
License     : MIT
Dependencies: ZERO (only the JDK). Test scope: JUnit Jupiter 5.14, Gson, Jasypt 1.9.3
Created     : November 2026
Status      : ✅ IMPLEMENTED & TESTED (v1.0.0)   ⏳ NOT YET TAGGED, NOT YET ON MAVEN CENTRAL
Registry    : Maven Central (Sonatype Central Portal), see "Publish & Release Status"
Release     : GitHub Actions on tag push (v*); the Central upload waits for a manual Publish
```

---

## 🔗 Cross-Language Family (ALL SAME ENC() FORMAT!)

```
┌─────────────────────────────────────────────────────────────────┐
│                 Jasypt Encryption Library Family                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   🐹 GoCrypt    github.com/farizfadian/gocrypt     (Go)         │
│   🐍 PyCrypt    github.com/farizfadian/pycrypt     (Python)     │
│   📦 NodeCrypt  github.com/farizfadian/nodecrypt   (Node.js)    │
│   🐘 PHPCrypt   github.com/farizfadian/phpcrypt    (PHP)        │
│   🦀 RustCrypt  github.com/farizfadian/rustcrypt   (Rust)       │
│   ☕ JavaCrypt  github.com/farizfadian/javacrypt   (Java)       │
│   (Jasypt       jasypt.org                         Java)        │
│                                                                  │
│   SAME MODE ON BOTH SIDES: default, --jasypt, --jasypt-strong   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**GoCrypt is the reference implementation.** When in doubt, match GoCrypt byte-for-byte.
Never "improve" a wire format on your own: a value encrypted by any member must decrypt in every other member.

An `ENC(...)` value does not record its algorithm, so both sides must use the same mode.

---

## 🏗️ Why a Java member, when Java has Jasypt

Java Jasypt can read **one** of the family's three modes: `PBEWithMD5AndDES` (DES + MD5, no integrity check).
JavaCrypt lets a Java service read and write all three, in particular the default AES-256-GCM mode. A value
encrypted without `--jasypt` then works in all six languages.

| Mode (CLI flag) | Class | Go / Python / Node / PHP / Rust | Java Jasypt | JavaCrypt |
|-----------------|-------|---------------------------------|-------------|-----------|
| (none) | `Encryptor` | ✅ | ❌ no such mode | ✅ |
| `--jasypt` | `JasyptEncryptor` | ✅ | ✅ | ✅ |
| `--jasypt-strong` | `JasyptStrongEncryptor` | ✅ | ❌ Jasypt writes a random IV after the salt | ✅ |

```java
// ✅ a value another family member wrote in the default mode
Encryptor enc = new Encryptor(password);

// ✅ a value that an application using the real Jasypt library must read
JasyptEncryptor enc = new JasyptEncryptor(password);
```

---

## 📁 Project Structure

```
javacrypt/
├── pom.xml                        # release 8, zero deps (enforcer), warnings fail, "release" profile
├── mvnw, mvnw.cmd, .mvn/          # Maven wrapper (Maven 3.9.16, script-only)
├── src/main/java/io/github/farizfadian/javacrypt/
│   ├── package-info.java          # package docs with the mode table
│   ├── JavaCrypt.java             # ENC_PREFIX/SUFFIX, isEncrypted, version()
│   ├── ErrorCode.java             # enum
│   ├── JavaCryptException.java    # the one unchecked exception: getCode(), getKey()
│   ├── StringEncryptor.java       # encrypt/decrypt + 5 default methods (the ENC(...) helpers)
│   ├── Encryptor.java             # AES-GCM 128/192/256, Builder
│   ├── JasyptEncryptor.java       # PBKDF1-MD5 + DES-CBC, Builder
│   ├── JasyptStrongEncryptor.java # PBKDF2 + AES-256-CBC (family layout), Builder
│   ├── ConfigLoader.java          # env, flat YAML, properties, setToSystemProperties
│   ├── Kdf.java                   # package-private: pbkdf2Sha256(), pbkdf1Md5(), written by hand
│   ├── Internal.java              # package-private: base64, strict UTF-8, trimming, ENC scan,
│   │                              #   cipher helpers that map provider failures
│   └── cli/Main.java              # the command line (uses only the public API)
├── src/main/resources/.../version.properties   # filtered: version=${project.version}
├── src/test/java/...              # see "Testing Status"
├── src/test/resources/
│   ├── gocrypt_vectors.json           # byte-identical copy of RustCrypt's fixture. DO NOT regenerate
│   └── gocrypt_vectors_unicode.json   # generated here: non-ASCII password and plaintexts
├── scripts/
│   ├── gen-vectors/               # Go: produces the vectors from the real gocrypt module
│   └── changelog-section.sh       # release notes for one version, used by release.yml
├── examples/smallrye-config/      # Quarkus / SmallRye Config interceptor (own pom, not published)
├── .github/workflows/             # ci.yml, release.yml
├── README.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md, LICENSE
└── CLAUDE.md                      # this file
```

---

## 📐 Wire Formats (MUST match GoCrypt exactly)

All outputs are **standard base64 with padding**, wrapped as `ENC(<base64>)` by the `*WithPrefix` variants.
Passwords and plaintext are **UTF-8**. Empty (or null) password → `EMPTY_PASSWORD`. Empty (or null) value → `EMPTY_VALUE`.

### `Encryptor` - AES-256-GCM (family-internal, NOT readable by Java Jasypt)

| Parameter | Default | Configurable |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA256 | — |
| Iterations | `10000` | `builder(pw).iterations(n)` |
| Salt size | `16` bytes, random | `.saltSize(n)` |
| Key size | `32` bytes (AES-256) | `.keySize(16\|24\|32)` |
| Nonce | `12` bytes, random | — |
| AEAD | AES-GCM, tag 16 bytes appended to ciphertext, no AAD | — |
| **Output** | `base64( salt ‖ nonce ‖ ciphertext ‖ tag )` | |

Decrypt: fewer than `saltSize + 12 + 16` bytes, a bad tag, or plaintext that is not UTF-8 → `DECRYPTION_FAILED`, no detail.

### `JasyptEncryptor` - PBEWithMD5AndDES (Java Jasypt default, ✅ compatible)

| Parameter | Value |
|---|---|
| KDF | PBKDF1 with MD5: `h = md5(password ‖ salt)`, then `h = md5(h)` for a total of `iterations` MD5 calls |
| Iterations | `1000` (Jasypt default), `builder(pw).iterations(n)` |
| Salt size | `8` bytes, random |
| Key / IV | `h[0..8]` = DES key, `h[8..16]` = IV |
| Cipher | DES-CBC, PKCS5 padding |
| **Output** | `base64( salt ‖ ciphertext )` |

Decrypt: fewer than 16 bytes or ciphertext not a multiple of 8 → `INVALID_JASYPT_DATA`. Bad padding or non-UTF-8 → `DECRYPTION_FAILED`.
No integrity check: a wrong password gives an error or, rarely, garbage. Tests assert "error or not equal to the plaintext".

### `JasyptStrongEncryptor` - "PBEWithHmacSHA256AndAES_256" (family format, NOT real Jasypt)

| Parameter | Value |
|---|---|
| KDF | PBKDF2-HMAC-SHA256, `1000` iterations (`.iterations(n)`), derive **48 bytes** |
| Salt size | `16` bytes, random (`.saltSize(n)`) |
| Key / IV | `derived[0..32]` = AES-256 key, `derived[32..48]` = IV |
| Cipher | AES-256-CBC, PKCS7 padding (`AES/CBC/PKCS5Padding` in Java) |
| **Output** | `base64( salt ‖ ciphertext )` |

Decrypt: fewer than `saltSize + 16` bytes or ciphertext not a multiple of 16 → `INVALID_JASYPT_DATA`.

⚠️ Real Jasypt writes `salt ‖ random IV ‖ ciphertext`. The key derivation is identical; only the IV differs.
`JasyptInteropTest.theOnlyDifferenceToJasyptsStrongFormatIsWhereTheIvComesFrom` proves it: with the derived IV
inserted after the salt, Jasypt reads a family value. **Do not "fix" this alone**: it is a coordinated change
across all six libraries.

### Shared helpers

```
ENC_PREFIX = "ENC("     ENC_SUFFIX = ")"     scan pattern: ENC\(([^)]+)\)
```

- `JavaCrypt.isEncrypted(value)` - trimmed value starts with `ENC(` and ends with `)`; `null` → false
- `decryptPrefixed(value)` - trims, checks the wrapper (`INVALID_ENC_FORMAT`), decrypts the inside
- `decryptAllInString(input)` - replaces every match; a failing match keeps its text and the **last** error is thrown after the whole input was processed (GoCrypt semantics)
- `decryptAllInStringLossy(input)` - same, never throws; used by the CLI `decrypt-file`
- `decryptMap(map)` - decrypts wrapped values, copies the rest (and `null`), keeps order; the first failure aborts with `KEY_DECRYPT` naming the key
- Trimming uses Unicode White_Space like Go's `TrimSpace` and Rust's `trim`, **not** `String.trim()`
- Base64 follows Go's decoder: CR/LF ignored, padding required (`Base64.getDecoder()` alone would accept unpadded input)

Error messages match GoCrypt: `password cannot be empty`, `value cannot be empty`,
`invalid encrypted format, expected ENC(...)`, `invalid jasypt encrypted data`, `decryption failed`,
`failed to decode base64: ...`, `failed to decrypt key <key>: <cause>`.

---

## 🧭 Design Decisions (and why)

1. **Java 8 bytecode** (`maven.compiler.release` 8, main and test). The library is tiny, every algorithm exists in Java 8, and Jasypt's audience includes old Java 8 applications. Built with a current JDK; the Java 8 claim is proven by running the tests on a Java 8 runtime in CI.
2. **Zero runtime dependencies**, enforced by maven-enforcer (`bannedDependencies`).
3. **Key derivation is written by hand** (`Kdf`): PBKDF2 over `Mac("HmacSHA256")` and PBKDF1 over `MessageDigest("MD5")`, on the UTF-8 bytes of the password, like GoCrypt. The JDK's password-based key factories are **not** used: how they turn a `char[]` into bytes depends on the provider and the JDK version. Evidence from CI: the JDK's `PBEWithMD5AndDES` factory throws `Password is not ASCII` on Java 8, 11, 17 and 21 and accepts it on 25.
4. **One artifact**: the jar is the library and the CLI (`Main-Class` in the manifest). No CLI framework.
5. **One unchecked exception** with an `ErrorCode` enum.
6. **Immutable, thread-safe encryptors**; a `Cipher` per call.
7. **No JSON loader** (it would need a dependency). The README shows a recipe that is itself a test (`JsonRecipeTest`). `decryptAllInString` must not be used on raw JSON: the plaintext is not escaped.
8. **`setToSystemProperties`** instead of the family's `setToEnv`: a Java process cannot change its environment.
9. **Provider failures are split in two** (`Internal.encrypt/decrypt`): setting up the cipher fails only if the runtime lacks the algorithm or refuses the key size → `UNSUPPORTED` with the cause; anything after that → `DECRYPTION_FAILED` without a cause.
10. **The CLI never uses the platform charset**: files are UTF-8, redirected output is UTF-8 with `\n`, an interactive console gets its own charset.

---

## 💻 Commands

```bash
# Full gate (what CI runs). Needs JDK 17+; the wrapper downloads Maven.
./mvnw verify                                  # warnings fail, unit tests, then JarIT against the jar
./mvnw -Prelease -Dgpg.skip verify             # + sources and javadoc jars; javadoc warnings fail

# One class
./mvnw test -Dtest=GoldenVectorsTest

# Tests on another Java runtime (how CI covers 8, 11, 17, 21)
./mvnw verify -Djvm=/path/to/jdk/bin/java

# Live cross-language round trips (binaries from the GitHub release pages)
GOCRYPT_CLI=/path/gocrypt-cli RUSTCRYPT_CLI=/path/rustcrypt ./mvnw test -Dtest=CrossLanguageCliTest

# Example
./mvnw -DskipTests install && ./mvnw -f examples/smallrye-config/pom.xml verify

# Regenerate the non-ASCII vectors (needs Go)
cd scripts/gen-vectors && go run . -set unicode -commit <gocrypt commit> -out ../../src/test/resources/gocrypt_vectors_unicode.json

# CLI
java -jar target/javacrypt-1.0.0.jar encrypt -p password -v "secret" --jasypt
java -jar target/javacrypt-1.0.0.jar decrypt -p password -v "ENC(...)"
java -jar target/javacrypt-1.0.0.jar encrypt-file -p password -i .env.plain -o .env.encrypted
```

---

## 📝 API Reference

```java
import io.github.farizfadian.javacrypt.*;

Encryptor enc = new Encryptor(password);
Encryptor custom = Encryptor.builder(password).iterations(50_000).saltSize(32).keySize(32).build();
JasyptEncryptor jasypt = JasyptEncryptor.builder(password).iterations(2_000).build();
JasyptStrongEncryptor strong = JasyptStrongEncryptor.builder(password).iterations(5_000).saltSize(16).build();

String wrapped = enc.encryptWithPrefix(plaintext);     // ENC(...)
String plain = enc.decryptPrefixed("ENC(...)");
Map<String, String> decrypted = enc.decryptMap(config);
String text = enc.decryptAllInString(configText);

ConfigLoader loader = new ConfigLoader(password);                     // AES-256-GCM, like GoCrypt
ConfigLoader forJasypt = new ConfigLoader(new JasyptEncryptor(pw));   // any StringEncryptor
Map<String, String> env = loader.loadEnvFile(".env");
Map<String, String> yml = loader.loadYaml("config.yml");              // flat key: value
Properties props = loader.loadProperties("app.properties");           // UTF-8 unless a charset is given
loader.setToSystemProperties(".env");
```

---

## 🧪 Testing Status

185 unit tests + 5 jar tests. Locally (JDK 25, Windows) 6 are skipped by assumptions; see below.

| Suite | Count | Notes |
|-------|-------|-------|
| `GoldenVectorsTest` | 17 | both fixtures: KDF outputs, fixed-salt output byte for byte in 3 modes, every GoCrypt value decrypts |
| `KdfTest` | 4 | published PBKDF2 vectors; agreement with the JDK's PBKDF2 for ASCII and non-ASCII passwords |
| `EncryptorTest` / `JasyptEncryptorTest` / `JasyptStrongEncryptorTest` | 25 / 19 / 22 | shared `EncryptorContract` + format-specific: tamper, truncate, wrong password, bad base64, non-UTF-8 plaintext, threads |
| `InternalTest` | 4 | provider failures: `UNSUPPORTED` vs `DECRYPTION_FAILED` |
| `StringEncryptorTest`, `JavaCryptTest` | 13, 4 | the `ENC(...)` helpers (port of RustCrypt's `prefix.rs` tests), `$` and `\` in plaintext |
| `JasyptInteropTest` | 9 | real Jasypt 1.9.3, both directions; what Jasypt cannot read |
| `ConfigLoaderTest` | 20 | env, YAML, properties, system properties, BOM/CRLF, non-UTF-8 files |
| `JsonRecipeTest` | 3 | the README's JSON recipe |
| `cli.MainTest` | 32 | in-process; a port of RustCrypt's `tests/cli.rs` plus JVM-specific cases |
| `cli.MainProcessTest` | 8 | real child JVMs: bytes on stdout, default charset variants, non-ASCII args and env |
| `CrossLanguageCliTest` | 4 | live against `gocrypt-cli` and `rustcrypt`; skipped unless `GOCRYPT_CLI` / `RUSTCRYPT_CLI` are set |
| `RuntimeVersionTest` | 1 | fails if tests run on another Java major than `JAVACRYPT_EXPECT_JAVA` (CI sets it) |
| `cli.JarIT` (failsafe) | 5 | `java -jar` on the packaged jar; manifest; every class is class-file version 52 |

### What CI proves (run 44445171812, commit 8c45e3c, 2026-11-19: 22/22 jobs green)

- **Java 8, 11, 17, 21, 25 × Linux, Windows, macOS** (15 cells): jar built with JDK 25, tests run on the cell's JVM.
- **Cross-language** on all three OS: released `gocrypt-cli` v1.0.0 and `rustcrypt` v1.0.0, sha256 checked, 3 modes, both directions, ASCII and non-ASCII password. A missing binary fails the job (`JAVACRYPT_REQUIRE_CLIS`).
- **Lint**: javadoc and compiler warnings as errors; a second build gives byte-identical jars.
- **Example**: SmallRye Config 4.2.2 and 3.18.3.
- **Audit**: osv-scanner over the test dependencies.

### Skipped by assumption (and why that is correct)

| Test | Skipped on | Reason |
|------|-----------|--------|
| Jasypt with a non-ASCII password (2 tests) | Java 8, 11, 17, 21 | Jasypt itself fails there: `InvalidKeySpecException: Password is not ASCII`. Runs on Java 25. |
| `windowsWarnsWhenAnArgumentWasDamagedByTheCodePage` | Linux, macOS | runs on all 5 Windows cells |
| `anyUnicodeArgumentArrivesIntactOnUtf8Systems` | Windows | runs on all 10 Linux and macOS cells |
| `CrossLanguageCliTest` | the `test` job | runs in the `cross-language` job |

### Not verified

- PHPCrypt: never run (same format as GoCrypt by its code; no PHP was available).
- PyCrypt 1.0.1 and NodeCrypt 1.0.1: round trips with the JavaCrypt CLI were run once by hand on Windows (2026-11-19), three modes, both directions, ASCII values. Not automated.
- The interactive-console branch of the CLI's output charset (console charset instead of UTF-8) has no automated test.
- Java 22, 23, 24: not in the matrix.
- The example inside a running Quarkus application, and native images.
- The `publish` job of `release.yml` (signing, Central upload): never run, the secrets do not exist yet.

---

## 🔎 Findings Worth Remembering

1. **JDK 17 only:** `AES/GCM` decryption of an input shorter than the tag throws an unchecked `ProviderException` (wrapping `ShortBufferException`) instead of `AEADBadTagException`. Found by the first CI run. Fixed twice over: an explicit length check before the cipher, and `ProviderException` is mapped to `DECRYPTION_FAILED`.
2. **Windows arguments are lossy.** `java.exe` receives its arguments through the ANSI code page (`sun.jnu.encoding`, e.g. Cp1252). `ä` survives, an emoji arrives as `??`. No JVM option recovers it. The environment is not affected on Windows (UTF-16). The CLI warns when `-p` or `-v` contains `?` on such a system; it cannot know whether the `?` is real.
3. **Redirected stdout is not UTF-8 by default** on Windows, even on JDK 25 (`stdout.encoding` is the native code page). The CLI creates its own `PrintStream`.
4. **Jasypt + non-ASCII password** works on Java 25 only (of 8, 11, 17, 21, 25), and Jasypt **normalizes passwords to NFC** while the family uses the bytes as given.
5. **Tests that pass on first run prove little.** The non-ASCII vectors were checked by mutation (ISO-8859-1 password bytes made exactly those fail); the stdout tests by mutating the charset; the example by removing its service file.
6. **CI flake seen once:** Maven Central answered HTTP 429 when all jobs started with cold caches (after the set of `pom.xml` files changed). Re-running the failed job was enough.

---

## 🧰 Local Environment Notes

- The maintainer's Windows machine has JDK 25 (GraalVM) and Maven 3.9, no Gradle and no other JDK: **Java 8, 11, 17 and 21 are verified in CI only.**
- Git `core.autocrlf` is on there; `.gitattributes` forces LF in the repository (and CRLF for `*.cmd`). `mvnw` is committed with the executable bit.
- When writing files from a shell on that machine, backslashes inside heredocs are unreliable. Use an editor tool for anything containing `\u` escapes.

---

## ⚠️ Known Issues

1. `JasyptStrongEncryptor` format ≠ real Java Jasypt strong format (see Wire Formats). Do not fix unilaterally.
2. `JasyptEncryptor`: DES/MD5 are weak; the CBC modes have no integrity check (wrong password → error or garbage).
3. Windows command-line arguments lose characters outside the code page (Finding 2). Use `JAVACRYPT_PASSWORD` and the file commands.
4. Java 8 before 8u161 needs the unlimited strength policy files for AES-256 → `ErrorCode.UNSUPPORTED`.
5. `loadYaml` is a flat `key: value` parser (GoCrypt parity); there is no JSON loader.
6. `encrypt-file` does not trim around `=` (GoCrypt parity): `KEY = value` encrypts `" value"`.
7. GoCrypt's PKCS padding check accepts a pad byte of 0 (returns the garbage); Java rejects it. Only reachable with a wrong password.

---

## 📦 Publish & Release Status

| Item | Status |
|------|--------|
| Published | ⏳ **No.** Not tagged, not on Maven Central, no GitHub Release (as of 2026-11-19) |
| Coordinates | `io.github.farizfadian:javacrypt:1.0.0` |
| CI | ✅ GitHub Actions: 15-cell test matrix, cross-language, lint, example, audit |
| Release | ⏳ `release.yml` is written but its `publish` job has never run |
| Secrets needed | `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` (none set yet) |
| Cross-language tested | ✅ GoCrypt and RustCrypt (automated), Java Jasypt 1.9.3 (automated), PyCrypt and NodeCrypt (by hand, once) |

### How to release (only on the owner's explicit go-ahead: a Central release can never be deleted)

1. One-time setup: Sonatype Central Portal account, verified namespace `io.github.farizfadian`, a user token, a GPG key whose public half is on `keyserver.ubuntu.com` or `keys.openpgp.org`, and the four repository secrets.
2. Rehearse: Actions → Release → "Run workflow". It builds, signs, verifies the signatures and checks the keyserver, without creating a release or uploading.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [1.0.0] - YYYY-MM-DD` (the workflow refuses a tag without it) and commit.
4. Tag and push:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
5. The workflow creates the GitHub Release (jar, sources, javadoc, `checksums.txt`) and uploads to the Central Portal. `autoPublish` is `false`: review the validated deployment at <https://central.sonatype.com/publishing/deployments> and press **Publish** (or **Drop**).
6. For the next version: bump `<version>` and `project.build.outputTimestamp` in `pom.xml`, and the versions in README and the example.

---

## 📋 Full Context Reference

For the complete cross-language context, see the maintainer's private family context document (kept outside this repository).

---

<p align="center"><b>An idea from <a href="https://github.com/farizfadian">Fariz</a> and made with love by <a href="https://claude.ai">Claude AI</a></b></p>
