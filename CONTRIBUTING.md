# Contributing to JavaCrypt

Thank you for considering a contribution. JavaCrypt is one of six libraries that share a wire format, so the most important rule comes first: **a value encrypted by any member must decrypt in every other member.**

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Cross-Language Compatibility Rules](#cross-language-compatibility-rules)
- [Pull Request Process](#pull-request-process)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

Be respectful and constructive. We are all here to build something useful.

## How Can I Contribute?

### 🐛 Reporting Bugs

Open an issue with:

- the JavaCrypt version, the Java version and vendor (`java -version`), and the operating system
- the mode (default, `--jasypt`, `--jasypt-strong`) and, for interoperability problems, the other library and its version
- the smallest example that shows the problem. **Never post a real password or secret.** A value encrypted with a throwaway password is enough.

For security problems, do not open an issue: see [SECURITY.md](SECURITY.md).

### 💡 Suggesting Features

Open an issue first. A feature that touches a wire format, an error message or a CLI option affects five other libraries and is decided for the family as a whole.

### 🔧 Pull Requests

Small, focused pull requests with tests are the easiest to review.

## Development Setup

You need a JDK 17 or newer (the build produces Java 8 bytecode with it) and nothing else: the Maven wrapper downloads Maven.

```bash
# Full gate (this is what CI runs)
./mvnw verify                             # compile with warnings as errors, unit tests, jar tests
./mvnw -Prelease -Dgpg.skip verify        # also the sources and javadoc jars; javadoc warnings fail

# One test class
./mvnw test -Dtest=GoldenVectorsTest

# The tests on another Java runtime, the way CI tests Java 8, 11, 17 and 21
./mvnw verify -Djvm=/path/to/that/jdk/bin/java

# The example (needs the library in the local repository first)
./mvnw -DskipTests install
./mvnw -f examples/smallrye-config/pom.xml verify
```

```bash
# Live round trips against the released CLIs of other family members.
# Download the binaries from their GitHub release pages.
GOCRYPT_CLI=/path/to/gocrypt-cli RUSTCRYPT_CLI=/path/to/rustcrypt \
  ./mvnw test -Dtest=CrossLanguageCliTest
```

```bash
# Regenerate the non-ASCII golden vectors (needs Go; uses the published gocrypt module)
cd scripts/gen-vectors
go run . -set unicode -commit <gocrypt commit> -out ../../src/test/resources/gocrypt_vectors_unicode.json
```

`src/test/resources/gocrypt_vectors.json` is a byte-identical copy of RustCrypt's fixture. Do not regenerate it.

## Cross-Language Compatibility Rules

1. **GoCrypt is the reference implementation.** When in doubt, match GoCrypt byte for byte.
2. **Never change a wire format**, not even to improve it: the salt and nonce sizes, the iteration defaults, the layout of the encoded bytes, base64 with padding, the `ENC(...)` wrapper. A change has to ship in all six libraries at once.
3. **A round trip inside JavaCrypt proves nothing about the format.** Every change to an encryptor must keep `GoldenVectorsTest` green, which compares against values that GoCrypt produced. A sibling library once shipped a default mode no other member could read while its own tests were green.
4. **Passwords and plaintext are UTF-8.** Never use the platform default charset: not for strings, not for files, not for process output.
5. **Keep the error messages**: they are the same across the family (`decryption failed`, `invalid encrypted format, expected ENC(...)`, ...).
6. **State what was tested.** A compatibility claim in the documentation names the other implementation, its version, and whether it was run automatically, by hand, or not at all.

## Pull Request Process

1. Write the test first and watch it fail for the right reason.
2. Make it pass; keep `./mvnw -Prelease -Dgpg.skip verify` green.
3. Update `CHANGELOG.md` under `[Unreleased]`, and the README if behaviour changed.
4. CI must be green on the whole matrix: Java 8, 11, 17, 21 and 25 on Linux, Windows and macOS. Some bugs only show on one Java version.

## Style Guidelines

- **Java 8 language level** for main and test code: no `var`, records, text blocks or `List.of`.
- **No dependencies** outside the test scope. An enforcer rule fails the build otherwise.
- Public classes and methods have Javadoc that says what a caller needs to know, including which other implementations can read a format.
- Encryptors are immutable and thread-safe: create a `Cipher` per call.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `build:`, `refactor:`.
- Nothing private in committed files: no real passwords, no internal project names, no machine-specific paths.
