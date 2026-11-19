# JavaCrypt ☕🔐

[![Maven Central](https://img.shields.io/maven-central/v/io.github.farizfadian/javacrypt.svg)](https://central.sonatype.com/artifact/io.github.farizfadian/javacrypt)
[![CI](https://github.com/farizfadian/javacrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/farizfadian/javacrypt/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-8%2B-orange.svg)](https://github.com/farizfadian/javacrypt)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Jasypt-like encryption library for Java** - Encrypt your application configuration with the familiar
`ENC(...)` pattern, and share it with Go, Python, Node.js, PHP and Rust. Zero dependencies, Java 8+.

> **Made with ❤️ from Claude AI for Java developers whose services are not all written in Java**

---

## 🎯 Why JavaCrypt, when Java already has Jasypt?

JavaCrypt belongs to a family of libraries that share one wire format, so one encrypted config file
can be read from six languages. The family has three modes. **Java Jasypt can read only one of
them**: `PBEWithMD5AndDES`, which is DES with MD5 and has no integrity check.

JavaCrypt reads and writes all three, including the family's default, authenticated AES-256-GCM.

| Mode | Algorithm | Go · Python · Node.js · PHP · Rust | Java Jasypt | **JavaCrypt** |
|------|-----------|:---:|:---:|:---:|
| default | AES-256-GCM | ✅ | ❌ | ✅ |
| `--jasypt` | PBEWithMD5AndDES | ✅ | ✅ | ✅ |
| `--jasypt-strong` | AES-256-CBC (family layout) | ✅ | ❌ | ✅ |

It provides:

- ✅ **Familiar `ENC(...)` pattern** - just like Jasypt in Spring Boot
- ✅ **All three family modes** - a value encrypted in any language can be read in Java
- ✅ **Still talks to real Jasypt** - `JasyptEncryptor` and Jasypt read each other's values
- ✅ **Zero dependencies** - only the JDK
- ✅ **Java 8 and later** - tested on Java 8, 11, 17, 21 and 25, on Linux, Windows and macOS
- ✅ **Config loaders** - `.env`, flat YAML and `.properties` with automatic decryption
- ✅ **CLI included** - the library jar is also the command-line tool
- ✅ **Tested against the reference** - byte-identical to GoCrypt, plus live round trips with the released tools

---

## 🔗 Cross-Language Family (ALL SAME ENC() FORMAT!)

```
┌─────────────────────────────────────────────────────────────────┐
│              Jasypt Multi-Language Encryption Family             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   🐹 GoCrypt     github.com/farizfadian/gocrypt     (Go)        │
│   🐍 PyCrypt     github.com/farizfadian/pycrypt     (Python)    │
│   📦 NodeCrypt   github.com/farizfadian/nodecrypt   (Node.js)   │
│   🐘 PHPCrypt    github.com/farizfadian/phpcrypt    (PHP)       │
│   🦀 RustCrypt   github.com/farizfadian/rustcrypt   (Rust)      │
│   ☕ JavaCrypt   github.com/farizfadian/javacrypt   (Java)      │
│                                                                  │
│   SAME MODE ON BOTH SIDES: default, --jasypt, --jasypt-strong   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

An `ENC(...)` value does not record how it was encrypted. Both sides must use the same mode, the
same password and the same parameters. GoCrypt is the reference implementation.

---

## 📦 Installation

**Maven**

```xml
<dependency>
  <groupId>io.github.farizfadian</groupId>
  <artifactId>javacrypt</artifactId>
  <version>1.0.0</version>
</dependency>
```

**Gradle**

```kotlin
implementation("io.github.farizfadian:javacrypt:1.0.0")
```

**Requirements:** Java 8 or later (8u161 or later for AES-256, see Known Issues below).
No other dependency. In a modular application the module name is `io.github.farizfadian.javacrypt`.

**CLI:** the same jar. Download `javacrypt-1.0.0.jar` from the
[releases page](https://github.com/farizfadian/javacrypt/releases) or from Maven Central and run it
with `java -jar`.

---

## 🚀 Quick Start

### Basic Encryption/Decryption

```java
import io.github.farizfadian.javacrypt.Encryptor;

Encryptor enc = new Encryptor(System.getenv("JAVACRYPT_PASSWORD"));

String encrypted = enc.encryptWithPrefix("my_database_password");
// ENC(kU/jNgiOOc9euKgZ2vAjYlpKoahu4KXaaoJ8XL75fs2A...)

String decrypted = enc.decryptPrefixed(encrypted);
// my_database_password
```

### Loading Encrypted Configuration

```java
import io.github.farizfadian.javacrypt.ConfigLoader;

ConfigLoader loader = new ConfigLoader(System.getenv("JAVACRYPT_PASSWORD"));

Map<String, String> config = loader.loadEnvFile(".env");
String dbPassword = config.get("DB_PASS");   // decrypted
```

### Values shared with an application that uses Java Jasypt

```java
import io.github.farizfadian.javacrypt.JasyptEncryptor;

JasyptEncryptor enc = new JasyptEncryptor(password);          // PBEWithMD5AndDES
String plain = enc.decryptPrefixed("ENC(valueWrittenByJasypt)");
```

---

## 🔐 Encryption Algorithms

| Class | Algorithm | Read by the rest of the family | Read by Java Jasypt |
|-------|-----------|:---:|:---:|
| `Encryptor` | AES-256-GCM, PBKDF2-HMAC-SHA256 (10 000 iterations) | ✅ | ❌ |
| `JasyptEncryptor` | PBEWithMD5AndDES (1 000 iterations) | ✅ | ✅ |
| `JasyptStrongEncryptor` | AES-256-CBC, PBKDF2-HMAC-SHA256 (1 000 iterations) | ✅ | ❌ |

### Which encryptor should I use?

- **`Encryptor`**, unless you have a reason not to. It is the only mode that detects a wrong
  password or a changed value every time.
- **`JasyptEncryptor`**, only when the value must also be read by an application that uses the real
  Jasypt library. MD5 and DES are weak.
- **`JasyptStrongEncryptor`**, only to read values that another member already wrote in this mode.
  Despite the family's name for it, **it is not the format of Jasypt's
  `PBEWithHmacSHA256AndAES_256`**: Jasypt stores a random IV after the salt, the family derives the
  IV from the password.

All three are immutable and thread-safe.

---

## 📖 Usage Guide

### 1. Configuration Files

```properties
# config.env
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASS=ENC(kU/jNgiOOc9euKgZ2vAjYlpKoahu4KXaaoJ8XL75fs2AwbzwVRF4d2ey0pqQdVNT5Q==)
```

```java
ConfigLoader loader = new ConfigLoader(password);                  // AES-256-GCM
ConfigLoader jasypt = new ConfigLoader(new JasyptEncryptor(pw));   // any StringEncryptor

Map<String, String> env  = loader.loadEnvFile("config.env");       // KEY=VALUE lines
Map<String, String> yaml = loader.loadYaml("config.yaml");         // flat key: value lines
Properties props         = loader.loadProperties("app.properties"); // java.util.Properties syntax, UTF-8
```

A value that looks encrypted but cannot be decrypted is always an error that names its key
(`failed to decrypt key DB_PASS: decryption failed`). It is never returned as the literal
`ENC(...)` text.

`loadYaml` is the family's flat line parser, not a YAML parser: nesting is flattened and lists are
not understood. For real YAML or JSON documents, see [JSON and YAML documents](#5-json-and-yaml-documents).

### 2. Set to System Properties

A Java process cannot change its own environment variables, so the counterpart of the family's
`setToEnv` is:

```java
loader.setToSystemProperties("config.env");
String dbPass = System.getProperty("DB_PASS");
```

### 3. Decrypt a Map

```java
Map<String, String> config = new LinkedHashMap<>();
config.put("host", "localhost");
config.put("password", "ENC(...)");

Map<String, String> decrypted = enc.decryptMap(config);   // order kept, plain values copied
```

### 4. Decrypt All in a String

```java
String text = "password=ENC(xxx) api_key=ENC(yyy)";

String result = enc.decryptAllInString(text);        // throws if any value fails
String lossy  = enc.decryptAllInStringLossy(text);   // keeps values that fail, never throws
```

### 5. JSON and YAML documents

JavaCrypt has no JSON loader, because that would need a dependency. Parse the document with the
library you already use, then decrypt the string values of the parsed tree:

```java
/** Returns a copy of a parsed tree (maps, lists, scalars) with every ENC(...) string decrypted. */
static Object decryptStrings(StringEncryptor encryptor, Object node) {
    if (node instanceof String) {
        String text = (String) node;
        return JavaCrypt.isEncrypted(text) ? encryptor.decryptPrefixed(text) : text;
    }
    if (node instanceof Map) {
        Map<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) node).entrySet()) {
            copy.put(String.valueOf(entry.getKey()), decryptStrings(encryptor, entry.getValue()));
        }
        return copy;
    }
    if (node instanceof List) {
        List<Object> copy = new ArrayList<>();
        for (Object item : (List<?>) node) {
            copy.add(decryptStrings(encryptor, item));
        }
        return copy;
    }
    return node; // numbers, booleans, null
}
```

Do **not** run `decryptAllInString` over the raw JSON or YAML text: the decrypted value is inserted
as it is, so a secret containing `"` or `\` would break the document.

### 6. Check if a Value is Encrypted

```java
if (JavaCrypt.isEncrypted(value)) {
    value = enc.decryptPrefixed(value);
}
```

### 7. Errors

Everything throws one unchecked exception, `JavaCryptException`, with an `ErrorCode`:

```java
try {
    enc.decryptPrefixed(value);
} catch (JavaCryptException e) {
    if (e.getCode() == ErrorCode.DECRYPTION_FAILED) {
        // wrong password, wrong mode, or the value was changed
    }
}
```

| Code | Message |
|------|---------|
| `EMPTY_PASSWORD` | `password cannot be empty` |
| `EMPTY_VALUE` | `value cannot be empty` |
| `INVALID_ENC_FORMAT` | `invalid encrypted format, expected ENC(...)` |
| `INVALID_JASYPT_DATA` | `invalid jasypt encrypted data` |
| `DECRYPTION_FAILED` | `decryption failed` (no detail, on purpose) |
| `INVALID_BASE64` | `failed to decode base64: ...` |
| `KEY_DECRYPT` | `failed to decrypt key <key>: ...` (`getKey()` returns the key) |
| `INVALID_PARAMETER` | `invalid parameter: ...` |
| `IO` | a config file could not be read |
| `UNSUPPORTED` | this Java runtime lacks an algorithm or key size |

---

## 💻 CLI Tool

The library jar is the command-line tool. It mirrors `gocrypt-cli` and `rustcrypt`.

```bash
# Encrypt a value
java -jar javacrypt-1.0.0.jar encrypt -p mySecret -v "database_password"
# Output: ENC(base64value...)

# Decrypt a value (the ENC(...) wrapper is optional)
java -jar javacrypt-1.0.0.jar decrypt -p mySecret -v "ENC(base64value...)"
# Output: database_password

# Encrypt all KEY=VALUE values in a file
java -jar javacrypt-1.0.0.jar encrypt-file -p mySecret -i .env.plain -o .env.encrypted

# Decrypt all ENC(...) values in a file (omit -o or use "-" for stdout)
java -jar javacrypt-1.0.0.jar decrypt-file -p mySecret -i .env.encrypted -o .env.plain

# Use the mode Java Jasypt can read
java -jar javacrypt-1.0.0.jar encrypt -p mySecret -v "secret" --jasypt

# Use the family's strong mode
java -jar javacrypt-1.0.0.jar encrypt -p mySecret -v "secret" --jasypt-strong

# Raw base64 without the ENC(...) wrapper
java -jar javacrypt-1.0.0.jar encrypt -p mySecret -v "secret" --no-prefix

# Use an environment variable for the password
export JAVACRYPT_PASSWORD=mySecret
java -jar javacrypt-1.0.0.jar encrypt -v "secret"
```

The exit status is 0 on success and 1 on any error; errors go to stderr.

### Characters outside ASCII

- **Files** are read and written as UTF-8, on every platform and Java version.
- **Output** that is redirected or piped is UTF-8 with `\n` line ends, like the Go and Rust tools
  write it. On an interactive console the console's own encoding is used.
- **Arguments on Windows:** Java receives its command-line arguments in the system code page (for
  example Cp1252). Characters outside it arrive as `?`, before JavaCrypt sees them, and cannot be
  recovered. For such a password use `JAVACRYPT_PASSWORD`, and for such values use `encrypt-file`
  and `decrypt-file`; both carry any character. JavaCrypt prints a warning when `-p` or `-v`
  contains a `?` on such a system. On Linux and macOS with a UTF-8 locale, arguments are not
  affected.

---

## ☕ Cross-Language Compatibility

### What was tested, and how

| Against | What | Result |
|---------|------|--------|
| **GoCrypt v1.0.0** (golden vectors) | Fixed-salt output of all three modes compared byte for byte; every value GoCrypt wrote is decrypted. An ASCII password and a non-ASCII one (`pässwörd-🔐`). | ✅ on Java 8, 11, 17, 21, 25 × Linux, Windows, macOS |
| **`gocrypt-cli` v1.0.0** (released binary) | Live round trips, three modes, both directions, both passwords | ✅ Linux, Windows, macOS (Java 25) |
| **`rustcrypt` v1.0.0** (released binary) | Live round trips, three modes, both directions, both passwords | ✅ Linux, Windows, macOS (Java 25) |
| **Java Jasypt 1.9.3** | `JasyptEncryptor` ↔ `StandardPBEStringEncryptor` (`PBEWithMD5AndDES`), both directions, default and custom iterations | ✅ on Java 8, 11, 17, 21, 25 |
| **Java Jasypt 1.9.3**, non-ASCII password | same, with `pässwörd-🔐` | ✅ on Java 25. On Java 8 to 21 Jasypt itself cannot use such a password, see below |
| **PyCrypt 1.0.1**, **NodeCrypt 1.0.1** (CLIs) | Round trips with the JavaCrypt CLI, three modes, both directions, ASCII values | ✅ run once by hand on Windows (2026-11-19), not automated |
| **PHPCrypt** | | not run |

The first five rows run in CI on every push.

### Example: encrypt in Go, decrypt in Java

```bash
gocrypt-cli encrypt -p secret -v "hello"
# ENC(...)
```

```java
String hello = new Encryptor("secret").decryptPrefixed("ENC(...)");
```

With `--jasypt` on one side, use `JasyptEncryptor` on the other; with `--jasypt-strong`, use
`JasyptStrongEncryptor`.

### Passwords

Passwords are used as their UTF-8 bytes, exactly as given, in all six libraries. Two things to
know when the other side is **Java Jasypt**:

- **Jasypt cannot use a non-ASCII password on Java 8 to 21.** The JDK's own `PBEWithMD5AndDES` key
  factory rejects it (`Password is not ASCII`). On Java 25 it works and agrees with the family.
  Java 22 to 24 were not tested. JavaCrypt does not have this limit: it derives the key itself.
- **Jasypt normalizes passwords to Unicode NFC**; the family does not. If a password could be
  written with combining characters, normalize it before giving it to JavaCrypt:
  `Normalizer.normalize(password, Normalizer.Form.NFC)`.

---

## 🚀 Quarkus / SmallRye Config

[`examples/smallrye-config`](examples/smallrye-config) contains a `ConfigSourceInterceptor` that
decrypts `ENC(...)` values from any config source, with the password taken from
`JAVACRYPT_PASSWORD`. It is tested with a real `SmallRyeConfig` against SmallRye Config 4.2.2
(Quarkus 4.0) and 3.18.3 (Quarkus 3.x). Not tested: a running Quarkus application and native images.

---

## ⚙️ Advanced Configuration

Non-default parameters are set with a builder. They are not stored in the encrypted value, so the
reader must be built the same way as the writer.

```java
Encryptor enc = Encryptor.builder(password)
        .iterations(50_000)   // default 10 000
        .saltSize(32)         // default 16
        .keySize(32)          // 16, 24 or 32 (default)
        .build();

JasyptEncryptor jasypt = JasyptEncryptor.builder(password)
        .iterations(2_000)    // default 1 000, Jasypt: setKeyObtentionIterations
        .build();

JasyptStrongEncryptor strong = JasyptStrongEncryptor.builder(password)
        .iterations(5_000)    // default 1 000
        .saltSize(16)         // default 16
        .build();
```

---

## 🛡️ Security

| Encryptor | Cipher | Key derivation | Integrity | Assessment |
|-----------|--------|----------------|-----------|------------|
| `Encryptor` | AES-256-GCM | PBKDF2-HMAC-SHA256, 10 000 iterations | authentication tag | ✅ Recommended |
| `JasyptStrongEncryptor` | AES-256-CBC | PBKDF2-HMAC-SHA256, 1 000 iterations | none | acceptable within the family |
| `JasyptEncryptor` | DES-CBC | PBKDF1-MD5, 1 000 iterations | none | ⚠️ legacy, for Jasypt compatibility only |

### Best Practices

1. Keep the password out of the repository: an environment variable or a secret manager.
2. Use `Encryptor` unless Java Jasypt must read the value.
3. Use a long, random password. 10 000 PBKDF2 iterations do not make a weak one safe.
4. `decryption failed` deliberately says nothing more. Do not add detail to it in your own logs.

See [SECURITY.md](SECURITY.md) for the security model and how to report a vulnerability.

---

## ⚠️ Known Issues

1. **`JasyptStrongEncryptor` is a family format, not Jasypt's.** Java Jasypt cannot read it. Moving
   to Jasypt's layout would break existing values and has to happen in all six libraries together.
2. **`JasyptEncryptor` uses DES and MD5**, and the two CBC modes have no integrity check: a wrong
   password usually gives an error, but can occasionally give garbage instead. `Encryptor` always
   detects it.
3. **Windows command-line arguments** lose characters outside the system code page. See
   [Characters outside ASCII](#characters-outside-ascii).
4. **Java Jasypt with a non-ASCII password** only works on recent JDKs, and Jasypt normalizes
   passwords to NFC. See [Passwords](#passwords).
5. **Java 8 older than 8u161** limits AES to 128 bits unless the unlimited strength policy files
   are installed. `Encryptor` and `JasyptStrongEncryptor` then fail with `ErrorCode.UNSUPPORTED`.
6. **`loadYaml` is a flat line parser** (the same as GoCrypt's), and there is no JSON loader.
7. **`encrypt-file` does not trim around `=`**, like the other CLIs: in `KEY = value` the encrypted
   value starts with a space. Write `KEY=value`.
8. Passwords and derived keys stay in memory until garbage collected; they are not wiped.

---

## 📚 API Reference

```java
package io.github.farizfadian.javacrypt;

// Encryptors (all implement StringEncryptor)
new Encryptor(password)                         Encryptor.builder(password)...build()
new JasyptEncryptor(password)                   JasyptEncryptor.builder(password)...build()
new JasyptStrongEncryptor(password)             JasyptStrongEncryptor.builder(password)...build()

// StringEncryptor
String encrypt(String plaintext)                // base64
String encryptWithPrefix(String plaintext)      // ENC(base64)
String decrypt(String encoded)
String decryptPrefixed(String value)
String decryptAllInString(String input)
String decryptAllInStringLossy(String input)
Map<String, String> decryptMap(Map<String, String> map)

// Helpers
JavaCrypt.isEncrypted(value)    JavaCrypt.ENC_PREFIX    JavaCrypt.ENC_SUFFIX    JavaCrypt.version()

// Config
new ConfigLoader(password)                      new ConfigLoader(stringEncryptor)
Map<String, String> loadEnvFile(path)           Map<String, String> loadYaml(path)
Properties loadProperties(path[, charset])      void setToSystemProperties(path)

// Errors
JavaCryptException: getCode() -> ErrorCode, getKey()
```

Paths can be given as `java.nio.file.Path` or `String`. A custom `StringEncryptor` only has to
implement `encrypt` and `decrypt`; the other methods are default methods.

---

## 📁 Project Structure

```
javacrypt/
├── pom.xml                         # Java 8 bytecode, zero dependencies, "release" profile
├── src/main/java/io/github/farizfadian/javacrypt/
│   ├── Encryptor.java              # AES-256-GCM
│   ├── JasyptEncryptor.java        # PBEWithMD5AndDES
│   ├── JasyptStrongEncryptor.java  # AES-256-CBC, family layout
│   ├── StringEncryptor.java        # interface + ENC(...) helpers
│   ├── ConfigLoader.java           # .env, flat YAML, .properties
│   ├── JavaCrypt.java              # isEncrypted, constants, version
│   ├── JavaCryptException.java, ErrorCode.java
│   ├── Kdf.java, Internal.java     # package-private
│   └── cli/Main.java               # the command line
├── src/test/                       # unit, golden vector, Jasypt and CLI tests
├── scripts/gen-vectors/            # Go: produces the golden vectors from GoCrypt
├── examples/smallrye-config/       # Quarkus / SmallRye Config interceptor
└── .github/workflows/              # ci.yml, release.yml
```

---

## 🧪 Testing

```bash
./mvnw verify                                   # everything, with the JDK you have (17 or newer)

# Live round trips against the released CLIs of other members
GOCRYPT_CLI=/path/to/gocrypt-cli RUSTCRYPT_CLI=/path/to/rustcrypt ./mvnw test -Dtest=CrossLanguageCliTest

# Run the tests on another Java runtime (this is how CI tests Java 8)
./mvnw verify -Djvm=/path/to/jdk8/bin/java
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full gate and the compatibility rules.

---

## 🤝 Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first: the wire formats
are shared with five other libraries and must not change.

---

## 📄 License

MIT License - see [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

- [Jasypt](http://www.jasypt.org/) for the `ENC(...)` idea and the original algorithm
- [GoCrypt](https://github.com/farizfadian/gocrypt), the reference implementation of the family

---

<p align="center"><b>An idea from <a href="https://github.com/farizfadian">Fariz</a> and made with love by <a href="https://claude.ai">Claude AI</a></b></p>
