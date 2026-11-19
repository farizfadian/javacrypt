# Changelog

All notable changes to JavaCrypt are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First release. JavaCrypt is the Java member of the GoCrypt family: it reads and writes the same
`ENC(...)` values as GoCrypt, PyCrypt, NodeCrypt, PHPCrypt and RustCrypt.

### Added

- `Encryptor`: AES-256-GCM with PBKDF2-HMAC-SHA256, the family's default mode. Java Jasypt has no
  such mode, so until now a Java service could not read these values.
- `JasyptEncryptor`: `PBEWithMD5AndDES`, readable by Java Jasypt itself and by the whole family.
- `JasyptStrongEncryptor`: the family's AES-256-CBC layout. It is not the format of Jasypt's
  `PBEWithHmacSHA256AndAES_256`; Jasypt cannot read it.
- `StringEncryptor` interface with the family's helpers: `encryptWithPrefix`, `decryptPrefixed`,
  `decryptAllInString`, `decryptAllInStringLossy`, `decryptMap`, plus `JavaCrypt.isEncrypted`.
- `ConfigLoader` for `.env` files, flat YAML and Java `.properties` files, with any
  `StringEncryptor`. `setToSystemProperties` takes the place of the family's `setToEnv`.
- Command-line interface in the library jar: `java -jar javacrypt-1.0.0.jar encrypt | decrypt |
  encrypt-file | decrypt-file`, with the options of `gocrypt-cli` and `rustcrypt`.
- `JavaCryptException`, one unchecked exception with an `ErrorCode`.
- Example: a SmallRye Config interceptor for Quarkus applications (`examples/smallrye-config`).

### Compatibility

- Java 8 or later. No dependencies.
- Tested on Java 8, 11, 17, 21 and 25, on Linux, Windows and macOS.
- Byte-identical to GoCrypt v1.0.0 for fixed salts in all three modes, including a non-ASCII
  password; live round trips with the released `gocrypt-cli` v1.0.0 and `rustcrypt` v1.0.0.
- `JasyptEncryptor` interoperates with Jasypt 1.9.3 in both directions.

[Unreleased]: https://github.com/farizfadian/javacrypt/commits/main
