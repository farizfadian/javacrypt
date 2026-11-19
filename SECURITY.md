# Security Policy

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

---

## 🚨 Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### DO NOT

- ❌ Open a public GitHub issue
- ❌ Discuss the vulnerability publicly before it's fixed

### DO

1. **Use GitHub's private vulnerability reporting** on the repository (Security → Report a vulnerability), or **email the maintainer directly** at the address listed in the GitHub profile
2. **Include the following information:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

Because JavaCrypt shares its wire formats with GoCrypt, PyCrypt, NodeCrypt, PHPCrypt and RustCrypt, a format-level issue will be coordinated and fixed across all six libraries.

---

## 🛡️ Security Model

| Encryptor | Cipher | KDF | Integrity | Assessment |
|-----------|--------|-----|-----------|------------|
| `Encryptor` | AES-256-GCM | PBKDF2-HMAC-SHA256, 10 000 iterations | AEAD tag | ✅ Recommended |
| `JasyptStrongEncryptor` | AES-256-CBC | PBKDF2-HMAC-SHA256, 1 000 iterations | none (PKCS7 padding only) | ✅ Acceptable within the family |
| `JasyptEncryptor` | DES-CBC | PBKDF1-MD5, 1 000 iterations | none (PKCS5 padding only) | ⚠️ Legacy, Jasypt-compatibility only |

Known limitations (documented, not considered vulnerabilities):

- `JasyptEncryptor` uses DES (56-bit key) and MD5 because Java Jasypt's default algorithm does. It exists for compatibility with applications that use Jasypt; use `Encryptor` whenever Jasypt does not need to read the value.
- The CBC modes have no authentication: a wrong password or a changed ciphertext is usually detected by the padding check, but can occasionally decrypt to garbage. JavaCrypt additionally rejects output that is not valid UTF-8. `Encryptor` (AES-GCM) always detects it.
- `JasyptStrongEncryptor` derives the IV from PBKDF2 together with the key (the family format) instead of using a random IV like Java Jasypt. Every encryption still uses a fresh random salt, so key and IV differ for every value.
- `ErrorCode.DECRYPTION_FAILED` deliberately carries no detail and no cause, so the library cannot be used as a padding or authentication oracle.
- Passwords and derived keys are not wiped from memory; they live until garbage collected.
- The iteration counts are the family's defaults and are low by current standards. They can be raised with the builders, on both sides. A long random password matters more than the count.
- The command line accepts the password with `-p`, which is visible in the process list and in shell history. Prefer the `JAVACRYPT_PASSWORD` environment variable.

---

## 🧱 What JavaCrypt relies on

- **The JDK's cryptography only**: `AES/GCM/NoPadding`, `AES/CBC/PKCS5Padding`, `DES/CBC/PKCS5Padding`, `HmacSHA256`, `MD5` and `SecureRandom`. There are no other dependencies.
- **Key derivation is written out in this library** (PBKDF2-HMAC-SHA256 and PBKDF1-MD5 over the UTF-8 bytes of the password), so the result does not depend on how a provider converts a `char[]` password. It is pinned by vectors generated with GoCrypt and compared with the JDK's own PBKDF2 in the tests.

---

## ✅ Best Practices

1. Never commit the password. Use an environment variable or a secret manager.
2. Use `Encryptor` (AES-256-GCM) for anything Java Jasypt does not have to read.
3. Use a long, random password.
4. Rotate secrets by re-encrypting with a new password; values encrypted with the old one stay readable only with the old one.
5. Do not log decrypted values, and do not add detail to "decryption failed".
