/**
 * Jasypt-like {@code ENC(...)} encryption for configuration values, compatible across languages.
 *
 * <p>JavaCrypt is the Java member of a family of libraries (GoCrypt, PyCrypt, NodeCrypt, PHPCrypt,
 * RustCrypt) that share one wire format, so the same encrypted config file can be read from every
 * language. It has no dependencies and runs on Java 8 and later.
 *
 * <pre>{@code
 * Encryptor enc = new Encryptor(System.getenv("JAVACRYPT_PASSWORD"));
 * String wrapped = enc.encryptWithPrefix("s3cr3t");      // ENC(...)
 * String secret  = enc.decryptPrefixed(wrapped);         // s3cr3t
 * }</pre>
 *
 * <h2>Three encryptors, three formats</h2>
 *
 * <p>An {@code ENC(...)} value does not record how it was encrypted. Both sides must use the same
 * encryptor, password and parameters.
 *
 * <table>
 *   <caption>Which implementation reads which format</caption>
 *   <tr><th>Class</th><th>Algorithm</th><th>Rest of the family</th><th>Java Jasypt</th></tr>
 *   <tr><td>{@link io.github.farizfadian.javacrypt.Encryptor}</td>
 *       <td>AES-256-GCM, PBKDF2-HMAC-SHA256</td><td>yes</td><td>no</td></tr>
 *   <tr><td>{@link io.github.farizfadian.javacrypt.JasyptEncryptor}</td>
 *       <td>PBEWithMD5AndDES</td><td>yes</td><td>yes</td></tr>
 *   <tr><td>{@link io.github.farizfadian.javacrypt.JasyptStrongEncryptor}</td>
 *       <td>AES-256-CBC, PBKDF2-HMAC-SHA256 (family layout)</td><td>yes</td><td>no</td></tr>
 * </table>
 *
 * <p>Use {@link io.github.farizfadian.javacrypt.Encryptor} unless a value must be read by an
 * application that uses the real Jasypt library; only then use
 * {@link io.github.farizfadian.javacrypt.JasyptEncryptor}.
 *
 * <p>All encryptors are immutable and thread-safe. Errors are reported as
 * {@link io.github.farizfadian.javacrypt.JavaCryptException}, an unchecked exception with an
 * {@link io.github.farizfadian.javacrypt.ErrorCode}.
 */
package io.github.farizfadian.javacrypt;
