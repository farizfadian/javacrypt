package io.github.farizfadian.javacrypt;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Key derivation functions, written out by hand like GoCrypt does.
 *
 * <p>The password is always a byte array that the caller encoded as UTF-8. The JDK's password-based
 * key factories are not used: how they turn a {@code char[]} into bytes is up to the installed
 * provider and has changed between JDK versions, and the wire format must not depend on that.
 */
final class Kdf {

    private static final int SHA256_LENGTH = 32;

    private Kdf() {
    }

    /**
     * PBKDF2 with HMAC-SHA256 (RFC 8018).
     *
     * @param password the UTF-8 password bytes, not empty
     * @param salt the salt
     * @param iterations the iteration count, at least 1
     * @param length the number of bytes to derive
     * @return {@code length} derived bytes
     */
    static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int length) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(password, "HmacSHA256"));

            byte[] derived = new byte[length];
            byte[] u = new byte[SHA256_LENGTH];
            byte[] t = new byte[SHA256_LENGTH];
            int blocks = (length + SHA256_LENGTH - 1) / SHA256_LENGTH;
            for (int block = 1; block <= blocks; block++) {
                // U1 = HMAC(password, salt || INT(block)), then Un = HMAC(password, Un-1)
                hmac.update(salt);
                hmac.update((byte) (block >>> 24));
                hmac.update((byte) (block >>> 16));
                hmac.update((byte) (block >>> 8));
                hmac.update((byte) block);
                hmac.doFinal(u, 0);
                System.arraycopy(u, 0, t, 0, SHA256_LENGTH);
                for (int i = 2; i <= iterations; i++) {
                    hmac.update(u);
                    hmac.doFinal(u, 0);
                    for (int j = 0; j < SHA256_LENGTH; j++) {
                        t[j] ^= u[j];
                    }
                }
                int offset = (block - 1) * SHA256_LENGTH;
                System.arraycopy(t, 0, derived, offset, Math.min(SHA256_LENGTH, length - offset));
            }
            return derived;
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.unsupported("HmacSHA256", e);
        }
    }

    /**
     * PBKDF1 with MD5, as used by PBEWithMD5AndDES: {@code md5(password || salt)}, then MD5 of the
     * previous digest, for a total of {@code iterations} MD5 calls.
     *
     * @param password the UTF-8 password bytes
     * @param salt the salt
     * @param iterations the iteration count, at least 1
     * @return 16 bytes: the DES key in bytes 0 to 7, the IV in bytes 8 to 15
     */
    static byte[] pbkdf1Md5(byte[] password, byte[] salt, int iterations) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(password);
            md5.update(salt);
            byte[] hash = md5.digest();
            for (int i = 1; i < iterations; i++) {
                hash = md5.digest(hash);
            }
            return hash;
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.unsupported("MD5", e);
        }
    }
}
