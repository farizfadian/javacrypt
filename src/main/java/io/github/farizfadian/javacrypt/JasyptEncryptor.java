package io.github.farizfadian.javacrypt;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * {@code PBEWithMD5AndDES}, the default algorithm of Java Jasypt.
 *
 * <p>This is the one mode that <strong>Java Jasypt itself can read</strong>
 * ({@code StandardPBEStringEncryptor} with its default settings), and every member of the family
 * reads it too. Use it when a value is shared with an application that uses real Jasypt.
 *
 * <p><strong>MD5 and DES are weak.</strong> There is also no integrity check: decrypting with a
 * wrong password usually fails, but can occasionally return garbage instead. Prefer
 * {@link Encryptor} whenever Jasypt does not have to read the value.
 *
 * <p>Wire format: {@code base64(salt(8) || ciphertext)}, DES-CBC with PKCS#5 padding. Key and IV
 * come from MD5 applied {@code iterations} times to {@code password || salt}.
 *
 * <p>Instances are immutable and safe to share between threads.
 */
public final class JasyptEncryptor implements StringEncryptor {

    /** Default iteration count, the same as Jasypt's. */
    public static final int DEFAULT_ITERATIONS = 1000;

    /** Salt size in bytes. Fixed by the algorithm. */
    public static final int SALT_SIZE = 8;

    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

    private final byte[] password;
    private final int iterations;

    /**
     * Creates an encryptor with Jasypt's default of 1000 iterations.
     *
     * @param password the password, encoded as UTF-8
     */
    public JasyptEncryptor(String password) {
        this(new Builder(password));
    }

    JasyptEncryptor(Builder builder) {
        this.password = Internal.utf8(builder.password);
        this.iterations = builder.iterations;
    }

    /**
     * Starts a builder for a non-default iteration count. Both sides must use the same value.
     *
     * @param password the password, encoded as UTF-8
     * @return a new builder
     */
    public static Builder builder(String password) {
        return new Builder(password);
    }

    @Override
    public String encrypt(String plaintext) {
        return encryptWithSalt(Internal.randomBytes(SALT_SIZE), plaintext);
    }

    /** The deterministic core, used directly by the golden vector tests. */
    String encryptWithSalt(byte[] salt, String plaintext) {
        byte[] derived = Kdf.pbkdf1Md5(password, salt, iterations);
        byte[] input = Internal.utf8(plaintext);
        try {
            byte[] ciphertext = Internal.crypt(TRANSFORMATION, Cipher.ENCRYPT_MODE, Arrays.copyOfRange(derived, 0, 8),
                    new IvParameterSpec(derived, 8, 8), input, 0, input.length);
            return Internal.encodeBase64(salt, ciphertext);
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.unsupported(TRANSFORMATION, e);
        }
    }

    @Override
    public String decrypt(String encoded) {
        byte[] combined = Internal.decodeBase64(encoded);
        byte[] salt = Arrays.copyOfRange(combined, 0, SALT_SIZE);
        byte[] derived = Kdf.pbkdf1Md5(password, salt, iterations);
        try {
            byte[] plaintext = Internal.crypt(TRANSFORMATION, Cipher.DECRYPT_MODE, Arrays.copyOfRange(derived, 0, 8),
                    new IvParameterSpec(derived, 8, 8), combined, SALT_SIZE, combined.length - SALT_SIZE);
            return Internal.fromUtf8(plaintext);
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.decryptionFailed();
        }
    }

    /** Builder for a {@link JasyptEncryptor} with a non-default iteration count. */
    public static final class Builder {

        private final String password;
        private int iterations = DEFAULT_ITERATIONS;

        Builder(String password) {
            this.password = password;
        }

        /**
         * Sets the iteration count (Jasypt: {@code setKeyObtentionIterations}).
         *
         * @param iterations the iteration count, default {@value JasyptEncryptor#DEFAULT_ITERATIONS}
         * @return this builder
         */
        public Builder iterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Creates the encryptor.
         *
         * @return a new immutable encryptor
         */
        public JasyptEncryptor build() {
            return new JasyptEncryptor(this);
        }
    }
}
