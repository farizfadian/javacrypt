package io.github.farizfadian.javacrypt;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * AES-256-CBC with key and IV derived by PBKDF2-HMAC-SHA256: the family's "strong" layout.
 *
 * <p><strong>This is a family format. Java Jasypt cannot read it</strong>, even though the family
 * names it after Jasypt's {@code PBEWithHmacSHA256AndAES_256}: real Jasypt stores a random IV after
 * the salt ({@code salt || iv || ciphertext}), while the family derives the IV from the password.
 * GoCrypt, PyCrypt, NodeCrypt, PHPCrypt and RustCrypt all read and write the layout below.
 *
 * <p>There is no integrity check: decrypting with a wrong password usually fails, but can
 * occasionally return garbage instead. Prefer {@link Encryptor} for new values.
 *
 * <p>Wire format: {@code base64(salt || ciphertext)}, AES-256-CBC with PKCS#7 padding. PBKDF2
 * derives 48 bytes: the key is bytes 0 to 31, the IV is bytes 32 to 47.
 *
 * <p>Instances are immutable and safe to share between threads.
 */
public final class JasyptStrongEncryptor implements StringEncryptor {

    /** Default PBKDF2 iteration count. */
    public static final int DEFAULT_ITERATIONS = 1000;

    /** Default salt size in bytes. */
    public static final int DEFAULT_SALT_SIZE = 16;

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 32;
    private static final int BLOCK_SIZE = 16;

    private final byte[] password;
    private final int iterations;
    private final int saltSize;

    /**
     * Creates an encryptor with the family's default parameters: 1000 iterations and a 16-byte salt.
     *
     * @param password the password, encoded as UTF-8
     */
    public JasyptStrongEncryptor(String password) {
        this(new Builder(password));
    }

    JasyptStrongEncryptor(Builder builder) {
        this.password = Internal.utf8(builder.password);
        this.iterations = builder.iterations;
        this.saltSize = builder.saltSize;
    }

    /**
     * Starts a builder for non-default parameters. Both sides must use the same values: they are
     * not stored in the encrypted value.
     *
     * @param password the password, encoded as UTF-8
     * @return a new builder
     */
    public static Builder builder(String password) {
        return new Builder(password);
    }

    @Override
    public String encrypt(String plaintext) {
        return encryptWithSalt(Internal.randomBytes(saltSize), plaintext);
    }

    /** The deterministic core, used directly by the golden vector tests. */
    String encryptWithSalt(byte[] salt, String plaintext) {
        byte[] derived = Kdf.pbkdf2Sha256(password, salt, iterations, KEY_SIZE + BLOCK_SIZE);
        byte[] input = Internal.utf8(plaintext);
        try {
            byte[] ciphertext = Internal.crypt(TRANSFORMATION, Cipher.ENCRYPT_MODE,
                    Arrays.copyOfRange(derived, 0, KEY_SIZE), new IvParameterSpec(derived, KEY_SIZE, BLOCK_SIZE),
                    input, 0, input.length);
            return Internal.encodeBase64(salt, ciphertext);
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.unsupported(TRANSFORMATION + " with a 256-bit key", e);
        }
    }

    @Override
    public String decrypt(String encoded) {
        byte[] combined = Internal.decodeBase64(encoded);
        byte[] salt = Arrays.copyOfRange(combined, 0, saltSize);
        byte[] derived = Kdf.pbkdf2Sha256(password, salt, iterations, KEY_SIZE + BLOCK_SIZE);
        try {
            byte[] plaintext = Internal.crypt(TRANSFORMATION, Cipher.DECRYPT_MODE,
                    Arrays.copyOfRange(derived, 0, KEY_SIZE), new IvParameterSpec(derived, KEY_SIZE, BLOCK_SIZE),
                    combined, saltSize, combined.length - saltSize);
            return Internal.fromUtf8(plaintext);
        } catch (GeneralSecurityException e) {
            throw JavaCryptException.decryptionFailed();
        }
    }

    /** Builder for a {@link JasyptStrongEncryptor} with non-default parameters. */
    public static final class Builder {

        private final String password;
        private int iterations = DEFAULT_ITERATIONS;
        private int saltSize = DEFAULT_SALT_SIZE;

        Builder(String password) {
            this.password = password;
        }

        /**
         * Sets the PBKDF2 iteration count.
         *
         * @param iterations the iteration count, default {@value JasyptStrongEncryptor#DEFAULT_ITERATIONS}
         * @return this builder
         */
        public Builder iterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Sets the salt size.
         *
         * @param saltSize the salt size in bytes, default {@value JasyptStrongEncryptor#DEFAULT_SALT_SIZE}
         * @return this builder
         */
        public Builder saltSize(int saltSize) {
            this.saltSize = saltSize;
            return this;
        }

        /**
         * Creates the encryptor.
         *
         * @return a new immutable encryptor
         */
        public JasyptStrongEncryptor build() {
            return new JasyptStrongEncryptor(this);
        }
    }
}
