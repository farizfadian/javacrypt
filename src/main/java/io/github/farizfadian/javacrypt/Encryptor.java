package io.github.farizfadian.javacrypt;

import java.util.Arrays;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-256-GCM with a key derived by PBKDF2-HMAC-SHA256: the family's default mode.
 *
 * <p>This is authenticated encryption: a wrong password or a changed value is always detected.
 * Every member of the family reads it (GoCrypt, PyCrypt 1.0.1+, NodeCrypt, PHPCrypt, RustCrypt).
 * <strong>Java Jasypt cannot read it</strong>; use {@link JasyptEncryptor} for values that Jasypt
 * itself must read.
 *
 * <p>Wire format: {@code base64(salt || nonce(12) || ciphertext || tag(16))}.
 *
 * <p>Instances are immutable and safe to share between threads.
 */
public final class Encryptor implements StringEncryptor {

    /** Default PBKDF2 iteration count. */
    public static final int DEFAULT_ITERATIONS = 10000;

    /** Default salt size in bytes. */
    public static final int DEFAULT_SALT_SIZE = 16;

    /** Default key size in bytes (AES-256). */
    public static final int DEFAULT_KEY_SIZE = 32;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_SIZE = 12;
    private static final int TAG_BITS = 128;

    private final byte[] password;
    private final int iterations;
    private final int saltSize;
    private final int keySize;

    /**
     * Creates an encryptor with the family's default parameters: 10000 iterations, a 16-byte salt
     * and a 32-byte key.
     *
     * @param password the password, encoded as UTF-8
     */
    public Encryptor(String password) {
        this(new Builder(password));
    }

    Encryptor(Builder builder) {
        this.password = Internal.requirePassword(builder.password);
        this.iterations = Internal.requireIterations(builder.iterations);
        this.saltSize = Internal.requireSaltSize(builder.saltSize);
        if (builder.keySize != 16 && builder.keySize != 24 && builder.keySize != 32) {
            throw JavaCryptException.invalidParameter("key size must be 16, 24 or 32");
        }
        this.keySize = builder.keySize;
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
        return encryptWithSaltAndNonce(Internal.randomBytes(saltSize), Internal.randomBytes(NONCE_SIZE), plaintext);
    }

    /** The deterministic core, used directly by the golden vector tests. */
    String encryptWithSaltAndNonce(byte[] salt, byte[] nonce, String plaintext) {
        Internal.requireValue(plaintext);
        byte[] key = Kdf.pbkdf2Sha256(password, salt, iterations, keySize);
        // The cipher returns ciphertext || tag, which is the family layout.
        byte[] sealed = Internal.encrypt(TRANSFORMATION, key, new GCMParameterSpec(TAG_BITS, nonce),
                Internal.utf8(plaintext));
        return Internal.encodeBase64(salt, nonce, sealed);
    }

    @Override
    public String decrypt(String encoded) {
        Internal.requireValue(encoded);
        byte[] combined = Internal.decodeBase64(encoded);
        // Anything shorter than salt + nonce + tag cannot be authentic. Checked here, before the key
        // is derived, rather than left to the provider: JDK 17 answers a missing tag with an
        // unchecked exception of its own.
        if (combined.length < saltSize + NONCE_SIZE + TAG_BITS / 8) {
            throw JavaCryptException.decryptionFailed();
        }
        byte[] salt = Arrays.copyOfRange(combined, 0, saltSize);
        byte[] nonce = Arrays.copyOfRange(combined, saltSize, saltSize + NONCE_SIZE);
        byte[] key = Kdf.pbkdf2Sha256(password, salt, iterations, keySize);
        int offset = saltSize + NONCE_SIZE;
        byte[] plaintext = Internal.decrypt(TRANSFORMATION, key, new GCMParameterSpec(TAG_BITS, nonce),
                combined, offset, combined.length - offset);
        return Internal.plaintextFromUtf8(plaintext);
    }

    /**
     * Describes the parameters. The password is never included.
     *
     * @return for example {@code Encryptor{algorithm=AES-GCM, iterations=10000, saltSize=16, keySize=32}}
     */
    @Override
    public String toString() {
        return "Encryptor{algorithm=AES-GCM, iterations=" + iterations + ", saltSize=" + saltSize
                + ", keySize=" + keySize + "}";
    }

    /**
     * Returns the PBKDF2 iteration count.
     *
     * @return the iteration count
     */
    public int getIterations() {
        return iterations;
    }

    /**
     * Returns the salt size.
     *
     * @return the salt size in bytes
     */
    public int getSaltSize() {
        return saltSize;
    }

    /**
     * Returns the AES key size.
     *
     * @return the key size in bytes: 16, 24 or 32
     */
    public int getKeySize() {
        return keySize;
    }

    /** Builder for an {@link Encryptor} with non-default parameters. */
    public static final class Builder {

        private final String password;
        private int iterations = DEFAULT_ITERATIONS;
        private int saltSize = DEFAULT_SALT_SIZE;
        private int keySize = DEFAULT_KEY_SIZE;

        Builder(String password) {
            this.password = password;
        }

        /**
         * Sets the PBKDF2 iteration count.
         *
         * @param iterations the iteration count, default {@value Encryptor#DEFAULT_ITERATIONS}
         * @return this builder
         */
        public Builder iterations(int iterations) {
            this.iterations = iterations;
            return this;
        }

        /**
         * Sets the salt size.
         *
         * @param saltSize the salt size in bytes, default {@value Encryptor#DEFAULT_SALT_SIZE}
         * @return this builder
         */
        public Builder saltSize(int saltSize) {
            this.saltSize = saltSize;
            return this;
        }

        /**
         * Sets the AES key size.
         *
         * @param keySize 16 (AES-128), 24 (AES-192) or 32 (AES-256, the default)
         * @return this builder
         */
        public Builder keySize(int keySize) {
            this.keySize = keySize;
            return this;
        }

        /**
         * Creates the encryptor.
         *
         * @return a new immutable encryptor
         */
        public Encryptor build() {
            return new Encryptor(this);
        }
    }
}
