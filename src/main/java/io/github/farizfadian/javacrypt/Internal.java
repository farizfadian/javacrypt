package io.github.farizfadian.javacrypt;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Helpers shared by the encryptors. Nothing here is part of the public API. */
final class Internal {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Internal() {
    }

    static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Returns the UTF-8 bytes of a password, rejecting {@code null} and the empty string. */
    static byte[] requirePassword(String password) {
        if (password == null || password.isEmpty()) {
            throw JavaCryptException.emptyPassword();
        }
        return utf8(password);
    }

    /** Rejects a {@code null} or empty plaintext or ciphertext. */
    static void requireValue(String value) {
        if (value == null || value.isEmpty()) {
            throw JavaCryptException.emptyValue();
        }
    }

    static int requireIterations(int iterations) {
        if (iterations < 1) {
            throw JavaCryptException.invalidParameter("iterations must be at least 1");
        }
        return iterations;
    }

    static int requireSaltSize(int saltSize) {
        if (saltSize < 0) {
            throw JavaCryptException.invalidParameter("salt size must not be negative");
        }
        return saltSize;
    }

    /**
     * Decodes decrypted bytes as UTF-8, strictly.
     *
     * <p>{@code new String(bytes, UTF_8)} would silently replace invalid sequences with U+FFFD. Bytes
     * that are not UTF-8 mean the password or the mode was wrong, so that is "decryption failed".
     */
    static String plaintextFromUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw JavaCryptException.decryptionFailed();
        }
    }

    static String encodeBase64(byte[]... parts) {
        return Base64.getEncoder().encodeToString(concat(parts));
    }

    /**
     * Decodes standard base64 with the strictness of the rest of the family.
     *
     * <p>Like Go's decoder, CR and LF are ignored, so a value wrapped over several lines still
     * decodes. Padding is required: Go and Rust reject the unpadded form, and a value one member
     * reads must be readable by all of them. {@link Base64#getDecoder()} alone would accept it.
     */
    static byte[] decodeBase64(String encoded) {
        String compact = encoded;
        if (encoded.indexOf('\n') >= 0 || encoded.indexOf('\r') >= 0) {
            compact = encoded.replace("\r", "").replace("\n", "");
        }
        if (compact.length() % 4 != 0) {
            throw JavaCryptException.invalidBase64("input length " + compact.length() + " is not a multiple of 4");
        }
        try {
            return Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException e) {
            throw JavaCryptException.invalidBase64(e.getMessage());
        }
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    /**
     * Runs one cipher operation with a fresh {@link Cipher}, which keeps the encryptors thread-safe.
     *
     * @param transformation for example {@code AES/GCM/NoPadding}
     * @param mode {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     * @param key the raw key; its algorithm is the first part of {@code transformation}
     * @param params the IV or GCM parameters
     * @param input the bytes to process, from {@code offset} for {@code length} bytes
     */
    static byte[] crypt(String transformation, int mode, byte[] key, AlgorithmParameterSpec params,
            byte[] input, int offset, int length) throws GeneralSecurityException {
        String algorithm = transformation.substring(0, transformation.indexOf('/'));
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(mode, new SecretKeySpec(key, algorithm), params);
        return cipher.doFinal(input, offset, length);
    }
}
