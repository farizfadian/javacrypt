package io.github.farizfadian.javacrypt;

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

    static String fromUtf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static String encodeBase64(byte[]... parts) {
        return Base64.getEncoder().encodeToString(concat(parts));
    }

    static byte[] decodeBase64(String encoded) {
        try {
            return Base64.getDecoder().decode(encoded);
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
