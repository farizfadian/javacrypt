package io.github.farizfadian.javacrypt;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Helpers shared by the encryptors. Nothing here is part of the public API. */
final class Internal {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** The family's scan pattern: at least one character, up to the first closing parenthesis. */
    private static final Pattern ENC_PATTERN = Pattern.compile("ENC\\(([^)]+)\\)");

    private Internal() {
    }

    /**
     * White space as Go's {@code strings.TrimSpace} and Rust's {@code str::trim} define it (the
     * Unicode White_Space property). {@link String#trim()} differs: it also drops control characters
     * and keeps the no-break space.
     */
    static boolean isSpace(char c) {
        switch (c) {
            case '\t':
            case '\n':
            case '\u000b':
            case '\f':
            case '\r':
            case ' ':
            case '\u0085':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case '　':
                return true;
            default:
                return c >= ' ' && c <= ' ';
        }
    }

    static String trimSpace(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isSpace(s.charAt(start))) {
            start++;
        }
        while (end > start && isSpace(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(start, end);
    }

    /** Tells whether an already trimmed value has the {@code ENC(...)} wrapper. */
    static boolean isWrapped(String trimmed) {
        return trimmed.startsWith(JavaCrypt.ENC_PREFIX) && trimmed.endsWith(JavaCrypt.ENC_SUFFIX);
    }

    /** Trims the value, checks the wrapper and returns what is inside it, which may be empty. */
    static String unwrap(String value) {
        if (value == null) {
            throw JavaCryptException.invalidEncFormat();
        }
        String trimmed = trimSpace(value);
        if (!isWrapped(trimmed)) {
            throw JavaCryptException.invalidEncFormat();
        }
        return trimmed.substring(JavaCrypt.ENC_PREFIX.length(), trimmed.length() - JavaCrypt.ENC_SUFFIX.length());
    }

    /**
     * Replaces every {@code ENC(...)} match in {@code input} with its plaintext.
     *
     * <p>A match that cannot be decrypted stays as it is and the scan continues. When {@code lossy}
     * is false, the last such error is thrown once the whole input has been processed (GoCrypt's
     * behaviour). The text is assembled by hand: {@code Matcher.appendReplacement} would treat
     * {@code $} and {@code \} in a decrypted value as group references.
     */
    static String decryptAll(StringEncryptor encryptor, String input, boolean lossy) {
        Objects.requireNonNull(input, "input");
        Matcher matcher = ENC_PATTERN.matcher(input);
        StringBuilder out = null;
        JavaCryptException lastError = null;
        int copied = 0;
        while (matcher.find()) {
            if (out == null) {
                out = new StringBuilder(input.length());
            }
            out.append(input, copied, matcher.start());
            String match = matcher.group();
            try {
                out.append(encryptor.decryptPrefixed(match));
            } catch (JavaCryptException e) {
                lastError = e;
                out.append(match);
            }
            copied = matcher.end();
        }
        if (out == null) {
            return input;
        }
        out.append(input, copied, input.length());
        if (lastError != null && !lossy) {
            throw lastError;
        }
        return out.toString();
    }

    /** Decrypts the wrapped values of a map; the first failure aborts and names the key. */
    static Map<String, String> decryptMap(StringEncryptor encryptor, Map<String, String> map) {
        Objects.requireNonNull(map, "map");
        Map<String, String> out = new LinkedHashMap<>(Math.max(16, map.size() * 2));
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String value = entry.getValue();
            if (JavaCrypt.isEncrypted(value)) {
                try {
                    value = encryptor.decryptPrefixed(value);
                } catch (JavaCryptException e) {
                    throw JavaCryptException.keyDecrypt(entry.getKey(), e);
                }
            }
            out.put(entry.getKey(), value);
        }
        return out;
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
