package io.github.farizfadian.javacrypt;

import java.util.Map;

/**
 * Common interface of {@link Encryptor}, {@link JasyptEncryptor} and {@link JasyptStrongEncryptor}.
 *
 * <p>An encrypted value does not record which algorithm produced it, so the reader must use the
 * same implementation, password and parameters as the writer.
 *
 * <p>Only {@link #encrypt(String)} and {@link #decrypt(String)} have to be implemented. The
 * {@code ENC(...)} helpers are default methods built on those two, so a custom implementation
 * works with {@link ConfigLoader} as well.
 */
public interface StringEncryptor {

    /**
     * Encrypts {@code plaintext} and returns the base64 payload, without the {@code ENC(...)} wrapper.
     *
     * <p>Every call returns a different value, because the salt is random.
     *
     * @param plaintext the text to encrypt, not empty
     * @return standard base64 with padding
     * @throws JavaCryptException with {@link ErrorCode#EMPTY_VALUE} if {@code plaintext} is null or empty
     */
    String encrypt(String plaintext);

    /**
     * Decrypts a base64 payload, without the {@code ENC(...)} wrapper.
     *
     * @param encoded the payload produced by {@link #encrypt(String)} or by another member of the family
     * @return the plaintext
     * @throws JavaCryptException if the value is empty, is not base64, or cannot be decrypted
     */
    String decrypt(String encoded);

    /**
     * Encrypts {@code plaintext} and wraps the result as {@code ENC(<base64>)}, the form used in
     * config files.
     *
     * @param plaintext the text to encrypt, not empty
     * @return the wrapped value
     * @throws JavaCryptException with {@link ErrorCode#EMPTY_VALUE} if {@code plaintext} is null or empty
     */
    default String encryptWithPrefix(String plaintext) {
        return JavaCrypt.ENC_PREFIX + encrypt(plaintext) + JavaCrypt.ENC_SUFFIX;
    }

    /**
     * Decrypts a value of the form {@code ENC(<base64>)}. Surrounding white space is ignored.
     *
     * @param value the wrapped value
     * @return the plaintext
     * @throws JavaCryptException with {@link ErrorCode#INVALID_ENC_FORMAT} if the wrapper is missing,
     *     or as {@link #decrypt(String)} does for what is inside it
     */
    default String decryptPrefixed(String value) {
        return decrypt(Internal.unwrap(value));
    }

    /**
     * Replaces every {@code ENC(...)} occurrence in {@code input} with its plaintext.
     *
     * <p>An occurrence that cannot be decrypted is left as it is and the rest of the input is still
     * processed. If any occurrence failed, the last error is then thrown. Use
     * {@link #decryptAllInStringLossy(String)} to get the partly decrypted text instead.
     *
     * <p>Do not use this on raw JSON, YAML or XML text when the plaintext may contain characters
     * that need escaping there: the decrypted text is inserted as it is. Parse the document first
     * and call {@link #decryptPrefixed(String)} on its string values.
     *
     * @param input any text, not {@code null}
     * @return the text with every occurrence decrypted
     * @throws JavaCryptException if an occurrence could not be decrypted
     */
    default String decryptAllInString(String input) {
        return Internal.decryptAll(this, input, false);
    }

    /**
     * Like {@link #decryptAllInString(String)}, but never fails: an occurrence that cannot be
     * decrypted is kept as it is.
     *
     * @param input any text, not {@code null}
     * @return the text with every decryptable occurrence decrypted
     */
    default String decryptAllInStringLossy(String input) {
        return Internal.decryptAll(this, input, true);
    }

    /**
     * Returns a copy of {@code map} in which every {@code ENC(...)} value is decrypted. Other
     * values, including {@code null}, are copied as they are, and the order of the entries is kept.
     *
     * @param map the configuration, not {@code null}; it is not modified
     * @return a new map
     * @throws JavaCryptException with {@link ErrorCode#KEY_DECRYPT} for the first value that cannot be
     *     decrypted; {@link JavaCryptException#getKey()} names its key
     */
    default Map<String, String> decryptMap(Map<String, String> map) {
        return Internal.decryptMap(this, map);
    }
}
