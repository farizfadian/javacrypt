package io.github.farizfadian.javacrypt;

/**
 * Common interface of {@link Encryptor}, {@link JasyptEncryptor} and {@link JasyptStrongEncryptor}.
 *
 * <p>An encrypted value does not record which algorithm produced it, so the reader must use the
 * same implementation, password and parameters as the writer.
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
}
