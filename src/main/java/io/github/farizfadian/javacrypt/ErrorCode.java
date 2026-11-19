package io.github.farizfadian.javacrypt;

/**
 * The reason a {@link JavaCryptException} was thrown.
 *
 * <p>New constants may be added in minor releases, so keep a {@code default} branch when switching
 * on this enum.
 */
public enum ErrorCode {

    /** The password given to a constructor or builder was {@code null} or empty. */
    EMPTY_PASSWORD,

    /** The plaintext or ciphertext given to encrypt or decrypt was {@code null} or empty. */
    EMPTY_VALUE,

    /** A value was expected to look like {@code ENC(...)} but did not. */
    INVALID_ENC_FORMAT,

    /** The decoded payload of a Jasypt mode is too short or not aligned to the cipher's block size. */
    INVALID_JASYPT_DATA,

    /**
     * Authentication or padding failed, or the result was not valid UTF-8: a wrong password, a wrong
     * mode, or data that was changed. No further detail is given on purpose.
     */
    DECRYPTION_FAILED,

    /** The value was not valid standard base64 with padding. */
    INVALID_BASE64,

    /** A value belonging to a named key (in a map or a config file) could not be decrypted. */
    KEY_DECRYPT,

    /** A builder parameter was out of range, for example a key size other than 16, 24 or 32. */
    INVALID_PARAMETER,

    /** A configuration file could not be read. */
    IO,

    /**
     * This Java runtime does not provide a required algorithm or key size, for example AES-256 on a
     * Java 8 release older than 8u161 without the unlimited strength policy files.
     */
    UNSUPPORTED
}
