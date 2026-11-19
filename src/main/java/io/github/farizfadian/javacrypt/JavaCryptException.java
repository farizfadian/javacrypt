package io.github.farizfadian.javacrypt;

/**
 * The single unchecked exception thrown by JavaCrypt.
 *
 * <p>Use {@link #getCode()} to tell the cases apart. The messages match the other members of the
 * family (GoCrypt is the reference), for example {@code "decryption failed"} or
 * {@code "invalid encrypted format, expected ENC(...)"}.
 */
public class JavaCryptException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * The reason this exception was thrown.
     *
     * @serial
     */
    private final ErrorCode code;

    /**
     * The key whose value could not be decrypted, or {@code null}.
     *
     * @serial
     */
    private final String key;

    /**
     * Creates an exception without a cause.
     *
     * @param code the reason
     * @param message the message, in the family's wording
     */
    public JavaCryptException(ErrorCode code, String message) {
        this(code, message, null, null);
    }

    /**
     * Creates an exception with a cause.
     *
     * @param code the reason
     * @param message the message, in the family's wording
     * @param cause the underlying exception, may be {@code null}
     */
    public JavaCryptException(ErrorCode code, String message, Throwable cause) {
        this(code, message, null, cause);
    }

    private JavaCryptException(ErrorCode code, String message, String key, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.key = key;
    }

    /**
     * Returns the reason this exception was thrown.
     *
     * @return the error code, never {@code null}
     */
    public ErrorCode getCode() {
        return code;
    }

    /**
     * Returns the key whose value could not be decrypted.
     *
     * @return the key for {@link ErrorCode#KEY_DECRYPT}, otherwise {@code null}
     */
    public String getKey() {
        return key;
    }

    static JavaCryptException emptyPassword() {
        return new JavaCryptException(ErrorCode.EMPTY_PASSWORD, "password cannot be empty");
    }

    static JavaCryptException emptyValue() {
        return new JavaCryptException(ErrorCode.EMPTY_VALUE, "value cannot be empty");
    }

    static JavaCryptException invalidEncFormat() {
        return new JavaCryptException(ErrorCode.INVALID_ENC_FORMAT, "invalid encrypted format, expected ENC(...)");
    }

    static JavaCryptException invalidJasyptData() {
        return new JavaCryptException(ErrorCode.INVALID_JASYPT_DATA, "invalid jasypt encrypted data");
    }

    /** Deliberately carries no cause and no detail: callers must not learn why decryption failed. */
    static JavaCryptException decryptionFailed() {
        return new JavaCryptException(ErrorCode.DECRYPTION_FAILED, "decryption failed");
    }

    static JavaCryptException invalidBase64(String detail) {
        return new JavaCryptException(ErrorCode.INVALID_BASE64, "failed to decode base64: " + detail);
    }

    static JavaCryptException keyDecrypt(String key, JavaCryptException cause) {
        return new JavaCryptException(ErrorCode.KEY_DECRYPT,
                "failed to decrypt key " + key + ": " + cause.getMessage(), key, cause);
    }

    static JavaCryptException invalidParameter(String detail) {
        return new JavaCryptException(ErrorCode.INVALID_PARAMETER, "invalid parameter: " + detail);
    }

    static JavaCryptException io(String message, Throwable cause) {
        return new JavaCryptException(ErrorCode.IO, message, cause);
    }

    static JavaCryptException unsupported(String what, Throwable cause) {
        return new JavaCryptException(ErrorCode.UNSUPPORTED,
                "not supported by this Java runtime: " + what, cause);
    }
}
