package io.github.farizfadian.javacrypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Constants and helpers for the {@code ENC(...)} wrapper shared by the whole family.
 *
 * <p>In a config file, an encrypted value is written as {@code ENC(<base64>)}. Every
 * {@link StringEncryptor} can produce and read that form with
 * {@link StringEncryptor#encryptWithPrefix(String)} and {@link StringEncryptor#decryptPrefixed(String)}.
 */
public final class JavaCrypt {

    /** Prefix of a wrapped encrypted value. */
    public static final String ENC_PREFIX = "ENC(";

    /** Suffix of a wrapped encrypted value. */
    public static final String ENC_SUFFIX = ")";

    private static final String VERSION = loadVersion();

    private JavaCrypt() {
    }

    /**
     * Tells whether a value looks like {@code ENC(...)}, ignoring surrounding white space.
     *
     * <p>Only the wrapper is checked, not whether the payload can be decrypted.
     *
     * @param value the value to check, may be {@code null}
     * @return {@code true} if the trimmed value starts with {@code ENC(} and ends with {@code )}
     */
    public static boolean isEncrypted(String value) {
        return value != null && Internal.isWrapped(Internal.trimSpace(value));
    }

    /**
     * Returns the version of this library.
     *
     * @return for example {@code 1.0.0}, or {@code unknown} if the jar was repackaged without its resources
     */
    public static String version() {
        return VERSION;
    }

    private static String loadVersion() {
        try (InputStream in = JavaCrypt.class.getResourceAsStream("version.properties")) {
            if (in != null) {
                Properties properties = new Properties();
                properties.load(in);
                String version = properties.getProperty("version");
                if (version != null && !version.isEmpty()) {
                    return version;
                }
            }
        } catch (IOException e) {
            // fall through: the version is informational only
        }
        return "unknown";
    }
}
