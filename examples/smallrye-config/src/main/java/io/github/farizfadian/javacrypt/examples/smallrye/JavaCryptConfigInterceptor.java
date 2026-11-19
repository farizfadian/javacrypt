package io.github.farizfadian.javacrypt.examples.smallrye;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JavaCrypt;
import io.github.farizfadian.javacrypt.JavaCryptException;
import io.github.farizfadian.javacrypt.StringEncryptor;
import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.Priorities;
import jakarta.annotation.Priority;

/**
 * Decrypts {@code ENC(...)} configuration values with JavaCrypt.
 *
 * <p>SmallRye Config is the configuration engine of Quarkus. With this class on the classpath and
 * registered in {@code META-INF/services/io.smallrye.config.ConfigSourceInterceptor}, any property
 * whose value is {@code ENC(...)} reaches the application decrypted, whichever source it came from:
 *
 * <pre>
 * # application.properties
 * db.password=ENC(kU/jNgiOOc9euKgZ2vAjYlpKoahu4KXaaoJ8XL75fs2AwbzwVRF4d2ey0pqQdVNT5Q==)
 * </pre>
 *
 * <p>The password is read from the property {@code javacrypt.password}, which SmallRye maps to the
 * environment variable {@code JAVACRYPT_PASSWORD}. Keep it out of files that are committed.
 *
 * <p>Values are decrypted with {@link Encryptor} (AES-256-GCM), the family's default mode. For
 * values written by Java Jasypt, create a {@code JasyptEncryptor} in {@link #encryptor(String)}
 * instead.
 */
@Priority(Priorities.APPLICATION)
public class JavaCryptConfigInterceptor implements ConfigSourceInterceptor {

    private static final long serialVersionUID = 1L;

    /** The property that holds the password. As an environment variable: {@code JAVACRYPT_PASSWORD}. */
    public static final String PASSWORD_PROPERTY = "javacrypt.password";

    // Created on first use: most applications read plain values long before an encrypted one.
    private transient volatile StringEncryptor encryptor;

    @Override
    public ConfigValue getValue(ConfigSourceInterceptorContext context, String name) {
        ConfigValue value = context.proceed(name);
        if (value == null || PASSWORD_PROPERTY.equals(name) || !JavaCrypt.isEncrypted(value.getValue())) {
            return value;
        }
        try {
            return value.withValue(encryptor(context).decryptPrefixed(value.getValue()));
        } catch (JavaCryptException e) {
            // Name the property, never the value.
            throw new IllegalStateException("Cannot decrypt configuration property " + name + ": " + e.getMessage(), e);
        }
    }

    private StringEncryptor encryptor(ConfigSourceInterceptorContext context) {
        StringEncryptor current = encryptor;
        if (current == null) {
            ConfigValue password = context.proceed(PASSWORD_PROPERTY);
            if (password == null || password.getValue() == null || password.getValue().isEmpty()) {
                throw new JavaCryptException(io.github.farizfadian.javacrypt.ErrorCode.EMPTY_PASSWORD,
                        "no password: set the environment variable JAVACRYPT_PASSWORD (property " + PASSWORD_PROPERTY
                                + ")");
            }
            current = encryptor(password.getValue());
            encryptor = current;
        }
        return current;
    }

    /**
     * Creates the encryptor. Override or change this to use another mode, for example
     * {@code new JasyptEncryptor(password)} for values shared with an application that uses Jasypt.
     *
     * @param password the password
     * @return the encryptor used for every {@code ENC(...)} value
     */
    protected StringEncryptor encryptor(String password) {
        return new Encryptor(password);
    }
}
