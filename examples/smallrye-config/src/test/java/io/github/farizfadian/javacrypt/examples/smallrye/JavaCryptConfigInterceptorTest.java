package io.github.farizfadian.javacrypt.examples.smallrye;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JasyptEncryptor;
import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Proves the interceptor with a real {@link SmallRyeConfig}: the same object a Quarkus application
 * reads its configuration from.
 */
class JavaCryptConfigInterceptorTest {

    private static final String PASSWORD = "example-password";

    /** The application's own configuration, as it would be in application.properties. */
    private static Map<String, String> application(String encryptedPassword) {
        Map<String, String> properties = new HashMap<>();
        properties.put("db.host", "localhost");
        properties.put("db.password", encryptedPassword);
        properties.put("db.url", "jdbc:postgresql://${db.host}/app");
        return properties;
    }

    /** A config with the interceptor discovered through META-INF/services, like in a real application. */
    private static SmallRyeConfig config(Map<String, String> application, Map<String, String> environment) {
        return new SmallRyeConfigBuilder()
                .addDefaultInterceptors()
                .addDiscoveredInterceptors()
                .withSources(new PropertiesConfigSource(application, "application.properties", 250))
                .withSources(new EnvConfigSource(environment, 300))
                .build();
    }

    private static Map<String, String> environment(String password) {
        Map<String, String> environment = new HashMap<>();
        environment.put("JAVACRYPT_PASSWORD", password);
        return environment;
    }

    @Test
    void encryptedValuesAreDecryptedAndOthersAreUntouched() {
        String encrypted = new Encryptor(PASSWORD).encryptWithPrefix("s3cr3t");
        SmallRyeConfig config = config(application(encrypted), environment(PASSWORD));

        assertEquals("s3cr3t", config.getValue("db.password", String.class));
        assertEquals("localhost", config.getValue("db.host", String.class));
        assertEquals("jdbc:postgresql://localhost/app", config.getValue("db.url", String.class),
                "the built-in expression expansion still works");
        assertEquals(Optional.empty(), config.getOptionalValue("db.missing", String.class));
    }

    @Test
    void thePasswordIsTheEnvironmentVariableJavacryptPassword() {
        // SmallRye maps the property javacrypt.password to the environment variable JAVACRYPT_PASSWORD.
        String encrypted = new Encryptor(PASSWORD).encryptWithPrefix("s3cr3t");
        SmallRyeConfig config = config(application(encrypted), environment(PASSWORD));
        assertEquals("s3cr3t", config.getValue("db.password", String.class));

        // A different password in the environment cannot open the value.
        SmallRyeConfig wrong = config(application(encrypted), environment("another-password"));
        RuntimeException e = assertThrows(RuntimeException.class, () -> wrong.getValue("db.password", String.class));
        assertTrue(messages(e).contains("db.password"), messages(e));
        assertFalse(messages(e).contains("s3cr3t"));
    }

    @Test
    void aMissingPasswordIsReportedOnlyWhenAnEncryptedValueIsRead() {
        String encrypted = new Encryptor(PASSWORD).encryptWithPrefix("s3cr3t");
        SmallRyeConfig config = config(application(encrypted), new HashMap<>());

        // Plain values do not need the password.
        assertEquals("localhost", config.getValue("db.host", String.class));

        RuntimeException e = assertThrows(RuntimeException.class, () -> config.getValue("db.password", String.class));
        assertTrue(messages(e).contains("JAVACRYPT_PASSWORD"), messages(e));
        assertTrue(messages(e).contains("db.password"), messages(e));
    }

    @Test
    void aValueWrittenInAnotherModeIsAnErrorNotTheLiteralText() {
        // The interceptor uses AES-256-GCM. A value written with the Jasypt-compatible mode must not
        // reach the application as "ENC(...)".
        String jasyptValue = new JasyptEncryptor(PASSWORD).encryptWithPrefix("s3cr3t");
        SmallRyeConfig config = config(application(jasyptValue), environment(PASSWORD));
        assertThrows(RuntimeException.class, () -> config.getValue("db.password", String.class));
    }

    @Test
    void thePasswordItselfIsNeverDecrypted() {
        // A password that happens to look like ENC(...) must not send the interceptor into a loop.
        SmallRyeConfig config = config(application("plain"), environment("ENC(not-a-ciphertext)"));
        assertEquals("ENC(not-a-ciphertext)", config.getValue("javacrypt.password", String.class));
        assertEquals("plain", config.getValue("db.password", String.class));
    }

    private static String messages(Throwable e) {
        StringBuilder all = new StringBuilder();
        for (Throwable t = e; t != null; t = t.getCause()) {
            all.append(t.getMessage()).append(" | ");
        }
        return all.toString();
    }
}
