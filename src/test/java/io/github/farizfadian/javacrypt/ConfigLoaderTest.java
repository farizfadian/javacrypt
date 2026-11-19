package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@link ConfigLoader}: env, flat YAML and properties files with {@code ENC(...)} values. */
class ConfigLoaderTest {

    private static final String PASSWORD = "javacrypt-test-2026";
    private static final String UTF8_SAMPLE = EncryptorContract.UTF8_SAMPLE;

    @TempDir
    Path dir;

    private Path write(String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static JavaCryptException assertFails(ErrorCode code, org.junit.jupiter.api.function.Executable action) {
        return EncryptorContract.assertFails(code, action);
    }

    // ── construction ──────────────────────────────────────────────────────────

    @Test
    void aPasswordGivesTheDefaultAesGcmEncryptorLikeGoCrypt() {
        ConfigLoader loader = new ConfigLoader(PASSWORD);
        assertTrue(loader.getEncryptor() instanceof Encryptor);
        assertEquals(10000, ((Encryptor) loader.getEncryptor()).getIterations());
    }

    @Test
    void anyStringEncryptorCanBeUsed() {
        JasyptEncryptor jasypt = new JasyptEncryptor(PASSWORD);
        assertSame(jasypt, new ConfigLoader(jasypt).getEncryptor());
    }

    @Test
    void emptyPasswordAndNullEncryptorAreRejected() {
        assertFails(ErrorCode.EMPTY_PASSWORD, () -> new ConfigLoader(""));
        assertFails(ErrorCode.EMPTY_PASSWORD, () -> new ConfigLoader((String) null));
        assertThrows(NullPointerException.class, () -> new ConfigLoader((StringEncryptor) null));
    }

    // ── env files ─────────────────────────────────────────────────────────────

    @Test
    void loadEnvFileParsesTheFamilyFormatAndDecrypts() throws IOException {
        Encryptor enc = new Encryptor(PASSWORD);
        Path file = write(".env", ""
                + "# Database settings\n"
                + "\n"
                + "DB_HOST=localhost\n"
                + "DB_PORT = 5432 \n"
                + "DB_USER=\"admin\"\n"
                + "DB_PASS='" + enc.encryptWithPrefix("s3cr3t") + "'\n"
                + "API_KEY=" + enc.encryptWithPrefix(UTF8_SAMPLE) + "\n"
                + "URL=postgres://user:pw@host/db?a=1&b=2\n"
                + "EMPTY=\n"
                + "NOT A PAIR\n"
                + "  # indented comment=1\n"
                + "  INDENTED=value\n"
                + "QUOTE_MIX=\"'both'\"\n"
                + "UNICODE=v\u00e4rde \uD83E\uDD80\n"
                + "LAST=no newline at the end");

        Map<String, String> config = new ConfigLoader(PASSWORD).loadEnvFile(file);

        assertEquals(Arrays.asList("DB_HOST", "DB_PORT", "DB_USER", "DB_PASS", "API_KEY", "URL", "EMPTY",
                "INDENTED", "QUOTE_MIX", "UNICODE", "LAST"), new ArrayList<>(config.keySet()), "file order is kept");
        assertEquals("localhost", config.get("DB_HOST"));
        assertEquals("5432", config.get("DB_PORT"));
        assertEquals("admin", config.get("DB_USER"));
        assertEquals("s3cr3t", config.get("DB_PASS"));
        assertEquals(UTF8_SAMPLE, config.get("API_KEY"));
        assertEquals("postgres://user:pw@host/db?a=1&b=2", config.get("URL"));
        assertEquals("", config.get("EMPTY"));
        assertEquals("value", config.get("INDENTED"));
        assertEquals("both", config.get("QUOTE_MIX"));
        assertEquals("v\u00e4rde \uD83E\uDD80", config.get("UNICODE"));
        assertEquals("no newline at the end", config.get("LAST"));
    }

    @Test
    void aFileWrittenOnWindowsLoadsCleanly() throws IOException {
        // UTF-8 byte order mark plus CRLF line ends: neither may leak into a key or a value.
        Encryptor enc = new Encryptor(PASSWORD);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.write(new byte[] {(byte) 0xef, (byte) 0xbb, (byte) 0xbf});
        bytes.write(("FIRST=one\r\nSECRET=" + enc.encryptWithPrefix("two") + "\r\n\r\n# note\r\nLAST=three\r\n")
                .getBytes(StandardCharsets.UTF_8));
        Path file = dir.resolve("windows.env");
        Files.write(file, bytes.toByteArray());

        Map<String, String> config = new ConfigLoader(PASSWORD).loadEnvFile(file);

        assertEquals(Arrays.asList("FIRST", "SECRET", "LAST"), new ArrayList<>(config.keySet()));
        assertEquals("one", config.get("FIRST"));
        assertEquals("two", config.get("SECRET"));
        assertEquals("three", config.get("LAST"));
    }

    @Test
    void aLaterDuplicateKeyWins() throws IOException {
        Path file = write("dup.env", "A=1\nB=2\nA=3\n");
        Map<String, String> config = new ConfigLoader(PASSWORD).loadEnvFile(file);
        assertEquals("3", config.get("A"));
        assertEquals(2, config.size());
    }

    @Test
    void aValueThatCannotBeDecryptedNamesItsKey() throws IOException {
        String foreign = new Encryptor("another-password").encryptWithPrefix("x");
        Path file = write("bad.env", "OK=plain\nDB_PASS=" + foreign + "\nLATER=ENC(not base64!)\n");

        JavaCryptException e = assertFails(ErrorCode.KEY_DECRYPT, () -> new ConfigLoader(PASSWORD).loadEnvFile(file));

        assertEquals("failed to decrypt key DB_PASS: decryption failed", e.getMessage());
        assertEquals("DB_PASS", e.getKey());
        assertEquals(ErrorCode.DECRYPTION_FAILED, ((JavaCryptException) e.getCause()).getCode());
    }

    @Test
    void pathsCanBeGivenAsStrings() throws IOException {
        Path file = write("s.env", "A=1\n");
        ConfigLoader loader = new ConfigLoader(PASSWORD);
        assertEquals("1", loader.loadEnvFile(file.toString()).get("A"));
        assertEquals("1", loader.loadYaml(write("s.yml", "A: 1\n").toString()).get("A"));
        assertEquals("1", loader.loadProperties(write("s.properties", "A=1\n").toString()).getProperty("A"));
    }

    // ── flat YAML ─────────────────────────────────────────────────────────────

    @Test
    void loadYamlIsTheSameFlatLineParserAsGoCrypt() throws IOException {
        Encryptor enc = new Encryptor(PASSWORD);
        Path file = write("config.yml", ""
                + "# application\n"
                + "name: 'my app'\n"
                + "database:\n"
                + "  host: localhost\n"
                + "  port: 5432\n"
                + "  password: " + enc.encryptWithPrefix("s3cr3t") + "\n"
                + "  url: \"jdbc:postgresql://db:5432/app\"\n"
                + "- a list item without a colon\n"
                + "greeting: " + UTF8_SAMPLE + "\n");

        Map<String, String> config = new ConfigLoader(PASSWORD).loadYaml(file);

        // Nesting is flattened: "database:" is an entry with an empty value, its children are top level.
        assertEquals(Arrays.asList("name", "database", "host", "port", "password", "url", "greeting"),
                new ArrayList<>(config.keySet()));
        assertEquals("my app", config.get("name"));
        assertEquals("", config.get("database"));
        assertEquals("localhost", config.get("host"));
        assertEquals("5432", config.get("port"));
        assertEquals("s3cr3t", config.get("password"));
        assertEquals("jdbc:postgresql://db:5432/app", config.get("url"), "only the first colon separates");
        assertEquals(UTF8_SAMPLE, config.get("greeting"));
    }

    @Test
    void loadYamlNamesTheKeyThatFailed() throws IOException {
        Path file = write("bad.yml", "ok: fine\napi_key: ENC(not base64!)\n");
        JavaCryptException e = assertFails(ErrorCode.KEY_DECRYPT, () -> new ConfigLoader(PASSWORD).loadYaml(file));
        assertEquals("api_key", e.getKey());
        assertTrue(e.getMessage().startsWith("failed to decrypt key api_key: failed to decode base64: "),
                e.getMessage());
    }

    // ── properties ────────────────────────────────────────────────────────────

    @Test
    void loadPropertiesReadsUtf8AndDecrypts() throws IOException {
        Encryptor enc = new Encryptor(PASSWORD);
        Path file = write("app.properties", ""
                + "# comment\n"
                + "! another comment\n"
                + "db.host=localhost\n"
                + "db.password=" + enc.encryptWithPrefix("s3cr3t") + "\n"
                + "spaced = " + enc.encryptWithPrefix("with spaces") + "\n"
                + "greeting=" + UTF8_SAMPLE + "\n"
                + "path=C:\\\\dir\\\\file\n"
                + "colon: also a separator\n");

        Properties properties = new ConfigLoader(PASSWORD).loadProperties(file);

        assertEquals("localhost", properties.getProperty("db.host"));
        assertEquals("s3cr3t", properties.getProperty("db.password"));
        assertEquals("with spaces", properties.getProperty("spaced"));
        assertEquals(UTF8_SAMPLE, properties.getProperty("greeting"), "UTF-8 is the default charset");
        assertEquals("C:\\dir\\file", properties.getProperty("path"), "java.util.Properties escape rules apply");
        assertEquals("also a separator", properties.getProperty("colon"));
        assertEquals(6, properties.size());
    }

    @Test
    void loadPropertiesHonoursAnExplicitCharset() throws IOException {
        Path file = dir.resolve("latin1.properties");
        Files.write(file, "name=caf\u00e9\n".getBytes(StandardCharsets.ISO_8859_1));
        ConfigLoader loader = new ConfigLoader(PASSWORD);
        assertEquals("caf\u00e9", loader.loadProperties(file, StandardCharsets.ISO_8859_1).getProperty("name"));
        // The same bytes are not valid UTF-8: reported, not silently replaced.
        assertFails(ErrorCode.IO, () -> loader.loadProperties(file));
    }

    @Test
    void loadPropertiesNamesTheKeyThatFailed() throws IOException {
        Path file = write("bad.properties", "ok=fine\ndb.password=ENC(not base64!)\n");
        JavaCryptException e = assertFails(ErrorCode.KEY_DECRYPT,
                () -> new ConfigLoader(PASSWORD).loadProperties(file));
        assertEquals("db.password", e.getKey());
    }

    // ── system properties ─────────────────────────────────────────────────────

    @Test
    void setToSystemPropertiesExportsTheDecryptedEnvFile() throws IOException {
        Encryptor enc = new Encryptor(PASSWORD);
        String plain = "javacrypt.test.plain";
        String secret = "javacrypt.test.secret";
        Path file = write("sys.env", plain + "=visible\n" + secret + "=" + enc.encryptWithPrefix(UTF8_SAMPLE) + "\n");
        try {
            new ConfigLoader(PASSWORD).setToSystemProperties(file);
            assertEquals("visible", System.getProperty(plain));
            assertEquals(UTF8_SAMPLE, System.getProperty(secret));

            System.clearProperty(plain);
            new ConfigLoader(PASSWORD).setToSystemProperties(file.toString());
            assertEquals("visible", System.getProperty(plain));
        } finally {
            System.clearProperty(plain);
            System.clearProperty(secret);
        }
    }

    @Test
    void setToSystemPropertiesSetsNothingWhenAValueFails() throws IOException {
        String first = "javacrypt.test.first";
        Path file = write("partial.env", first + "=1\nBROKEN=ENC(not base64!)\n");
        try {
            assertFails(ErrorCode.KEY_DECRYPT, () -> new ConfigLoader(PASSWORD).setToSystemProperties(file));
            assertNull(System.getProperty(first), "the file is decrypted completely before anything is set");
        } finally {
            System.clearProperty(first);
        }
    }

    @Test
    void setToSystemPropertiesRejectsALineWithoutAName() throws IOException {
        String first = "javacrypt.test.before-nameless";
        Path file = write("nameless.env", first + "=1\n=value without a name\n");
        try {
            JavaCryptException e = assertFails(ErrorCode.INVALID_PARAMETER,
                    () -> new ConfigLoader(PASSWORD).setToSystemProperties(file));
            assertEquals("invalid parameter: cannot set a system property with an empty name", e.getMessage());
            assertNull(System.getProperty(first), "nothing is set when any name is invalid");
        } finally {
            System.clearProperty(first);
        }
    }

    // ── other encryptors, and I/O errors ──────────────────────────────────────

    @Test
    void everyLoaderWorksWithTheJasyptModesAndACustomEncryptor() throws IOException {
        StringEncryptor shout = new StringEncryptor() {
            @Override
            public String encrypt(String plaintext) {
                return plaintext.toLowerCase(java.util.Locale.ROOT);
            }

            @Override
            public String decrypt(String encoded) {
                return encoded.toUpperCase(java.util.Locale.ROOT);
            }
        };
        for (StringEncryptor enc : new StringEncryptor[] {
            new JasyptEncryptor(PASSWORD), new JasyptStrongEncryptor(PASSWORD), shout}) {
            String wrapped = enc.encryptWithPrefix("SECRET");
            ConfigLoader loader = new ConfigLoader(enc);
            String label = enc.getClass().getSimpleName();
            assertEquals("SECRET", loader.loadEnvFile(write("m.env", "K=" + wrapped + "\n")).get("K"), label);
            assertEquals("SECRET", loader.loadYaml(write("m.yml", "k: " + wrapped + "\n")).get("k"), label);
            assertEquals("SECRET",
                    loader.loadProperties(write("m.properties", "k=" + wrapped + "\n")).getProperty("k"), label);
        }
    }

    @Test
    void aValueOfAnotherModeIsAnErrorNotSilentlyKept() throws IOException {
        // The default loader is AES-GCM. A --jasypt value must not come back as the literal ENC(...).
        String jasyptValue = new JasyptEncryptor(PASSWORD).encryptWithPrefix("hello");
        Path file = write("mode.env", "K=" + jasyptValue + "\n");
        assertFails(ErrorCode.KEY_DECRYPT, () -> new ConfigLoader(PASSWORD).loadEnvFile(file));
    }

    @Test
    void aMissingFileIsAnIoError() {
        ConfigLoader loader = new ConfigLoader(PASSWORD);
        Path missing = dir.resolve("does-not-exist.env");
        JavaCryptException e = assertFails(ErrorCode.IO, () -> loader.loadEnvFile(missing));
        assertTrue(e.getMessage().contains("does-not-exist.env"), e.getMessage());
        assertTrue(e.getCause() instanceof IOException);
        assertFails(ErrorCode.IO, () -> loader.loadYaml(missing));
        assertFails(ErrorCode.IO, () -> loader.loadProperties(missing));
        assertFails(ErrorCode.IO, () -> loader.setToSystemProperties(missing));
        assertFails(ErrorCode.IO, () -> loader.loadEnvFile(dir));
    }

    @Test
    void aFileThatIsNotUtf8IsAnIoErrorNotMojibake() throws IOException {
        Path file = dir.resolve("latin1.env");
        Files.write(file, "NAME=caf\u00e9\n".getBytes(StandardCharsets.ISO_8859_1));
        JavaCryptException e = assertFails(ErrorCode.IO, () -> new ConfigLoader(PASSWORD).loadEnvFile(file));
        assertTrue(e.getMessage().contains("UTF-8"), e.getMessage());
        assertFalse(e.getMessage().contains("caf"), "file content must not be echoed");
    }
}
