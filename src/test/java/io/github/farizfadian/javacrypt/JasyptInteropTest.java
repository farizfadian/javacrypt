package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.junit.jupiter.api.Test;

/**
 * Interoperability with the real Java Jasypt library (org.jasypt:jasypt 1.9.3, a test dependency).
 *
 * <p>What these tests establish: {@link JasyptEncryptor} and Jasypt's default
 * {@code PBEWithMD5AndDES} read each other's values. The other two modes are family formats that
 * Jasypt cannot read, which the tests at the bottom demonstrate rather than assume.
 */
class JasyptInteropTest {

    private static final String PASSWORD = "javacrypt-test-2026";

    private static final List<String> PLAINTEXTS = Arrays.asList(
            "hello",
            "Password123!",
            EncryptorContract.repeat("0123456789", 20),
            "12345678",
            EncryptorContract.UTF8_SAMPLE,
            "日本語のテキスト",
            "naïve café ☕");

    /** Jasypt exactly as its documentation shows it: only the password is set. */
    private static StandardPBEStringEncryptor jasyptWithDefaults(String password) {
        StandardPBEStringEncryptor jasypt = new StandardPBEStringEncryptor();
        jasypt.setPassword(password);
        return jasypt;
    }

    private static StandardPBEStringEncryptor jasypt(String password, int iterations) {
        StandardPBEStringEncryptor jasypt = new StandardPBEStringEncryptor();
        jasypt.setPassword(password);
        jasypt.setAlgorithm("PBEWithMD5AndDES");
        jasypt.setKeyObtentionIterations(iterations);
        return jasypt;
    }

    private static String runtime() {
        return "Java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")";
    }

    /**
     * Why Jasypt on this JVM cannot round-trip its own value with the given password, or
     * {@code null} if it can. The reason ends up in the test report, so the matrix shows what each
     * Java version does.
     */
    private static String whyJasyptRejects(String password) {
        try {
            StandardPBEStringEncryptor jasypt = jasyptWithDefaults(password);
            return "probe".equals(jasypt.decrypt(jasypt.encrypt("probe"))) ? null : "it does not read its own value";
        } catch (RuntimeException e) {
            Throwable root = e;
            while (root.getCause() != null) {
                root = root.getCause();
            }
            return root.getClass().getSimpleName() + ": " + root.getMessage();
        }
    }

    private static void assumeJasyptAccepts(String password) {
        String reason = whyJasyptRejects(password);
        assumeTrue(reason == null,
                "Jasypt cannot use a non-ASCII password on " + runtime() + " [" + reason + "]; nothing to compare");
    }

    // ── PBEWithMD5AndDES: both directions ─────────────────────────────────────

    @Test
    void jasyptReadsWhatJavaCryptWrites() {
        JasyptEncryptor javacrypt = new JasyptEncryptor(PASSWORD);
        StandardPBEStringEncryptor jasypt = jasyptWithDefaults(PASSWORD);
        for (String plaintext : PLAINTEXTS) {
            assertEquals(plaintext, jasypt.decrypt(javacrypt.encrypt(plaintext)));
        }
    }

    @Test
    void javaCryptReadsWhatJasyptWrites() {
        JasyptEncryptor javacrypt = new JasyptEncryptor(PASSWORD);
        StandardPBEStringEncryptor jasypt = jasyptWithDefaults(PASSWORD);
        for (String plaintext : PLAINTEXTS) {
            assertEquals(plaintext, javacrypt.decrypt(jasypt.encrypt(plaintext)));
        }
    }

    @Test
    void theEncWrapperIsTheOneJasyptPropertiesUse() {
        // Jasypt's property support wraps values as ENC(...). The payload inside is what encrypt() returns.
        JasyptEncryptor javacrypt = new JasyptEncryptor(PASSWORD);
        StandardPBEStringEncryptor jasypt = jasyptWithDefaults(PASSWORD);
        String wrapped = javacrypt.encryptWithPrefix("hello");
        assertEquals("hello", jasypt.decrypt(wrapped.substring(4, wrapped.length() - 1)));
        assertEquals("hello", javacrypt.decryptPrefixed("ENC(" + jasypt.encrypt("hello") + ")"));
    }

    @Test
    void customIterationCountsInteroperateBothWays() {
        JasyptEncryptor javacrypt = JasyptEncryptor.builder(PASSWORD).iterations(2000).build();
        StandardPBEStringEncryptor jasypt = jasypt(PASSWORD, 2000);
        assertEquals(EncryptorContract.UTF8_SAMPLE, jasypt.decrypt(javacrypt.encrypt(EncryptorContract.UTF8_SAMPLE)));
        assertEquals(EncryptorContract.UTF8_SAMPLE, javacrypt.decrypt(jasypt.encrypt(EncryptorContract.UTF8_SAMPLE)));

        // Sanity: the iteration count really matters. 1000 on one side must not read 2000 on the other.
        JasyptEncryptor defaults = new JasyptEncryptor(PASSWORD);
        String fromJasypt = jasypt.encrypt("hello");
        try {
            assertNotEquals("hello", defaults.decrypt(fromJasypt));
        } catch (JavaCryptException e) {
            assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
        }
    }

    // ── non-ASCII passwords ───────────────────────────────────────────────────

    @Test
    void nonAsciiPasswordInteroperatesWhereJasyptAcceptsIt() {
        // Jasypt hands the password to the JDK's PBEWithMD5AndDES key factory, and what that does
        // with non-ASCII characters depends on the JDK. JavaCrypt always uses the UTF-8 bytes
        // (pinned by the GoCrypt vectors). So: if Jasypt works with this password on this JVM at
        // all, the two must agree; if it does not, there is nothing to compare.
        String password = Fixtures.UNICODE_PASSWORD;
        assumeJasyptAccepts(password);

        JasyptEncryptor javacrypt = new JasyptEncryptor(password);
        StandardPBEStringEncryptor jasypt = jasyptWithDefaults(password);
        for (String plaintext : PLAINTEXTS) {
            assertEquals(plaintext, jasypt.decrypt(javacrypt.encrypt(plaintext)), runtime());
            assertEquals(plaintext, javacrypt.decrypt(jasypt.encrypt(plaintext)), runtime());
        }
    }

    @Test
    void jasyptNormalizesThePasswordToNfcAndJavaCryptDoesNot() {
        // "a" followed by a combining diaeresis: the same text as the single letter U+00E4, but
        // different bytes. Jasypt normalizes passwords to NFC before use; the family uses the
        // bytes as given. A caller with a decomposed password must normalize it for Jasypt interop.
        String decomposed = "pässword";
        String composed = Normalizer.normalize(decomposed, Normalizer.Form.NFC);
        assertNotEquals(decomposed, composed);
        assumeJasyptAccepts(decomposed);

        String fromJasypt = jasyptWithDefaults(decomposed).encrypt("hello");
        assertEquals("hello", new JasyptEncryptor(composed).decrypt(fromJasypt));
        try {
            assertNotEquals("hello", new JasyptEncryptor(decomposed).decrypt(fromJasypt));
        } catch (JavaCryptException e) {
            assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
        }
    }

    // ── what Jasypt cannot read (so the documentation states facts, not hopes) ─

    @Test
    void jasyptCannotReadADefaultModeValue() {
        String encoded = new Encryptor(PASSWORD).encrypt("hello");
        String got;
        try {
            got = jasyptWithDefaults(PASSWORD).decrypt(encoded);
        } catch (RuntimeException expected) {
            got = null;
        }
        assertNotEquals("hello", got);
    }

    private static StandardPBEStringEncryptor jasyptStrong(String password) {
        StandardPBEStringEncryptor jasypt = new StandardPBEStringEncryptor();
        jasypt.setPassword(password);
        jasypt.setAlgorithm("PBEWITHHMACSHA256ANDAES_256");
        jasypt.setIvGenerator(new RandomIvGenerator());
        return jasypt;
    }

    private static boolean jasyptStrongWorksHere() {
        try {
            StandardPBEStringEncryptor jasypt = jasyptStrong(PASSWORD);
            return "probe".equals(jasypt.decrypt(jasypt.encrypt("probe")));
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Test
    void theFamilyStrongLayoutIsNotJasyptsStrongFormat() {
        assumeTrue(jasyptStrongWorksHere(), "PBEWITHHMACSHA256ANDAES_256 is not usable on " + runtime());
        JasyptStrongEncryptor javacrypt = new JasyptStrongEncryptor(PASSWORD);
        StandardPBEStringEncryptor jasypt = jasyptStrong(PASSWORD);

        // Jasypt -> JavaCrypt: an error, or garbage. Never the plaintext.
        String fromJasypt = jasypt.encrypt("hello");
        try {
            assertNotEquals("hello", javacrypt.decrypt(fromJasypt));
        } catch (JavaCryptException e) {
            assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
        }

        // JavaCrypt -> Jasypt: the same.
        String fromJavaCrypt = javacrypt.encrypt("hello");
        String got;
        try {
            got = jasypt.decrypt(fromJavaCrypt);
        } catch (RuntimeException expected) {
            got = null;
        }
        assertNotEquals("hello", got);
    }

    @Test
    void theOnlyDifferenceToJasyptsStrongFormatIsWhereTheIvComesFrom() {
        // Documents the exact gap, for the day the family moves to Jasypt's layout together:
        // the key derivation is identical; Jasypt stores a random IV after the salt, the family
        // derives the IV. Inserting the derived IV after the salt gives a value Jasypt reads.
        assumeTrue(jasyptStrongWorksHere(), "PBEWITHHMACSHA256ANDAES_256 is not usable on " + runtime());
        JasyptStrongEncryptor javacrypt = new JasyptStrongEncryptor(PASSWORD);
        byte[] family = Base64.getDecoder().decode(javacrypt.encrypt(EncryptorContract.UTF8_SAMPLE));
        byte[] salt = Arrays.copyOfRange(family, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(family, 16, family.length);
        byte[] derived = Kdf.pbkdf2Sha256(Fixtures.utf8(PASSWORD), salt, 1000, 48);
        byte[] iv = Arrays.copyOfRange(derived, 32, 48);

        String jasyptLayout = Base64.getEncoder().encodeToString(Internal.concat(salt, iv, ciphertext));

        assertEquals(EncryptorContract.UTF8_SAMPLE, jasyptStrong(PASSWORD).decrypt(jasyptLayout));
    }
}
