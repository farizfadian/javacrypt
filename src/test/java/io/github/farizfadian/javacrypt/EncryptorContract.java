package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Behaviour every encryptor must show, whatever its algorithm. The three concrete test classes
 * extend this one and add what is specific to their wire format.
 */
abstract class EncryptorContract {

    static final String PASSWORD = "javacrypt-test-2026";
    static final String UTF8_SAMPLE = "Selamat pagi, Fariz 🦀";

    /** Creates the encryptor under test with its default parameters. */
    abstract StringEncryptor create(String password);

    /** Creates the encryptor under test with a non-default iteration count. */
    abstract StringEncryptor createWithIterations(String password, int iterations);

    /** True for AES-GCM, which always detects a wrong password; false for the CBC modes. */
    abstract boolean authenticated();

    /** Encrypts raw bytes the way the mode does, so a test can plant bytes that are not UTF-8. */
    abstract String sealRawBytes(String password, byte[] plaintext) throws Exception;

    static JavaCryptException assertFails(ErrorCode code, Executable action) {
        JavaCryptException e = assertThrows(JavaCryptException.class, action);
        assertEquals(code, e.getCode(), e.getMessage());
        return e;
    }

    static String repeat(String s, int times) {
        StringBuilder sb = new StringBuilder(s.length() * times);
        for (int i = 0; i < times; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    static List<String> plaintexts() {
        return Arrays.asList(
                "hello",
                "Password123!",
                repeat("0123456789", 20),
                UTF8_SAMPLE,
                "x",
                "12345678",
                "0123456789abcdef",
                "line one\n\tline two\r\nline three",
                " leading and trailing spaces ",
                repeat("äöü 日本語 ", 500));
    }

    @Test
    void roundTripsEveryKindOfPlaintext() {
        StringEncryptor enc = create(PASSWORD);
        for (String plaintext : plaintexts()) {
            assertEquals(plaintext, enc.decrypt(enc.encrypt(plaintext)));
        }
    }

    @Test
    void aSecondInstanceWithTheSamePasswordReadsTheValue() {
        String encoded = create(PASSWORD).encrypt(UTF8_SAMPLE);
        assertEquals(UTF8_SAMPLE, create(PASSWORD).decrypt(encoded));
    }

    @Test
    void twoEncryptionsOfTheSameValueDiffer() {
        StringEncryptor enc = create(PASSWORD);
        assertNotEquals(enc.encrypt("hello"), enc.encrypt("hello"));
    }

    @Test
    void outputIsStandardBase64WithPadding() {
        StringEncryptor enc = create(PASSWORD);
        for (String plaintext : plaintexts()) {
            String encoded = enc.encrypt(plaintext);
            assertEquals(0, encoded.length() % 4, encoded);
            assertTrue(encoded.matches("[A-Za-z0-9+/]+={0,2}"), encoded);
            assertEquals(encoded, Base64.getEncoder().encodeToString(Base64.getDecoder().decode(encoded)));
        }
    }

    @Test
    void emptyOrNullPasswordIsRejected() {
        assertEquals("password cannot be empty", assertFails(ErrorCode.EMPTY_PASSWORD, () -> create("")).getMessage());
        assertEquals("password cannot be empty", assertFails(ErrorCode.EMPTY_PASSWORD, () -> create(null)).getMessage());
        assertFails(ErrorCode.EMPTY_PASSWORD, () -> createWithIterations("", 2000));
    }

    @Test
    void emptyOrNullValueIsRejected() {
        StringEncryptor enc = create(PASSWORD);
        assertEquals("value cannot be empty", assertFails(ErrorCode.EMPTY_VALUE, () -> enc.encrypt("")).getMessage());
        assertFails(ErrorCode.EMPTY_VALUE, () -> enc.encrypt(null));
        assertEquals("value cannot be empty", assertFails(ErrorCode.EMPTY_VALUE, () -> enc.decrypt("")).getMessage());
        assertFails(ErrorCode.EMPTY_VALUE, () -> enc.decrypt(null));
    }

    @Test
    void wrongPasswordNeverYieldsThePlaintext() {
        StringEncryptor writer = create(PASSWORD);
        StringEncryptor reader = create("another-password");
        for (int i = 0; i < 50; i++) {
            String plaintext = "secret-" + i;
            String encoded = writer.encrypt(plaintext);
            if (authenticated()) {
                assertEquals("decryption failed",
                        assertFails(ErrorCode.DECRYPTION_FAILED, () -> reader.decrypt(encoded)).getMessage());
            } else {
                // No integrity check: an error, or garbage. Never the plaintext, never another exception type.
                try {
                    assertNotEquals(plaintext, reader.decrypt(encoded));
                } catch (JavaCryptException e) {
                    assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
                }
            }
        }
    }

    @Test
    void mismatchedIterationsNeverYieldThePlaintext() {
        String encoded = createWithIterations(PASSWORD, 2000).encrypt("hello");
        StringEncryptor reader = createWithIterations(PASSWORD, 2001);
        try {
            assertNotEquals("hello", reader.decrypt(encoded));
        } catch (JavaCryptException e) {
            assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
        }
        assertEquals("hello", createWithIterations(PASSWORD, 2000).decrypt(encoded));
    }

    @Test
    void iterationsBelowOneAreRejected() {
        for (int iterations : new int[] {0, -1}) {
            JavaCryptException e = assertFails(ErrorCode.INVALID_PARAMETER,
                    () -> createWithIterations(PASSWORD, iterations));
            assertEquals("invalid parameter: iterations must be at least 1", e.getMessage());
        }
    }

    @Test
    void textThatIsNotBase64IsRejected() {
        StringEncryptor enc = create(PASSWORD);
        for (String bad : new String[] {"not base64!", "ENC(abc)", "YWJj*GVm", "äöü="}) {
            JavaCryptException e = assertFails(ErrorCode.INVALID_BASE64, () -> enc.decrypt(bad));
            assertTrue(e.getMessage().startsWith("failed to decode base64: "), e.getMessage());
        }
    }

    @Test
    void base64WithoutItsPaddingIsRejected() {
        // The family writes padded base64; Go and Rust reject the unpadded form, so Java must too.
        StringEncryptor enc = create(PASSWORD);
        String padded = null;
        for (int i = 1; i <= 16 && padded == null; i++) {
            String candidate = enc.encrypt(repeat("p", i));
            if (candidate.endsWith("=")) {
                padded = candidate;
            }
        }
        assertTrue(padded != null, "some plaintext length must give a padded payload");
        String unpadded = padded.replace("=", "");
        assertFails(ErrorCode.INVALID_BASE64, () -> enc.decrypt(unpadded));
        assertFails(ErrorCode.INVALID_BASE64, () -> enc.decrypt("YQ"));
    }

    @Test
    void lineBreaksInsideBase64AreIgnoredLikeGoCryptDoes() {
        StringEncryptor enc = create(PASSWORD);
        String encoded = enc.encrypt(repeat("0123456789", 20));
        String wrapped = encoded.substring(0, 20) + "\r\n" + encoded.substring(20, 40) + "\n" + encoded.substring(40)
                + "\n";
        assertEquals(repeat("0123456789", 20), enc.decrypt(wrapped));
    }

    @Test
    void plaintextThatIsNotUtf8IsReportedAsDecryptionFailed() throws Exception {
        StringEncryptor enc = create(PASSWORD);
        byte[][] invalid = {
            {(byte) 0xff, (byte) 0xfe, 'a'},      // bytes that never occur in UTF-8
            {'a', (byte) 0x80},                    // a continuation byte on its own
            {(byte) 0xe2, (byte) 0x82},            // a three-byte sequence cut short
            {(byte) 0xc0, (byte) 0xaf},            // an overlong encoding
            {(byte) 0xed, (byte) 0xa0, (byte) 0x80} // a surrogate half encoded directly
        };
        for (byte[] raw : invalid) {
            String encoded = sealRawBytes(PASSWORD, raw);
            assertEquals("decryption failed",
                    assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded)).getMessage(),
                    Fixtures.hex(raw));
        }
        // The same helper with valid UTF-8 must decrypt, or this test would prove nothing.
        assertEquals(UTF8_SAMPLE, enc.decrypt(sealRawBytes(PASSWORD, Fixtures.utf8(UTF8_SAMPLE))));
    }

    @Test
    void oneInstanceCanBeSharedBetweenThreads() throws Exception {
        final StringEncryptor enc = createWithIterations(PASSWORD, 50);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Integer>> results = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                final int thread = t;
                results.add(pool.submit(new Callable<Integer>() {
                    @Override
                    public Integer call() {
                        int ok = 0;
                        for (int i = 0; i < 200; i++) {
                            String plaintext = "thread-" + thread + "-value-" + i + "-" + UTF8_SAMPLE;
                            if (plaintext.equals(enc.decrypt(enc.encrypt(plaintext)))) {
                                ok++;
                            }
                        }
                        return ok;
                    }
                }));
            }
            for (Future<Integer> result : results) {
                assertEquals(200, result.get(120, TimeUnit.SECONDS).intValue());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void toStringDescribesTheEncryptorWithoutThePassword() {
        String secret = "s3cr3t-P4ssw0rd-do-not-print";
        String text = create(secret).toString();
        assertFalse(text.contains(secret), text);
        assertTrue(text.startsWith(create(secret).getClass().getSimpleName() + "{"), text);
        assertTrue(text.contains("iterations="), text);
    }
}
