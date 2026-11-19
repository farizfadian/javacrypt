package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The {@code ENC(...)} helpers that {@link StringEncryptor} provides as default methods, tested with
 * a toy encryptor so that only the helper logic is under test.
 */
class StringEncryptorTest {

    /** "Encrypts" by reversing. Refuses to decrypt {@code bad}. Records what it was asked to decrypt. */
    private static final class Reverse implements StringEncryptor {
        final List<String> seen = new ArrayList<>();

        @Override
        public String encrypt(String plaintext) {
            if (plaintext == null || plaintext.isEmpty()) {
                throw JavaCryptException.emptyValue();
            }
            return new StringBuilder(plaintext).reverse().toString();
        }

        @Override
        public String decrypt(String encoded) {
            seen.add(encoded);
            if (encoded.isEmpty()) {
                throw JavaCryptException.emptyValue();
            }
            if (encoded.equals("bad")) {
                throw JavaCryptException.decryptionFailed();
            }
            if (encoded.equals("worse")) {
                throw JavaCryptException.invalidJasyptData();
            }
            return new StringBuilder(encoded).reverse().toString();
        }
    }

    private static JavaCryptException assertFails(ErrorCode code, org.junit.jupiter.api.function.Executable action) {
        return EncryptorContract.assertFails(code, action);
    }

    @Test
    void encryptWithPrefixWrapsThePayload() {
        assertEquals("ENC(cba)", new Reverse().encryptWithPrefix("abc"));
        assertFails(ErrorCode.EMPTY_VALUE, () -> new Reverse().encryptWithPrefix(""));
    }

    @Test
    void decryptPrefixedTrimsAndUnwraps() {
        Reverse enc = new Reverse();
        assertEquals("abc", enc.decryptPrefixed("ENC(cba)"));
        assertEquals("abc", enc.decryptPrefixed("  ENC(cba)\n"));
        assertEquals("abc", enc.decryptPrefixed("\u00a0ENC(cba)\u00a0"));
        assertEquals(Arrays.asList("cba", "cba", "cba"), enc.seen);
    }

    @Test
    void decryptPrefixedRejectsAValueWithoutTheWrapper() {
        Reverse enc = new Reverse();
        for (String bad : new String[] {"cba", "ENC(cba", "cba)", "enc(cba)", "", "x ENC(cba)", null}) {
            JavaCryptException e = assertFails(ErrorCode.INVALID_ENC_FORMAT, () -> enc.decryptPrefixed(bad));
            assertEquals("invalid encrypted format, expected ENC(...)", e.getMessage());
        }
        assertEquals(Collections.emptyList(), enc.seen, "nothing may reach decrypt()");
    }

    @Test
    void anEmptyWrapperIsAnEmptyValue() {
        assertFails(ErrorCode.EMPTY_VALUE, () -> new Reverse().decryptPrefixed("ENC()"));
    }

    @Test
    void decryptAllInStringReplacesZeroOneAndManyMatches() {
        Reverse enc = new Reverse();
        assertEquals("nothing here", enc.decryptAllInString("nothing here"));
        assertEquals("", enc.decryptAllInString(""));
        assertEquals("k=abc", enc.decryptAllInString("k=ENC(cba)"));
        assertEquals("a=x b=yz\nc=123 d", enc.decryptAllInString("a=ENC(x) b=ENC(zy)\nc=ENC(321) d"));
    }

    @Test
    void aFailingMatchIsKeptAndTheLastErrorIsThrownAfterEverythingWasProcessed() {
        Reverse enc = new Reverse();
        // Two different failures: the later one ("worse") is the one reported, as in GoCrypt.
        JavaCryptException e = assertFails(ErrorCode.INVALID_JASYPT_DATA,
                () -> enc.decryptAllInString("a=ENC(x) b=ENC(bad) c=ENC(worse) d=ENC(y)"));
        assertEquals("invalid jasypt encrypted data", e.getMessage());
        assertEquals(Arrays.asList("x", "bad", "worse", "y"), enc.seen, "matches after a failure are still processed");
    }

    @Test
    void theLossyVariantNeverThrowsAndKeepsFailedMatches() {
        Reverse enc = new Reverse();
        assertEquals("a=x b=ENC(bad) c=y", enc.decryptAllInStringLossy("a=ENC(x) b=ENC(bad) c=ENC(y)"));
        assertEquals("nothing here", enc.decryptAllInStringLossy("nothing here"));
        assertEquals("ENC(bad)", enc.decryptAllInStringLossy("ENC(bad)"));
    }

    @Test
    void theScanPatternIsTheFamilyOne() {
        // ENC\(([^)]+)\): "ENC()" is not a match, and a match ends at the first ")".
        Reverse enc = new Reverse();
        assertEquals("ENC() x(CNE) b(a", enc.decryptAllInStringLossy("ENC() ENC(ENC(x)) ENC(a(b)"));
        assertEquals(Arrays.asList("ENC(x", "a(b"), enc.seen);
    }

    @Test
    void decryptedTextIsInsertedLiterally() {
        // "$" and "\" are special in java.util.regex replacement strings. They must come back as they are.
        Reverse enc = new Reverse();
        for (String plaintext : new String[] {"pa$$w\\1rd$0", "$1", "\\", "a\\$b", "${name}", "C:\\dir\\file"}) {
            String text = "k=" + enc.encryptWithPrefix(plaintext) + ";";
            assertEquals("k=" + plaintext + ";", enc.decryptAllInString(text), plaintext);
            assertEquals("k=" + plaintext + ";", enc.decryptAllInStringLossy(text), plaintext);
        }
    }

    @Test
    void decryptAllInStringRejectsNullInput() {
        assertThrows(NullPointerException.class, () -> new Reverse().decryptAllInString(null));
        assertThrows(NullPointerException.class, () -> new Reverse().decryptAllInStringLossy(null));
        assertThrows(NullPointerException.class, () -> new Reverse().decryptMap(null));
    }

    @Test
    void decryptMapDecryptsWrappedValuesAndCopiesTheRest() {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("host", "localhost");
        config.put("secret", "ENC(cba)");
        config.put("spaced", "  ENC(zyx)  ");
        config.put("empty", "");
        config.put("missing", null);
        config.put("not-quite", "ENC(abc");

        Map<String, String> out = new Reverse().decryptMap(config);

        assertEquals(new ArrayList<>(config.keySet()), new ArrayList<>(out.keySet()), "input order is kept");
        assertEquals("localhost", out.get("host"));
        assertEquals("abc", out.get("secret"));
        assertEquals("xyz", out.get("spaced"));
        assertEquals("", out.get("empty"));
        assertNull(out.get("missing"));
        assertEquals("ENC(abc", out.get("not-quite"));
        assertEquals("ENC(cba)", config.get("secret"), "the input map is not modified");
    }

    @Test
    void decryptMapNamesTheKeyThatFailed() {
        Map<String, String> config = new LinkedHashMap<>();
        config.put("ok", "ENC(cba)");
        config.put("api_key", "ENC(bad)");
        config.put("later", "ENC(worse)");

        Reverse enc = new Reverse();
        JavaCryptException e = assertFails(ErrorCode.KEY_DECRYPT, () -> enc.decryptMap(config));

        assertEquals("failed to decrypt key api_key: decryption failed", e.getMessage());
        assertEquals("api_key", e.getKey());
        JavaCryptException cause = (JavaCryptException) e.getCause();
        assertEquals(ErrorCode.DECRYPTION_FAILED, cause.getCode());
        assertNull(cause.getKey());
        assertFalse(enc.seen.contains("worse"), "the first failure aborts");
    }

    @Test
    void theRealEncryptorsInheritTheHelpers() {
        for (StringEncryptor enc : new StringEncryptor[] {
            new Encryptor("pw"), new JasyptEncryptor("pw"), new JasyptStrongEncryptor("pw")}) {
            String wrapped = enc.encryptWithPrefix("hello");
            assertEquals("ENC(", wrapped.substring(0, 4));
            assertEquals(")", wrapped.substring(wrapped.length() - 1));
            assertEquals("hello", enc.decryptPrefixed(" " + wrapped + "\n"));
            assertEquals("a=hello b=hello", enc.decryptAllInString("a=" + wrapped + " b=" + wrapped));
            assertSame(ErrorCode.INVALID_ENC_FORMAT,
                    assertThrows(JavaCryptException.class, () -> enc.decryptPrefixed("hello")).getCode());
            assertSame(ErrorCode.EMPTY_VALUE,
                    assertThrows(JavaCryptException.class, () -> enc.decryptPrefixed("ENC()")).getCode());
        }
    }
}
