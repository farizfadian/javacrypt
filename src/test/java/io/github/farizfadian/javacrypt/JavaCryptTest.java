package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The {@code ENC(...)} wrapper constants and {@link JavaCrypt#isEncrypted(String)}. */
class JavaCryptTest {

    @Test
    void wrapperConstantsAreTheFamilyOnes() {
        assertEquals("ENC(", JavaCrypt.ENC_PREFIX);
        assertEquals(")", JavaCrypt.ENC_SUFFIX);
    }

    @Test
    void isEncryptedChecksOnlyTheWrapper() {
        for (String yes : new String[] {"ENC(abc)", "  ENC(abc)  ", "ENC()", "\tENC(a b)\n", "ENC(not base64!)"}) {
            assertTrue(JavaCrypt.isEncrypted(yes), yes);
        }
        for (String no : new String[] {"enc(abc)", "ENC(abc", "abc", "", "ENC(", "ENC", ")", "xENC(abc)", "ENC(abc)x"}) {
            assertFalse(JavaCrypt.isEncrypted(no), no);
        }
        assertFalse(JavaCrypt.isEncrypted(null));
    }

    @Test
    void whitespaceIsTrimmedLikeGoAndRustDo() {
        // Unicode white space is trimmed, including the no-break space that String.trim() keeps.
        assertTrue(JavaCrypt.isEncrypted(" ENC(abc) "));
        assertTrue(JavaCrypt.isEncrypted("　ENC(abc) "));
        assertTrue(JavaCrypt.isEncrypted("\u0085\u000b\fENC(abc)\r\n"));
        // Control characters are not white space, although String.trim() would drop them.
        assertFalse(JavaCrypt.isEncrypted("\u0000ENC(abc)"));
        assertFalse(JavaCrypt.isEncrypted("ENC(abc)\u0001"));
        // A zero-width space is not white space either.
        assertFalse(JavaCrypt.isEncrypted("​ENC(abc)"));
    }

    @Test
    void versionIsTheProjectVersion() {
        String version = JavaCrypt.version();
        assertFalse(version.contains("$"), "the resource was not filtered: " + version);
        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+(-[A-Za-z0-9.]+)?"), version);
        String expected = System.getProperty("javacrypt.expectedVersion");
        assertTrue(expected != null && !expected.isEmpty(), "the build must pass javacrypt.expectedVersion");
        assertEquals(expected, version);
    }
}
