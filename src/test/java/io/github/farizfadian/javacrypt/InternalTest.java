package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.spec.IvParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * How failures of the JDK's cipher provider are reported.
 *
 * <p>Two different things can go wrong, and callers must be able to tell them apart: the Java
 * runtime cannot do what is asked ({@link ErrorCode#UNSUPPORTED}, with the cause), or this
 * particular input cannot be decrypted ({@link ErrorCode#DECRYPTION_FAILED}, with no detail).
 */
class InternalTest {

    private static final String AES_CBC = "AES/CBC/PKCS5Padding";
    private static final byte[] KEY = new byte[32];
    private static final IvParameterSpec IV = new IvParameterSpec(new byte[16]);

    private static JavaCryptException assertFails(ErrorCode code, org.junit.jupiter.api.function.Executable action) {
        return EncryptorContract.assertFails(code, action);
    }

    @Test
    void encryptThenDecryptRoundTrips() {
        byte[] plaintext = Fixtures.utf8("hello");
        byte[] ciphertext = Internal.encrypt(AES_CBC, KEY, IV, plaintext);
        assertEquals(16, ciphertext.length);
        assertArrayEquals(plaintext, Internal.decrypt(AES_CBC, KEY, IV, ciphertext, 0, ciphertext.length));
    }

    @Test
    void anAlgorithmThisRuntimeDoesNotHaveIsUnsupported() {
        JavaCryptException onEncrypt = assertFails(ErrorCode.UNSUPPORTED,
                () -> Internal.encrypt("AES/NOPE/NoPadding", KEY, IV, new byte[16]));
        assertTrue(onEncrypt.getMessage().contains("AES/NOPE/NoPadding"), onEncrypt.getMessage());
        assertNotNull(onEncrypt.getCause(), "the cause tells the user what to fix");

        JavaCryptException onDecrypt = assertFails(ErrorCode.UNSUPPORTED,
                () -> Internal.decrypt("AES/NOPE/NoPadding", KEY, IV, new byte[16], 0, 16));
        assertTrue(onDecrypt.getMessage().contains("AES/NOPE/NoPadding"), onDecrypt.getMessage());
        assertNotNull(onDecrypt.getCause());
    }

    @Test
    void aKeyThisRuntimeRejectsIsUnsupportedOnBothSides() {
        // Stands in for AES-256 on a Java 8 without the unlimited strength policy ("Illegal key size"):
        // the runtime refuses the key before it looks at any data.
        byte[] rejected = new byte[5];
        JavaCryptException onEncrypt = assertFails(ErrorCode.UNSUPPORTED,
                () -> Internal.encrypt(AES_CBC, rejected, IV, new byte[16]));
        assertTrue(onEncrypt.getMessage().contains("40-bit key"), onEncrypt.getMessage());

        // Before this was separated, decrypt reported it as "decryption failed", which sends the
        // user looking for a wrong password instead of a missing JCE policy.
        JavaCryptException onDecrypt = assertFails(ErrorCode.UNSUPPORTED,
                () -> Internal.decrypt(AES_CBC, rejected, IV, new byte[16], 0, 16));
        assertTrue(onDecrypt.getMessage().contains("40-bit key"), onDecrypt.getMessage());
        assertNotNull(onDecrypt.getCause());
    }

    @Test
    void dataThatCannotBeDecryptedIsDecryptionFailedWithoutDetail() {
        // Random-looking blocks: the padding check fails.
        byte[] garbage = Fixtures.unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        JavaCryptException e = assertFails(ErrorCode.DECRYPTION_FAILED,
                () -> Internal.decrypt(AES_CBC, KEY, IV, garbage, 0, garbage.length));
        assertEquals("decryption failed", e.getMessage());
        assertNull(e.getCause(), "no cause: the reason must not be observable");

        // Not a whole number of blocks.
        assertFails(ErrorCode.DECRYPTION_FAILED, () -> Internal.decrypt(AES_CBC, KEY, IV, garbage, 0, 17));
    }
}
