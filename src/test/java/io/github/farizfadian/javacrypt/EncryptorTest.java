package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/** {@link Encryptor}: AES-GCM, the family's default mode. */
class EncryptorTest extends EncryptorContract {

    @Override
    StringEncryptor create(String password) {
        return new Encryptor(password);
    }

    @Override
    StringEncryptor createWithIterations(String password, int iterations) {
        return Encryptor.builder(password).iterations(iterations).build();
    }

    @Override
    boolean authenticated() {
        return true;
    }

    @Override
    String sealRawBytes(String password, byte[] plaintext) throws Exception {
        byte[] salt = new byte[16];
        byte[] nonce = new byte[12];
        byte[] key = Kdf.pbkdf2Sha256(Fixtures.utf8(password), salt, 10000, 32);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        return Base64.getEncoder().encodeToString(Internal.concat(salt, nonce, cipher.doFinal(plaintext)));
    }

    @Test
    void defaultsAreTheFamilyDefaults() {
        Encryptor enc = new Encryptor(PASSWORD);
        assertEquals(10000, enc.getIterations());
        assertEquals(16, enc.getSaltSize());
        assertEquals(32, enc.getKeySize());
        assertEquals(10000, Encryptor.DEFAULT_ITERATIONS);
        assertEquals(16, Encryptor.DEFAULT_SALT_SIZE);
        assertEquals(32, Encryptor.DEFAULT_KEY_SIZE);
    }

    @Test
    void builderSetsEveryParameter() {
        Encryptor enc = Encryptor.builder(PASSWORD).iterations(50000).saltSize(32).keySize(24).build();
        assertEquals(50000, enc.getIterations());
        assertEquals(32, enc.getSaltSize());
        assertEquals(24, enc.getKeySize());
        assertEquals(UTF8_SAMPLE, enc.decrypt(enc.encrypt(UTF8_SAMPLE)));
    }

    @Test
    void payloadIsSaltNonceCiphertextAndTag() {
        byte[] plaintext = Fixtures.utf8(UTF8_SAMPLE);
        byte[] decoded = Base64.getDecoder().decode(new Encryptor(PASSWORD).encrypt(UTF8_SAMPLE));
        assertEquals(16 + 12 + plaintext.length + 16, decoded.length);

        Encryptor wide = Encryptor.builder(PASSWORD).iterations(100).saltSize(32).build();
        assertEquals(32 + 12 + 5 + 16, Base64.getDecoder().decode(wide.encrypt("hello")).length);
    }

    @Test
    void everyKeySizeRoundTripsAndIsNotInterchangeable() {
        for (int keySize : new int[] {16, 24, 32}) {
            Encryptor enc = Encryptor.builder(PASSWORD).iterations(100).keySize(keySize).build();
            String encoded = enc.encrypt("hello");
            assertEquals("hello", enc.decrypt(encoded), "keySize=" + keySize);
            for (int other : new int[] {16, 24, 32}) {
                if (other != keySize) {
                    Encryptor reader = Encryptor.builder(PASSWORD).iterations(100).keySize(other).build();
                    assertFails(ErrorCode.DECRYPTION_FAILED, () -> reader.decrypt(encoded));
                }
            }
        }
    }

    @Test
    void otherKeySizesAreRejected() {
        for (int keySize : new int[] {0, 8, 15, 33, 64, -32}) {
            JavaCryptException e = assertFails(ErrorCode.INVALID_PARAMETER,
                    () -> Encryptor.builder(PASSWORD).keySize(keySize).build());
            assertEquals("invalid parameter: key size must be 16, 24 or 32", e.getMessage());
        }
    }

    @Test
    void negativeSaltSizeIsRejected() {
        JavaCryptException e = assertFails(ErrorCode.INVALID_PARAMETER,
                () -> Encryptor.builder(PASSWORD).saltSize(-1).build());
        assertEquals("invalid parameter: salt size must not be negative", e.getMessage());
    }

    @Test
    void mismatchedSaltSizeFails() {
        String encoded = Encryptor.builder(PASSWORD).iterations(100).saltSize(32).build().encrypt("hello");
        Encryptor reader = Encryptor.builder(PASSWORD).iterations(100).saltSize(16).build();
        assertFails(ErrorCode.DECRYPTION_FAILED, () -> reader.decrypt(encoded));
    }

    @Test
    void everySingleBitFlipIsDetected() {
        Encryptor enc = Encryptor.builder(PASSWORD).iterations(10).build();
        byte[] original = Base64.getDecoder().decode(enc.encrypt("hello"));
        for (int i = 0; i < original.length; i++) {
            byte[] tampered = original.clone();
            tampered[i] ^= 0x01;
            String encoded = Base64.getEncoder().encodeToString(tampered);
            assertEquals("decryption failed",
                    assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded)).getMessage(),
                    "byte " + i);
        }
    }

    @Test
    void everyTruncationIsDecryptionFailed() {
        Encryptor enc = Encryptor.builder(PASSWORD).iterations(10).build();
        byte[] original = Base64.getDecoder().decode(enc.encrypt("hello"));
        // 1 byte up to one byte short: below salt + nonce, exactly salt + nonce, and inside the tag.
        for (int length = 1; length < original.length; length++) {
            String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(original, length));
            assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded));
        }
    }

    @Test
    void appendedBytesAreDetected() {
        Encryptor enc = Encryptor.builder(PASSWORD).iterations(10).build();
        byte[] original = Base64.getDecoder().decode(enc.encrypt("hello"));
        String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(original, original.length + 1));
        assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded));
    }
}
