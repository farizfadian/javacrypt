package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/** {@link JasyptStrongEncryptor}: the family's AES-256-CBC layout. */
class JasyptStrongEncryptorTest extends EncryptorContract {

    @Override
    StringEncryptor create(String password) {
        return new JasyptStrongEncryptor(password);
    }

    @Override
    StringEncryptor createWithIterations(String password, int iterations) {
        return JasyptStrongEncryptor.builder(password).iterations(iterations).build();
    }

    @Override
    boolean authenticated() {
        return false;
    }

    @Override
    String sealRawBytes(String password, byte[] plaintext) throws Exception {
        byte[] salt = new byte[16];
        byte[] derived = Kdf.pbkdf2Sha256(Fixtures.utf8(password), salt, 1000, 48);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, 0, 32, "AES"), new IvParameterSpec(derived, 32, 16));
        return Base64.getEncoder().encodeToString(Internal.concat(salt, cipher.doFinal(plaintext)));
    }

    @Test
    void defaultsAreTheFamilyDefaults() {
        JasyptStrongEncryptor enc = new JasyptStrongEncryptor(PASSWORD);
        assertEquals(1000, enc.getIterations());
        assertEquals(16, enc.getSaltSize());
        assertEquals(1000, JasyptStrongEncryptor.DEFAULT_ITERATIONS);
        assertEquals(16, JasyptStrongEncryptor.DEFAULT_SALT_SIZE);
    }

    @Test
    void builderSetsEveryParameter() {
        JasyptStrongEncryptor enc = JasyptStrongEncryptor.builder(PASSWORD).iterations(5000).saltSize(32).build();
        assertEquals(5000, enc.getIterations());
        assertEquals(32, enc.getSaltSize());
        assertEquals(UTF8_SAMPLE, enc.decrypt(enc.encrypt(UTF8_SAMPLE)));
    }

    @Test
    void payloadIsTheSaltAndPaddedAesBlocks() {
        JasyptStrongEncryptor enc = new JasyptStrongEncryptor(PASSWORD);
        // PKCS#7 always pads: 5 bytes -> 16, 16 bytes -> 32.
        assertEquals(16 + 16, Base64.getDecoder().decode(enc.encrypt("hello")).length);
        assertEquals(16 + 32, Base64.getDecoder().decode(enc.encrypt("0123456789abcdef")).length);

        JasyptStrongEncryptor wide = JasyptStrongEncryptor.builder(PASSWORD).saltSize(32).build();
        assertEquals(32 + 16, Base64.getDecoder().decode(wide.encrypt("hello")).length);
    }

    @Test
    void shortOrMisalignedPayloadIsInvalidJasyptData() {
        JasyptStrongEncryptor enc = new JasyptStrongEncryptor(PASSWORD);
        byte[] valid = Base64.getDecoder().decode(enc.encrypt("0123456789abcdef"));
        // 1..31: no room for a salt and one block. 33..47: the ciphertext is not whole blocks.
        for (int length : new int[] {1, 15, 16, 17, 31, 33, 40, 47}) {
            String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(valid, length));
            JavaCryptException e = assertFails(ErrorCode.INVALID_JASYPT_DATA, () -> enc.decrypt(encoded));
            assertEquals("invalid jasypt encrypted data", e.getMessage(), "length " + length);
        }
    }

    @Test
    void droppingTheLastBlockIsAnErrorNotAPlaintext() {
        JasyptStrongEncryptor enc = new JasyptStrongEncryptor(PASSWORD);
        byte[] valid = Base64.getDecoder().decode(enc.encrypt("0123456789abcdef"));
        String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(valid, 32));
        assertEquals("decryption failed",
                assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded)).getMessage());
    }

    @Test
    void negativeSaltSizeIsRejected() {
        JavaCryptException e = assertFails(ErrorCode.INVALID_PARAMETER,
                () -> JasyptStrongEncryptor.builder(PASSWORD).saltSize(-1).build());
        assertEquals("invalid parameter: salt size must not be negative", e.getMessage());
    }

    @Test
    void mismatchedSaltSizeNeverYieldsThePlaintext() {
        String encoded = JasyptStrongEncryptor.builder(PASSWORD).saltSize(32).build().encrypt("hello");
        JasyptStrongEncryptor reader = new JasyptStrongEncryptor(PASSWORD);
        try {
            assertNotEquals("hello", reader.decrypt(encoded));
        } catch (JavaCryptException e) {
            assertEquals(ErrorCode.DECRYPTION_FAILED, e.getCode());
        }
    }
}
