package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/** {@link JasyptEncryptor}: PBEWithMD5AndDES, the mode Java Jasypt reads. */
class JasyptEncryptorTest extends EncryptorContract {

    @Override
    StringEncryptor create(String password) {
        return new JasyptEncryptor(password);
    }

    @Override
    StringEncryptor createWithIterations(String password, int iterations) {
        return JasyptEncryptor.builder(password).iterations(iterations).build();
    }

    @Override
    boolean authenticated() {
        return false;
    }

    @Override
    String sealRawBytes(String password, byte[] plaintext) throws Exception {
        byte[] salt = new byte[8];
        byte[] derived = Kdf.pbkdf1Md5(Fixtures.utf8(password), salt, 1000);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, 0, 8, "DES"), new IvParameterSpec(derived, 8, 8));
        return Base64.getEncoder().encodeToString(Internal.concat(salt, cipher.doFinal(plaintext)));
    }

    @Test
    void defaultsAreJasyptDefaults() {
        JasyptEncryptor enc = new JasyptEncryptor(PASSWORD);
        assertEquals(1000, enc.getIterations());
        assertEquals(1000, JasyptEncryptor.DEFAULT_ITERATIONS);
        assertEquals(8, JasyptEncryptor.SALT_SIZE);
        assertEquals(2000, JasyptEncryptor.builder(PASSWORD).iterations(2000).build().getIterations());
    }

    @Test
    void payloadIsAnEightByteSaltAndPaddedDesBlocks() {
        JasyptEncryptor enc = new JasyptEncryptor(PASSWORD);
        // PKCS#5 always pads: 5 bytes -> 8, 8 bytes -> 16, 9 bytes -> 16.
        assertEquals(8 + 8, Base64.getDecoder().decode(enc.encrypt("hello")).length);
        assertEquals(8 + 16, Base64.getDecoder().decode(enc.encrypt("12345678")).length);
        assertEquals(8 + 16, Base64.getDecoder().decode(enc.encrypt("123456789")).length);
    }

    @Test
    void shortOrMisalignedPayloadIsInvalidJasyptData() {
        JasyptEncryptor enc = new JasyptEncryptor(PASSWORD);
        byte[] valid = Base64.getDecoder().decode(enc.encrypt("12345678"));
        // 1..15: no room for a salt and one block. 17..23: the ciphertext is not whole blocks.
        for (int length : new int[] {1, 7, 8, 9, 15, 17, 20, 23}) {
            String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(valid, length));
            JavaCryptException e = assertFails(ErrorCode.INVALID_JASYPT_DATA, () -> enc.decrypt(encoded));
            assertEquals("invalid jasypt encrypted data", e.getMessage(), "length " + length);
        }
    }

    @Test
    void droppingTheLastBlockIsAnErrorNotAPlaintext() {
        JasyptEncryptor enc = new JasyptEncryptor(PASSWORD);
        byte[] valid = Base64.getDecoder().decode(enc.encrypt("12345678"));
        // Still block-aligned (salt + one block), but the padding block is gone.
        String encoded = Base64.getEncoder().encodeToString(Arrays.copyOf(valid, 16));
        assertEquals("decryption failed",
                assertFails(ErrorCode.DECRYPTION_FAILED, () -> enc.decrypt(encoded)).getMessage());
    }
}
