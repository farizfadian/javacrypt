package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;

/** Key derivation against published vectors and against the JDK's own implementations. */
class KdfTest {

    /** Outside every single-byte code page: two Latin-1 letters and a supplementary-plane emoji. */
    private static final String NON_ASCII_PASSWORD = "pässwörd-🔐";

    private static String pbkdf2Hex(String password, String salt, int iterations, int length) {
        return Fixtures.hex(Kdf.pbkdf2Sha256(Fixtures.utf8(password), Fixtures.utf8(salt), iterations, length));
    }

    @Test
    void pbkdf2MatchesPublishedHmacSha256Vectors() {
        assertEquals("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
                pbkdf2Hex("password", "salt", 1, 32));
        assertEquals("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
                pbkdf2Hex("password", "salt", 2, 32));
        assertEquals("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
                pbkdf2Hex("password", "salt", 4096, 32));
    }

    @Test
    void pbkdf2SpansSeveralHashBlocksAndTruncatesTheLast() {
        // 40 bytes need two SHA-256 blocks, the second one cut to 8 bytes.
        assertEquals("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
                pbkdf2Hex("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40));
    }

    @Test
    void pbkdf2AgreesWithTheJdkForAsciiAndNonAsciiPasswords() throws Exception {
        byte[] salt = Fixtures.unhex("000102030405060708090a0b0c0d0e0f");
        for (String password : new String[] {"rustcrypt-test-2026", NON_ASCII_PASSWORD}) {
            for (int length : new int[] {16, 32, 48}) {
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, length * 8);
                byte[] jdk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
                assertArrayEquals(jdk, Kdf.pbkdf2Sha256(Fixtures.utf8(password), salt, 1000, length),
                        "password=" + password + " length=" + length);
            }
        }
    }

    @Test
    void pbkdf1IsIteratedMd5OverPasswordThenSalt() throws Exception {
        byte[] password = Fixtures.utf8(NON_ASCII_PASSWORD);
        byte[] salt = Fixtures.unhex("0102030405060708");

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(password);
        md5.update(salt);
        byte[] once = md5.digest();
        assertArrayEquals(once, Kdf.pbkdf1Md5(password, salt, 1));

        byte[] thrice = md5.digest(md5.digest(once));
        assertArrayEquals(thrice, Kdf.pbkdf1Md5(password, salt, 3));
        assertEquals(16, Kdf.pbkdf1Md5(password, salt, 1000).length);
    }
}
