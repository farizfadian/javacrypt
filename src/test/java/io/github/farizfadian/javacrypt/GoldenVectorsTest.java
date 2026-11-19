package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.farizfadian.javacrypt.Fixtures.CbcVector;
import io.github.farizfadian.javacrypt.Fixtures.Fixture;
import io.github.farizfadian.javacrypt.Fixtures.GcmVector;
import io.github.farizfadian.javacrypt.Fixtures.Pbkdf1Vector;
import io.github.farizfadian.javacrypt.Fixtures.Pbkdf2Vector;
import io.github.farizfadian.javacrypt.Fixtures.Vector;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Pins JavaCrypt to GoCrypt, the family's reference implementation.
 *
 * <p>Round trips inside one library prove nothing about the wire format, so every mode is compared
 * with values that GoCrypt produced: the {@code fixed} groups byte for byte through the
 * salt-injecting cores, the {@code vectors} group by decrypting what GoCrypt's public API wrote.
 */
class GoldenVectorsTest {

    static Stream<String> fixtures() {
        return Stream.of(Fixtures.ASCII, Fixtures.UNICODE);
    }

    @Test
    void eachFixtureHasThePasswordItWasGeneratedFor() {
        assertEquals("rustcrypt-test-2026", Fixtures.load(Fixtures.ASCII).password);
        // Guards against regenerating the second file with an ASCII password, which would
        // silently remove the only vectors that exercise UTF-8 password bytes.
        Fixture unicode = Fixtures.load(Fixtures.UNICODE);
        assertEquals(Fixtures.UNICODE_PASSWORD, unicode.password);
        assertEquals(15, Fixtures.utf8(unicode.password).length, "2 two-byte letters and 1 four-byte emoji");
        boolean nonAsciiPlaintext = false;
        for (Vector v : unicode.vectors) {
            nonAsciiPlaintext |= !v.plaintext.matches("\\p{ASCII}*");
        }
        assertTrue(nonAsciiPlaintext);
    }

    private static StringEncryptor encryptorFor(String mode, String password) {
        switch (mode) {
            case "default":
                return new Encryptor(password);
            case "jasypt":
                return new JasyptEncryptor(password);
            case "jasypt-strong":
                return new JasyptStrongEncryptor(password);
            default:
                throw new IllegalArgumentException("unknown mode " + mode);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void fixtureNamesItsSourceAndCoversEveryMode(String resource) {
        Fixture f = Fixtures.load(resource);
        assertEquals(40, f.gocryptCommit.length(), "full gocrypt commit hash");
        assertEquals("github.com/farizfadian/gocrypt v1.0.0", f.gocryptModule);
        assertFalse(f.password.isEmpty());
        Set<String> modes = new HashSet<>();
        for (Vector v : f.vectors) {
            modes.add(v.mode);
        }
        assertEquals(new HashSet<>(java.util.Arrays.asList("default", "jasypt", "jasypt-strong")), modes);
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void pbkdf2Sha256MatchesGoCrypt(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.fixed.pbkdf2Sha256.isEmpty());
        for (Pbkdf2Vector v : f.fixed.pbkdf2Sha256) {
            byte[] out = Kdf.pbkdf2Sha256(Fixtures.utf8(f.password), Fixtures.unhex(v.saltHex), v.iterations, v.len);
            assertEquals(v.outHex, Fixtures.hex(out),
                    "salt=" + v.saltHex + " iterations=" + v.iterations + " len=" + v.len);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void pbkdf1Md5MatchesGoCrypt(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.fixed.pbkdf1Md5.isEmpty());
        for (Pbkdf1Vector v : f.fixed.pbkdf1Md5) {
            byte[] out = Kdf.pbkdf1Md5(Fixtures.utf8(f.password), Fixtures.unhex(v.saltHex), v.iterations);
            assertEquals(v.outHex, Fixtures.hex(out), "salt=" + v.saltHex + " iterations=" + v.iterations);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void aesGcmFixedSaltIsByteIdenticalToGoCrypt(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.fixed.aesGcm.isEmpty());
        for (GcmVector v : f.fixed.aesGcm) {
            byte[] salt = Fixtures.unhex(v.saltHex);
            Encryptor enc = Encryptor.builder(f.password)
                    .iterations(v.iterations)
                    .saltSize(salt.length)
                    .keySize(v.keySize)
                    .build();
            String label = "aes_gcm plaintext=" + v.plaintext + " keySize=" + v.keySize;
            assertEquals(v.encoded, enc.encryptWithSaltAndNonce(salt, Fixtures.unhex(v.nonceHex), v.plaintext), label);
            assertEquals(v.plaintext, enc.decrypt(v.encoded), label);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void jasyptDesFixedSaltIsByteIdenticalToGoCrypt(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.fixed.jasyptDes.isEmpty());
        for (CbcVector v : f.fixed.jasyptDes) {
            JasyptEncryptor enc = JasyptEncryptor.builder(f.password).iterations(v.iterations).build();
            String label = "jasypt_des plaintext=" + v.plaintext + " iterations=" + v.iterations;
            assertEquals(v.encoded, enc.encryptWithSalt(Fixtures.unhex(v.saltHex), v.plaintext), label);
            assertEquals(v.plaintext, enc.decrypt(v.encoded), label);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void jasyptStrongFixedSaltIsByteIdenticalToGoCrypt(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.fixed.jasyptStrong.isEmpty());
        for (CbcVector v : f.fixed.jasyptStrong) {
            byte[] salt = Fixtures.unhex(v.saltHex);
            JasyptStrongEncryptor enc = JasyptStrongEncryptor.builder(f.password)
                    .iterations(v.iterations)
                    .saltSize(salt.length)
                    .build();
            String label = "jasypt_strong plaintext=" + v.plaintext + " iterations=" + v.iterations;
            assertEquals(v.encoded, enc.encryptWithSalt(salt, v.plaintext), label);
            assertEquals(v.plaintext, enc.decrypt(v.encoded), label);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void decryptsEveryValueGoCryptWrote(String resource) {
        Fixture f = Fixtures.load(resource);
        assertFalse(f.vectors.isEmpty());
        for (Vector v : f.vectors) {
            StringEncryptor enc = encryptorFor(v.mode, f.password);
            assertEquals(v.plaintext, enc.decrypt(Fixtures.payload(v.encrypted)), "mode=" + v.mode);
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    void theThreeModesAreGenuinelyDifferentFormats(String resource) {
        Fixture f = Fixtures.load(resource);
        Encryptor gcm = new Encryptor(f.password);
        JasyptEncryptor des = new JasyptEncryptor(f.password);
        int checked = 0;
        for (Vector v : f.vectors) {
            String payload = Fixtures.payload(v.encrypted);
            if (v.mode.equals("default")) {
                // DES-CBC has no integrity check: it may fail or return garbage, never the plaintext.
                String got;
                try {
                    got = des.decrypt(payload);
                } catch (JavaCryptException expected) {
                    got = null;
                }
                assertNotEquals(v.plaintext, got, "a default-mode value must not decrypt as jasypt");
            } else {
                assertThrows(JavaCryptException.class, () -> gcm.decrypt(payload),
                        "a " + v.mode + " value must not decrypt as AES-GCM");
            }
            checked++;
        }
        assertTrue(checked > 0);
    }
}
