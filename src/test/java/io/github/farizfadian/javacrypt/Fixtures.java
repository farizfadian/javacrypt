package io.github.farizfadian.javacrypt;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Loads the golden vector files produced by GoCrypt (see {@code scripts/gen-vectors}).
 *
 * <p>The JSON keys are snake_case; Gson maps them onto the camelCase fields below.
 */
final class Fixtures {

    /** The fixture copied verbatim from RustCrypt: GoCrypt v1.0.0, ASCII password. */
    static final String ASCII = "gocrypt_vectors.json";

    private static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create();

    private Fixtures() {
    }

    static final class Fixture {
        String generator;
        String gocryptModule;
        String gocryptCommit;
        String generatedAt;
        String password;
        List<Vector> vectors;
        Fixed fixed;
    }

    /** A value produced by GoCrypt's public API with a random salt. */
    static final class Vector {
        String mode;
        String plaintext;
        String encrypted;
    }

    /** Values produced by GoCrypt's own derivation and cipher code with an injected salt. */
    static final class Fixed {
        List<Pbkdf2Vector> pbkdf2Sha256;
        List<Pbkdf1Vector> pbkdf1Md5;
        List<GcmVector> aesGcm;
        List<CbcVector> jasyptDes;
        List<CbcVector> jasyptStrong;
    }

    static final class Pbkdf2Vector {
        String saltHex;
        int iterations;
        int len;
        String outHex;
    }

    static final class Pbkdf1Vector {
        String saltHex;
        int iterations;
        String outHex;
    }

    static final class GcmVector {
        String saltHex;
        String nonceHex;
        int iterations;
        int keySize;
        String plaintext;
        String encoded;
    }

    static final class CbcVector {
        String saltHex;
        int iterations;
        String plaintext;
        String encoded;
    }

    static Fixture load(String resource) {
        try (InputStream in = Fixtures.class.getResourceAsStream("/" + resource)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found on the test classpath: " + resource);
            }
            try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                return GSON.fromJson(reader, Fixture.class);
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot read fixture " + resource, e);
        }
    }

    static byte[] unhex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length: " + hex);
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Strips the {@code ENC(} and {@code )} wrapper of a fixture value. */
    static String payload(String wrapped) {
        if (!wrapped.startsWith("ENC(") || !wrapped.endsWith(")")) {
            throw new IllegalArgumentException("not wrapped: " + wrapped);
        }
        return wrapped.substring(4, wrapped.length() - 1);
    }
}
