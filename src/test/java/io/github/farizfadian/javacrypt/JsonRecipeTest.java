package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The README's recipe for JSON, kept honest by running it.
 *
 * <p>JavaCrypt has no JSON loader, because that would need a dependency. The recipe is: parse the
 * document with the JSON library the application already has, then decrypt the string values of
 * the parsed tree. Gson stands in for "the library you already have"; the recipe itself only uses
 * {@code Map}, {@code List} and {@code String}.
 */
class JsonRecipeTest {

    private static final String PASSWORD = "javacrypt-test-2026";

    // ── the recipe, as printed in the README ──────────────────────────────────

    /** Returns a copy of a parsed JSON tree (maps, lists, scalars) with every ENC(...) string decrypted. */
    static Object decryptStrings(StringEncryptor encryptor, Object node) {
        if (node instanceof String) {
            String text = (String) node;
            return JavaCrypt.isEncrypted(text) ? encryptor.decryptPrefixed(text) : text;
        }
        if (node instanceof Map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) node).entrySet()) {
                copy.put(String.valueOf(entry.getKey()), decryptStrings(encryptor, entry.getValue()));
            }
            return copy;
        }
        if (node instanceof List) {
            List<Object> copy = new ArrayList<>();
            for (Object item : (List<?>) node) {
                copy.add(decryptStrings(encryptor, item));
            }
            return copy;
        }
        return node; // numbers, booleans, null
    }

    // ── the tests ─────────────────────────────────────────────────────────────

    @Test
    void theRecipeDecryptsStringsAtAnyDepth() {
        Encryptor enc = new Encryptor(PASSWORD);
        String json = "{"
                + "\"database\": {\"host\": \"localhost\", \"port\": 5432, \"password\": \"" + enc.encryptWithPrefix("s3cr3t")
                + "\"},"
                + "\"tokens\": [\"plain\", \"" + enc.encryptWithPrefix(EncryptorContract.UTF8_SAMPLE) + "\", {\"k\": \""
                + enc.encryptWithPrefix("nested") + "\"}],"
                + "\"enabled\": true, \"nothing\": null}";

        Map<?, ?> parsed = new Gson().fromJson(json, Map.class);
        Map<?, ?> config = (Map<?, ?>) decryptStrings(enc, parsed);

        Map<?, ?> database = (Map<?, ?>) config.get("database");
        assertEquals("localhost", database.get("host"));
        assertEquals(5432.0, database.get("port"));
        assertEquals("s3cr3t", database.get("password"));
        List<?> tokens = (List<?>) config.get("tokens");
        assertEquals("plain", tokens.get(0));
        assertEquals(EncryptorContract.UTF8_SAMPLE, tokens.get(1));
        assertEquals("nested", ((Map<?, ?>) tokens.get(2)).get("k"));
        assertEquals(Boolean.TRUE, config.get("enabled"));
        assertEquals(null, config.get("nothing"));
    }

    @Test
    void aSecretWithQuotesAndBackslashesSurvivesTheRecipe() {
        Encryptor enc = new Encryptor(PASSWORD);
        String secret = "pa\"ss\\word\n{}";
        String json = "{\"password\": \"" + enc.encryptWithPrefix(secret) + "\"}";

        Map<?, ?> config = (Map<?, ?>) decryptStrings(enc, new Gson().fromJson(json, Map.class));

        assertEquals(secret, config.get("password"));
    }

    @Test
    void decryptAllInStringOnRawJsonCorruptsSuchASecret() {
        // Why the README says "parse first": the decrypted text is inserted as it is, without the
        // escaping JSON needs. The document is then either invalid or means something else.
        Encryptor enc = new Encryptor(PASSWORD);
        String secret = "pa\"ss\\word\n{}";
        String json = "{\"password\": \"" + enc.encryptWithPrefix(secret) + "\"}";

        String replaced = enc.decryptAllInString(json);

        Object got;
        try {
            got = new Gson().fromJson(replaced, Map.class).get("password");
        } catch (JsonSyntaxException invalidJson) {
            got = null;
        }
        assertNotEquals(secret, got);
    }
}
