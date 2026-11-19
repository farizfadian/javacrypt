package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.farizfadian.javacrypt.Fixtures.Vector;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Live round trips against the released command-line tools of other family members.
 *
 * <p>JavaCrypt runs in this JVM; the other implementation is a real process. Every mode is
 * exercised in both directions, with an ASCII and a non-ASCII password. Point the environment
 * variables at the binaries from the GitHub release pages:
 *
 * <pre>
 * GOCRYPT_CLI=/path/to/gocrypt-cli-linux-amd64 RUSTCRYPT_CLI=/path/to/rustcrypt-linux-amd64 ./mvnw test -Dtest=CrossLanguageCliTest
 * </pre>
 *
 * <p>Without a variable the corresponding tests are skipped. CI sets
 * {@code JAVACRYPT_REQUIRE_CLIS=true}, which turns a missing binary into a failure, so the job
 * cannot pass by silently testing nothing.
 */
class CrossLanguageCliTest {

    private static final String[][] MODES = {
        {"default"}, {"jasypt", "--jasypt"}, {"jasypt-strong", "--jasypt-strong"}};

    @TempDir
    Path dir;

    private static StringEncryptor encryptorFor(String mode, String password) {
        switch (mode) {
            case "default":
                return new Encryptor(password);
            case "jasypt":
                return new JasyptEncryptor(password);
            default:
                return new JasyptStrongEncryptor(password);
        }
    }

    /** The binary named by {@code variable}; skips the test (or fails it in CI) when it is not set. */
    private static Path cli(String variable) {
        String value = System.getenv(variable);
        boolean required = "true".equalsIgnoreCase(System.getenv("JAVACRYPT_REQUIRE_CLIS"));
        if (value == null || value.isEmpty()) {
            if (required) {
                fail(variable + " is not set, but JAVACRYPT_REQUIRE_CLIS=true");
            }
            assumeTrue(false, variable + " is not set: no live round trip against that tool");
        }
        Path path = Paths.get(value);
        assertTrue(Files.isRegularFile(path), variable + " does not point to a file: " + value);
        return path;
    }

    /** Characters that this JVM can hand to a child process as an argument. */
    private static boolean canPassAsArgument(String text) {
        if (System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows")) {
            return true; // CreateProcessW takes UTF-16
        }
        String name = System.getProperty("sun.jnu.encoding");
        try {
            return (name == null ? Charset.defaultCharset() : Charset.forName(name)).newEncoder().canEncode(text);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static List<String> passwords() {
        List<String> passwords = new ArrayList<>();
        passwords.add(Fixtures.load(Fixtures.ASCII).password);
        if (canPassAsArgument(Fixtures.UNICODE_PASSWORD)) {
            passwords.add(Fixtures.UNICODE_PASSWORD);
        } else if ("true".equalsIgnoreCase(System.getenv("JAVACRYPT_REQUIRE_CLIS"))) {
            // In CI a green run must mean that the non-ASCII password really was exercised.
            fail("this JVM cannot pass a non-ASCII argument to a child process (sun.jnu.encoding="
                    + System.getProperty("sun.jnu.encoding") + "), so the non-ASCII password would be left out");
        }
        return passwords;
    }

    /** The plaintexts of both fixtures, without duplicates. */
    private static Set<String> plaintexts() {
        Set<String> plaintexts = new LinkedHashSet<>();
        for (String fixture : new String[] {Fixtures.ASCII, Fixtures.UNICODE}) {
            for (Vector v : Fixtures.load(fixture).vectors) {
                if (canPassAsArgument(v.plaintext)) {
                    plaintexts.add(v.plaintext);
                }
            }
        }
        return plaintexts;
    }

    private String run(Path cli, List<String> args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(cli.toString());
        command.addAll(args);
        File out = Files.createTempFile(dir, "stdout", ".bin").toFile();
        File err = Files.createTempFile(dir, "stderr", ".bin").toFile();
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectOutput(out);
        builder.redirectError(err);
        Process process = builder.start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("timed out: " + cli.getFileName());
        }
        String stdout = new String(Files.readAllBytes(out.toPath()), StandardCharsets.UTF_8);
        String stderr = new String(Files.readAllBytes(err.toPath()), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), cli.getFileName() + " " + args.get(0) + " failed: " + stderr);
        // Exactly one line end is removed: leading and trailing spaces of a plaintext must survive.
        if (stdout.endsWith("\r\n")) {
            return stdout.substring(0, stdout.length() - 2);
        }
        return stdout.endsWith("\n") ? stdout.substring(0, stdout.length() - 1) : stdout;
    }

    private static List<String> args(String command, String password, String value, String[] mode) {
        List<String> args = new ArrayList<>(Arrays.asList(command, "-p", password, "-v", value));
        args.addAll(Arrays.asList(mode).subList(1, mode.length));
        return args;
    }

    @ParameterizedTest(name = "{0} reads what JavaCrypt writes")
    @CsvSource({"gocrypt-cli, GOCRYPT_CLI", "rustcrypt, RUSTCRYPT_CLI"})
    void theOtherToolReadsWhatJavaCryptWrites(String tool, String variable) throws Exception {
        Path cli = cli(variable);
        int checked = 0;
        for (String password : passwords()) {
            for (String[] mode : MODES) {
                StringEncryptor javacrypt = encryptorFor(mode[0], password);
                for (String plaintext : plaintexts()) {
                    String wrapped = javacrypt.encryptWithPrefix(plaintext);
                    assertEquals(plaintext, run(cli, args("decrypt", password, wrapped, mode)),
                            tool + " must decrypt JavaCrypt output, mode=" + mode[0]);
                    checked++;
                }
            }
        }
        assertTrue(checked >= 3 * 4, "at least the ASCII password with four plaintexts in three modes");
    }

    @ParameterizedTest(name = "JavaCrypt reads what {0} writes")
    @CsvSource({"gocrypt-cli, GOCRYPT_CLI", "rustcrypt, RUSTCRYPT_CLI"})
    void javaCryptReadsWhatTheOtherToolWrites(String tool, String variable) throws Exception {
        Path cli = cli(variable);
        int checked = 0;
        for (String password : passwords()) {
            for (String[] mode : MODES) {
                StringEncryptor javacrypt = encryptorFor(mode[0], password);
                for (String plaintext : plaintexts()) {
                    String wrapped = run(cli, args("encrypt", password, plaintext, mode));
                    assertTrue(wrapped.startsWith("ENC(") && wrapped.endsWith(")"), tool + " output: " + wrapped);
                    assertEquals(plaintext, javacrypt.decryptPrefixed(wrapped),
                            "JavaCrypt must decrypt " + tool + " output, mode=" + mode[0]);
                    checked++;
                }
            }
        }
        assertTrue(checked >= 3 * 4, "at least the ASCII password with four plaintexts in three modes");
    }
}
