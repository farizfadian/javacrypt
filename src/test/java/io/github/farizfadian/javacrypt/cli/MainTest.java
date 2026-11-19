package io.github.farizfadian.javacrypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JasyptEncryptor;
import io.github.farizfadian.javacrypt.JasyptStrongEncryptor;
import io.github.farizfadian.javacrypt.JavaCrypt;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The command-line interface, run in-process through {@code Main.run}.
 *
 * <p>The first block is a port of RustCrypt's {@code tests/cli.rs}, so the two CLIs are held to the
 * same behaviour. The rest covers what only matters on the JVM. Real processes, encodings and the
 * jar itself are covered by {@code MainProcessTest} and {@code JarIT}.
 */
class MainTest {

    static final String PASSWORD = "javacrypt-test-2026";
    static final String UTF8 = "Selamat pagi, Fariz 🦀";
    static final String FOOTER =
            "An idea from Fariz (github.com/farizfadian) and made with love by Claude AI (claude.ai)";

    private static final String[][] MODES = {{}, {"--jasypt"}, {"--jasypt-strong"}};

    private static final Map<String, String> NO_ENV = Collections.emptyMap();

    @TempDir
    Path dir;

    /** What one invocation produced. */
    static final class Result {
        final int code;
        final String out;
        final String err;

        Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }

        /** Asserts success and returns stdout without its final line end. */
        String line() {
            assertEquals(0, code, "stderr: " + err);
            assertTrue(out.endsWith("\n"), "stdout must end with a line feed: " + out);
            assertFalse(out.contains("\r"), "stdout must not contain carriage returns");
            return out.substring(0, out.length() - 1);
        }

        Result fails() {
            assertEquals(1, code, "stdout: " + out + " stderr: " + err);
            return this;
        }
    }

    static Result run(Map<String, String> env, Main.ArgumentEncoding encoding, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        try {
            PrintStream outStream = new PrintStream(out, false, "UTF-8");
            PrintStream errStream = new PrintStream(err, false, "UTF-8");
            int code = Main.run(args, env, outStream, errStream, encoding);
            outStream.flush();
            errStream.flush();
            return new Result(code, new String(out.toByteArray(), StandardCharsets.UTF_8),
                    new String(err.toByteArray(), StandardCharsets.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static Result run(String... args) {
        return run(NO_ENV, Main.ArgumentEncoding.UNICODE, args);
    }

    static Result run(Map<String, String> env, String... args) {
        return run(env, Main.ArgumentEncoding.UNICODE, args);
    }

    /** The arguments followed by the mode flag, if the mode has one. */
    private static String[] withMode(String[] mode, String... args) {
        String[] all = Arrays.copyOf(args, args.length + mode.length);
        System.arraycopy(mode, 0, all, args.length, mode.length);
        return all;
    }

    private static Map<String, String> env(String password) {
        Map<String, String> env = new HashMap<>();
        env.put("JAVACRYPT_PASSWORD", password);
        return env;
    }

    private Path write(String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static String read(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    // ── encrypt / decrypt (port of cli.rs) ────────────────────────────────────

    @Test
    void encryptThenDecryptRoundTripInEveryMode() {
        for (String[] mode : MODES) {
            for (String plaintext : new String[] {"hello", "Password123!", UTF8}) {
                String wrapped = run(withMode(mode, "encrypt", "-p", PASSWORD, "-v", plaintext)).line();
                assertTrue(wrapped.startsWith("ENC(") && wrapped.endsWith(")"), wrapped);
                assertEquals(plaintext, run(withMode(mode, "decrypt", "-p", PASSWORD, "-v", wrapped)).line(),
                        "mode=" + Arrays.toString(mode));
            }
        }
    }

    @Test
    void cliOutputIsReadableByTheLibraryAndViceVersa() {
        String wrapped = run("encrypt", "-p", PASSWORD, "-v", "lib", "--jasypt").line();
        assertEquals("lib", new JasyptEncryptor(PASSWORD).decryptPrefixed(wrapped));

        String fromLibrary = new JasyptStrongEncryptor(PASSWORD).encryptWithPrefix("strong");
        assertEquals("strong", run("decrypt", "-p", PASSWORD, "-v", fromLibrary, "--jasypt-strong").line());

        String defaultMode = run("encrypt", "-p", PASSWORD, "-v", "gcm").line();
        assertEquals("gcm", new Encryptor(PASSWORD).decryptPrefixed(defaultMode));
    }

    @Test
    void noPrefixEmitsRawPayloadThatDecryptAccepts() {
        String raw = run("encrypt", "-p", PASSWORD, "-v", "raw", "--no-prefix").line();
        assertFalse(raw.contains("ENC("));
        assertEquals("raw", new Encryptor(PASSWORD).decrypt(raw));
        // decrypt detects the missing wrapper
        assertEquals("raw", run("decrypt", "-p", PASSWORD, "-v", raw).line());
    }

    @Test
    void passwordFallsBackToEnvironmentVariable() {
        String wrapped = run(env(PASSWORD), "encrypt", "-v", "from-env").line();
        // An empty -p also falls back to the environment (gocrypt-cli semantics).
        assertEquals("from-env", run(env(PASSWORD), "decrypt", "-p", "", "-v", wrapped).line());
    }

    @Test
    void aPasswordOnTheCommandLineWinsOverTheEnvironment() {
        String wrapped = run(env("from-the-environment"), "encrypt", "-p", PASSWORD, "-v", "x").line();
        assertEquals("x", new Encryptor(PASSWORD).decryptPrefixed(wrapped));
    }

    @Test
    void missingPasswordIsAnError() {
        Result result = run("encrypt", "-v", "x").fails();
        assertEquals("Error: password is required (-p or JAVACRYPT_PASSWORD)\n", result.err);
        assertEquals("", result.out);
        assertEquals("Error: password is required (-p or JAVACRYPT_PASSWORD)\n",
                run(env(""), "decrypt", "-v", "x").fails().err);
    }

    @Test
    void missingValueIsAnError() {
        assertEquals("Error: value is required (-v)\n", run("encrypt", "-p", PASSWORD).fails().err);
        assertEquals("Error: value is required (-v)\n", run("decrypt", "-p", PASSWORD, "-v", "").fails().err);
    }

    @Test
    void jasyptFlagsAreMutuallyExclusive() {
        Result result = run("encrypt", "-p", PASSWORD, "-v", "x", "--jasypt", "--jasypt-strong").fails();
        assertEquals("Error: --jasypt cannot be used with --jasypt-strong\n", result.err);
        assertEquals("", result.out);
    }

    @Test
    void wrongPasswordReportsDecryptionFailed() {
        String wrapped = run("encrypt", "-p", PASSWORD, "-v", "x").line();
        Result result = run("decrypt", "-p", "wrong", "-v", wrapped).fails();
        assertEquals("", result.out);
        assertEquals("Error: decryption failed\n", result.err);
    }

    @Test
    void invalidInputReportsLibraryError() {
        Result result = run("decrypt", "-p", PASSWORD, "-v", "ENC(not base64!)").fails();
        assertTrue(result.err.startsWith("Error: failed to decode base64: "), result.err);
    }

    // ── encrypt-file / decrypt-file (port of cli.rs) ──────────────────────────

    private static final String ENV_PLAIN = "# Database settings\n"
            + "DB_HOST=localhost\n"
            + "DB_PASS=\"s3cr3t\"\n"
            + "\n"
            + "EMPTY=\n"
            + "ALREADY=ENC(abc)\n"
            + "NOT A PAIR\n"
            + "API_KEY='key with spaces'\n"
            + "  # indented comment=1\n";

    @Test
    void encryptFileThenDecryptFileRoundTrip() throws IOException {
        for (String[] mode : MODES) {
            Path plain = write(".env.plain", ENV_PLAIN);
            Path encrypted = dir.resolve(".env.encrypted");
            Path restored = dir.resolve(".env.restored");

            Result encrypt = run(withMode(mode, "encrypt-file", "-p", PASSWORD,
                    "-i", plain.toString(), "-o", encrypted.toString()));
            assertEquals(0, encrypt.code, encrypt.err);
            assertEquals("", encrypt.out);

            String text = read(encrypted);
            List<String> lines = Arrays.asList(text.split("\n", -1));
            assertEquals(10, lines.size(), text);
            assertEquals("# Database settings", lines.get(0));
            assertTrue(lines.get(1).startsWith("DB_HOST=ENC(") && lines.get(1).endsWith(")"), lines.get(1));
            assertTrue(lines.get(2).startsWith("DB_PASS=ENC("), lines.get(2));
            assertFalse(lines.get(2).contains("\""), "quotes must be stripped before encrypting");
            assertEquals("", lines.get(3));
            assertEquals("EMPTY=", lines.get(4));
            assertEquals("ALREADY=ENC(abc)", lines.get(5));
            assertEquals("NOT A PAIR", lines.get(6));
            assertTrue(lines.get(7).startsWith("API_KEY=ENC("), lines.get(7));
            assertEquals("  # indented comment=1", lines.get(8));
            assertEquals("", lines.get(9), "the file ends with a line feed");

            Result decrypt = run(withMode(mode, "decrypt-file", "-p", PASSWORD,
                    "-i", encrypted.toString(), "-o", restored.toString()));
            assertEquals(0, decrypt.code, decrypt.err);

            assertEquals("# Database settings\n"
                    + "DB_HOST=localhost\n"
                    + "DB_PASS=s3cr3t\n"
                    + "\n"
                    + "EMPTY=\n"
                    + "ALREADY=ENC(abc)\n"
                    + "NOT A PAIR\n"
                    + "API_KEY=key with spaces\n"
                    + "  # indented comment=1\n", read(restored), "mode=" + Arrays.toString(mode));
        }
    }

    @Test
    void fileCommandsWriteToStdoutWhenOutputIsDashOrOmitted() throws IOException {
        Path plain = write("in.env", "K=v\n");

        String toDash = run("encrypt-file", "-p", PASSWORD, "--jasypt", "-i", plain.toString(), "-o", "-").line();
        assertTrue(toDash.startsWith("K=ENC("), toDash);

        String omitted = run("encrypt-file", "-p", PASSWORD, "--jasypt", "-i", plain.toString()).line();
        assertTrue(omitted.startsWith("K=ENC("), omitted);

        Path encrypted = write("out.env", omitted + "\nX=ENC(not base64!)\n");
        String back = run("decrypt-file", "-p", PASSWORD, "--jasypt", "-i", encrypted.toString()).line();
        assertEquals("K=v\nX=ENC(not base64!)", back, "bad values are kept verbatim");
    }

    @Test
    void fileCommandsReportMissingOrUnreadableInput() {
        assertEquals("Error: input file is required (-i)\n", run("encrypt-file", "-p", PASSWORD).fails().err);
        assertEquals("Error: input file is required (-i)\n",
                run("decrypt-file", "-p", PASSWORD, "-i", "").fails().err);

        Path missing = dir.resolve("javacrypt-cli-missing-2026.env");
        Result result = run("encrypt-file", "-p", PASSWORD, "-i", missing.toString()).fails();
        assertTrue(result.err.startsWith("Error opening input file: "), result.err);
        assertTrue(result.err.contains("javacrypt-cli-missing-2026.env"), result.err);
    }

    // ── version / help / usage errors (port of cli.rs) ────────────────────────

    @Test
    void versionOutputs() {
        String expected = "javacrypt version " + JavaCrypt.version();
        for (String arg : new String[] {"version", "--version", "-V", "-v"}) {
            assertEquals(expected, run(arg).line(), arg);
        }
        assertTrue(expected.matches("javacrypt version \\d+\\.\\d+\\.\\d+.*"), expected);
    }

    @Test
    void helpEndsWithFamilyFooter() {
        for (String arg : new String[] {"--help", "help", "-h"}) {
            Result result = run(arg);
            assertEquals(0, result.code);
            assertEquals("", result.err);
            assertTrue(result.out.contains("Usage:"), result.out);
            assertTrue(result.out.contains("encrypt-file"), result.out);
            assertTrue(result.out.contains("JAVACRYPT_PASSWORD"), result.out);
            assertTrue(result.out.endsWith(FOOTER + "\n"), result.out);
            assertFalse(result.out.contains("\r"));
        }
    }

    @Test
    void noArgsPrintsUsageAndFails() {
        Result result = run().fails();
        assertTrue(result.err.contains("Usage:"), result.err);
        assertEquals("", result.out);
    }

    @Test
    void unknownCommandFails() {
        Result result = run("frobnicate").fails();
        assertTrue(result.err.startsWith("Unknown command: frobnicate\n"), result.err);
        assertTrue(result.err.contains("Usage:"), result.err);
    }

    // ── argument parsing ──────────────────────────────────────────────────────

    @Test
    void longOptionsAndEqualsFormsAreAccepted() throws IOException {
        String wrapped = run("encrypt", "--password", PASSWORD, "--value", "hello").line();
        assertEquals("hello", run("decrypt", "--password=" + PASSWORD, "--value=" + wrapped).line());
        assertEquals("hello", run("decrypt", "-p=" + PASSWORD, "-v=" + wrapped).line());

        Path in = write("long.env", "K=v\n");
        Path out = dir.resolve("long.out");
        assertEquals(0, run("encrypt-file", "--password", PASSWORD, "--input", in.toString(),
                "--output=" + out).code);
        assertTrue(read(out).startsWith("K=ENC("));
    }

    @Test
    void theArgumentAfterAnOptionIsItsValueEvenIfItLooksLikeAnOption() {
        // A password or a secret may start with a dash or contain "=".
        String wrapped = run("encrypt", "-p", "-p", "-v", "--jasypt").line();
        assertEquals("--jasypt", new Encryptor("-p").decryptPrefixed(wrapped));

        String withEquals = run("encrypt", "-p", "pass=word", "-v", "a=b=c").line();
        assertEquals("a=b=c", new Encryptor("pass=word").decryptPrefixed(withEquals));
    }

    @Test
    void unknownAndMisplacedOptionsFail() {
        assertEquals("Error: unknown option: --bogus\n",
                run("encrypt", "-p", PASSWORD, "-v", "x", "--bogus").fails().err);
        assertEquals("Error: unknown option: --no-prefix\n",
                run("decrypt", "-p", PASSWORD, "-v", "x", "--no-prefix").fails().err);
        assertEquals("Error: unknown option: -i\n",
                run("encrypt", "-p", PASSWORD, "-v", "x", "-i", "file").fails().err);
        assertEquals("Error: unknown option: -v\n",
                run("encrypt-file", "-p", PASSWORD, "-v", "x").fails().err);
        assertEquals("Error: unexpected argument: stray\n",
                run("encrypt", "-p", PASSWORD, "-v", "x", "stray").fails().err);
        assertEquals("Error: option --jasypt does not take a value\n",
                run("encrypt", "-p", PASSWORD, "-v", "x", "--jasypt=yes").fails().err);
    }

    @Test
    void anOptionWithoutItsValueFails() {
        assertEquals("Error: option -p requires a value\n", run("encrypt", "-v", "x", "-p").fails().err);
        assertEquals("Error: option --value requires a value\n",
                run("encrypt", "-p", PASSWORD, "--value").fails().err);
    }

    @Test
    void helpIsAvailableOnEveryCommand() {
        for (String command : new String[] {"encrypt", "decrypt", "encrypt-file", "decrypt-file"}) {
            for (String flag : new String[] {"--help", "-h"}) {
                Result result = run(command, flag);
                assertEquals(0, result.code);
                assertTrue(result.out.endsWith(FOOTER + "\n"), result.out);
            }
        }
    }

    // ── files: line ends, encodings, odd shapes ───────────────────────────────

    @Test
    void outputAlwaysUsesLineFeedsAndCrLfInputIsUnderstood() throws IOException {
        Path in = write("crlf.env", "A=one\r\nB=two\r\n");
        Path out = dir.resolve("crlf.out");
        assertEquals(0, run("encrypt-file", "-p", PASSWORD, "-i", in.toString(), "-o", out.toString()).code);

        String text = read(out);
        assertFalse(text.contains("\r"), "output lines end with a line feed only");
        String[] lines = text.split("\n");
        assertEquals(2, lines.length);
        // The carriage return must not have become part of the encrypted value.
        Encryptor enc = new Encryptor(PASSWORD);
        assertEquals("one", enc.decryptPrefixed(lines[0].substring(2)));
        assertEquals("two", enc.decryptPrefixed(lines[1].substring(2)));
    }

    @Test
    void aFileWithoutAFinalLineEndGetsOne() throws IOException {
        Path in = write("no-eol.env", "A=1");
        String out = run("encrypt-file", "-p", PASSWORD, "-i", in.toString()).line();
        assertEquals("1", new Encryptor(PASSWORD).decryptPrefixed(out.substring(2)));
    }

    @Test
    void anEmptyFileGivesEmptyOutput() throws IOException {
        Path in = write("empty.env", "");
        Path out = dir.resolve("empty.out");
        assertEquals(0, run("encrypt-file", "-p", PASSWORD, "-i", in.toString(), "-o", out.toString()).code);
        assertEquals("", read(out));
        Result toStdout = run("decrypt-file", "-p", PASSWORD, "-i", in.toString());
        assertEquals(0, toStdout.code);
        assertEquals("", toStdout.out);
    }

    @Test
    void nonAsciiValuesSurviveTheFileCommands() throws IOException {
        for (String[] mode : MODES) {
            Path in = write("unicode.env", "GREETING=" + UTF8 + "\nNAME=日本語\n");
            Path encrypted = dir.resolve("unicode.enc");
            Path restored = dir.resolve("unicode.out");
            assertEquals(0, run(withMode(mode, "encrypt-file", "-p", PASSWORD,
                    "-i", in.toString(), "-o", encrypted.toString())).code);
            assertFalse(read(encrypted).contains("Selamat"));
            assertEquals(0, run(withMode(mode, "decrypt-file", "-p", PASSWORD,
                    "-i", encrypted.toString(), "-o", restored.toString())).code);
            assertEquals("GREETING=" + UTF8 + "\nNAME=日本語\n", read(restored));
        }
    }

    @Test
    void theInputFileMayBeOverwrittenInPlace() throws IOException {
        Path file = write("inplace.env", "A=1\nB=2\n");
        assertEquals(0, run("encrypt-file", "-p", PASSWORD, "-i", file.toString(), "-o", file.toString()).code);
        String text = read(file);
        assertTrue(text.startsWith("A=ENC("), text);
        assertEquals(0, run("decrypt-file", "-p", PASSWORD, "-i", file.toString(), "-o", file.toString()).code);
        assertEquals("A=1\nB=2\n", read(file));
    }

    @Test
    void aFileThatIsNotUtf8IsReportedNotMangled() throws IOException {
        Path in = dir.resolve("latin1.env");
        Files.write(in, "NAME=café\n".getBytes(StandardCharsets.ISO_8859_1));
        Path out = dir.resolve("latin1.out");
        Result result = run("encrypt-file", "-p", PASSWORD, "-i", in.toString(), "-o", out.toString()).fails();
        assertTrue(result.err.startsWith("Error reading file: "), result.err);
        assertTrue(result.err.contains("UTF-8"), result.err);
        assertFalse(Files.exists(out), "no output file is left behind when the input cannot be read");
    }

    @Test
    void anOutputFileThatCannotBeCreatedIsReported() throws IOException {
        Path in = write("ok.env", "A=1\n");
        Result result = run("encrypt-file", "-p", PASSWORD, "-i", in.toString(), "-o", dir.toString()).fails();
        assertTrue(result.err.startsWith("Error creating output file: "), result.err);
    }

    // ── arguments the platform may have damaged ───────────────────────────────

    @Test
    void aQuestionMarkInAnArgumentIsFlaggedWhereArgumentsCanBeLossy() {
        Main.ArgumentEncoding windows = new Main.ArgumentEncoding(true, false, "Cp1252");

        // What "-p pw🔐" looks like after Windows converted it to code page 1252.
        Result password = run(NO_ENV, windows, "encrypt", "-p", "pw??", "-v", "x");
        assertEquals(0, password.code, "it is a warning, not an error: the password may really contain '?'");
        assertTrue(password.out.startsWith("ENC("), password.out);
        assertTrue(password.err.startsWith("Warning: "), password.err);
        assertTrue(password.err.contains("Cp1252") && password.err.contains("JAVACRYPT_PASSWORD"), password.err);

        Result value = run(NO_ENV, windows, "encrypt", "-p", PASSWORD, "-v", "what?");
        assertEquals(0, value.code);
        assertTrue(value.err.startsWith("Warning: ") && value.err.contains("encrypt-file"), value.err);
    }

    @Test
    void noWarningWithoutAQuestionMarkOrWhereArgumentsAreUnicode() {
        Main.ArgumentEncoding windows = new Main.ArgumentEncoding(true, false, "Cp1252");
        assertEquals("", run(NO_ENV, windows, "encrypt", "-p", PASSWORD, "-v", "plain").err);
        // The environment is passed as UTF-16 on Windows: a '?' there is a real '?'.
        assertEquals("", run(env("pw??"), windows, "encrypt", "-v", "plain").err);
        // A UTF-8 system passes arguments unchanged.
        assertEquals("", run(NO_ENV, Main.ArgumentEncoding.UNICODE, "encrypt", "-p", "pw??", "-v", "what?").err);
        // The value of decrypt is base64, and file paths are not secrets: nothing to flag.
        String wrapped = run("encrypt", "-p", PASSWORD, "-v", "x").line();
        assertEquals("", run(NO_ENV, windows, "decrypt", "-p", PASSWORD, "-v", wrapped).err);
    }

    @Test
    void aLossyEnvironmentIsFlaggedToo() {
        // A Unix system with a non-UTF-8 locale decodes arguments and the environment the same lossy way.
        Main.ArgumentEncoding posix = new Main.ArgumentEncoding(true, true, "ANSI_X3.4-1968");
        Result result = run(env("pw??"), posix, "encrypt", "-v", "plain");
        assertEquals(0, result.code);
        assertTrue(result.err.startsWith("Warning: ") && result.err.contains("ANSI_X3.4-1968"), result.err);
    }
}
