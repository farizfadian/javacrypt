package io.github.farizfadian.javacrypt.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JasyptEncryptor;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The CLI as a real process, started with the JVM that runs the tests ({@code java.home}).
 *
 * <p>This is where encodings are tested, because they only exist at a process boundary: how the JVM
 * decodes its arguments and environment, and which bytes it writes to a redirected stdout. Every
 * case runs twice, once with the JVM's default charset and once with the other one
 * ({@code -Dfile.encoding=COMPAT} selects the platform charset on Java 18+, and is not a charset
 * name on older releases, where it selects UTF-8). The CLI must not depend on either.
 */
class MainProcessTest {

    private static final String PASSWORD = "javacrypt-test-2026";
    private static final String UTF8 = MainTest.UTF8;
    /** Two Latin-1 letters and an emoji: only UTF-8 systems can pass this as an argument. */
    private static final String UNICODE_PASSWORD = "pässwörd-🔐";
    /** Representable in every Western single-byte code page, and in UTF-8. */
    private static final String LATIN1_PASSWORD = "pässwörd";

    private static final String[][] JVM_OPTIONS = {{}, {"-Dfile.encoding=COMPAT"}};

    @TempDir
    Path dir;

    static final class Output {
        final int code;
        final byte[] out;
        final byte[] err;

        Output(int code, byte[] out, byte[] err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }

        String outText() {
            return new String(out, StandardCharsets.UTF_8);
        }

        String errText() {
            return new String(err, StandardCharsets.UTF_8);
        }

        Output ok() {
            assertEquals(0, code, "stderr: " + errText());
            return this;
        }
    }

    private static Path classesDirectory() {
        try {
            return Paths.get(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String javaExecutable() {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
        return Paths.get(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java").toString();
    }

    /** Runs the CLI in a child JVM with stdout and stderr redirected to files. */
    private Output cli(String[] jvmOptions, Map<String, String> env, String... args)
            throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.addAll(Arrays.asList(jvmOptions));
        command.add("-cp");
        command.add(classesDirectory().toString());
        command.add(Main.class.getName());
        command.addAll(Arrays.asList(args));
        return start(command, env, dir);
    }

    static Output start(List<String> command, Map<String, String> env, Path workDir)
            throws IOException, InterruptedException {
        File out = Files.createTempFile(workDir, "stdout", ".bin").toFile();
        File err = Files.createTempFile(workDir, "stderr", ".bin").toFile();
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().remove("JAVACRYPT_PASSWORD");
        builder.environment().putAll(env);
        builder.redirectOutput(out);
        builder.redirectError(err);
        builder.redirectInput(ProcessBuilder.Redirect.from(emptyFile(workDir)));
        Process process = builder.start();
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("timed out: " + command);
        }
        return new Output(process.exitValue(), Files.readAllBytes(out.toPath()), Files.readAllBytes(err.toPath()));
    }

    private static File emptyFile(Path workDir) throws IOException {
        Path empty = workDir.resolve("empty-stdin");
        if (!Files.exists(empty)) {
            Files.write(empty, new byte[0]);
        }
        return empty.toFile();
    }

    private static Map<String, String> env(String password) {
        return Collections.singletonMap("JAVACRYPT_PASSWORD", password);
    }

    private static final Map<String, String> NO_ENV = Collections.emptyMap();

    /** The charset the JVM uses to decode arguments (and, on Unix, the environment). */
    private static Charset argumentCharset() {
        String name = System.getProperty("sun.jnu.encoding");
        try {
            return name == null ? Charset.defaultCharset() : Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.US_ASCII;
        }
    }

    private static boolean windows() {
        return System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static boolean argumentsCanCarry(String text) {
        return argumentCharset().newEncoder().canEncode(text);
    }

    private static boolean environmentCanCarry(String text) {
        // Windows hands the environment over as UTF-16. Unix decodes it like the arguments.
        return windows() || argumentsCanCarry(text);
    }

    private static String describeRuntime() {
        return "Java " + System.getProperty("java.version") + " on " + System.getProperty("os.name")
                + ", arguments decoded as " + argumentCharset();
    }

    // ── output bytes ──────────────────────────────────────────────────────────

    @Test
    void redirectedStdoutIsUtf8WithLineFeedsWhateverTheDefaultCharsetIs() throws Exception {
        String wrapped = new Encryptor(PASSWORD).encryptWithPrefix(UTF8);
        for (String[] jvm : JVM_OPTIONS) {
            Output output = cli(jvm, NO_ENV, "decrypt", "-p", PASSWORD, "-v", wrapped).ok();
            assertArrayEquals((UTF8 + "\n").getBytes(StandardCharsets.UTF_8), output.out, Arrays.toString(jvm));
            assertEquals(0, output.err.length, output.errText());
        }
    }

    @Test
    void fileContentWrittenToStdoutIsUtf8Too() throws Exception {
        Path encrypted = dir.resolve("greeting.env");
        Files.write(encrypted, ("GREETING=" + new JasyptEncryptor(PASSWORD).encryptWithPrefix(UTF8) + "\n")
                .getBytes(StandardCharsets.UTF_8));
        for (String[] jvm : JVM_OPTIONS) {
            Output output = cli(jvm, NO_ENV, "decrypt-file", "--jasypt", "-p", PASSWORD,
                    "-i", encrypted.toString()).ok();
            assertArrayEquals(("GREETING=" + UTF8 + "\n").getBytes(StandardCharsets.UTF_8), output.out,
                    Arrays.toString(jvm));
        }
    }

    @Test
    void filesAreReadAndWrittenAsUtf8WhateverTheDefaultCharsetIs() throws Exception {
        Path plain = dir.resolve("plain.env");
        Files.write(plain, ("GREETING=" + UTF8 + "\nNAME=日本語\n").getBytes(StandardCharsets.UTF_8));
        for (String[] jvm : JVM_OPTIONS) {
            Path encrypted = dir.resolve("encrypted" + jvm.length + ".env");
            Path restored = dir.resolve("restored" + jvm.length + ".env");
            cli(jvm, NO_ENV, "encrypt-file", "-p", PASSWORD, "-i", plain.toString(), "-o", encrypted.toString()).ok();

            // The library, in this JVM, reads what the child process wrote.
            String[] lines = new String(Files.readAllBytes(encrypted), StandardCharsets.UTF_8).split("\n");
            assertEquals(UTF8, new Encryptor(PASSWORD).decryptPrefixed(lines[0].substring("GREETING=".length())));
            assertEquals("日本語", new Encryptor(PASSWORD).decryptPrefixed(lines[1].substring(5)));

            cli(jvm, NO_ENV, "decrypt-file", "-p", PASSWORD, "-i", encrypted.toString(), "-o", restored.toString())
                    .ok();
            assertArrayEquals(Files.readAllBytes(plain), Files.readAllBytes(restored), Arrays.toString(jvm));
        }
    }

    @Test
    void errorsGoToStderrWithExitCodeOne() throws Exception {
        Output output = cli(JVM_OPTIONS[0], NO_ENV, "encrypt", "-v", "x");
        assertEquals(1, output.code);
        assertEquals(0, output.out.length);
        assertEquals("Error: password is required (-p or JAVACRYPT_PASSWORD)\n", output.errText());

        Output usage = cli(JVM_OPTIONS[0], NO_ENV);
        assertEquals(1, usage.code);
        assertTrue(usage.errText().contains("Usage:"), usage.errText());
        assertFalse(usage.errText().contains("\r"));
    }

    // ── non-ASCII passwords and values ────────────────────────────────────────

    @Test
    void aNonAsciiPasswordWorksThroughTheEnvironmentVariable() throws Exception {
        assumeTrue(environmentCanCarry(UNICODE_PASSWORD),
                "the environment cannot carry this password here: " + describeRuntime());
        for (String[] jvm : JVM_OPTIONS) {
            // Written by the child with the password from its environment, read by the library here.
            String wrapped = cli(jvm, env(UNICODE_PASSWORD), "encrypt", "-v", "hello").ok().outText().trim();
            assertEquals("hello", new Encryptor(UNICODE_PASSWORD).decryptPrefixed(wrapped), describeRuntime());

            // And the other way round, with a non-ASCII plaintext coming back on stdout.
            String fromLibrary = new JasyptEncryptor(UNICODE_PASSWORD).encryptWithPrefix(UTF8);
            Output output = cli(jvm, env(UNICODE_PASSWORD), "decrypt", "--jasypt", "-v", fromLibrary).ok();
            assertArrayEquals((UTF8 + "\n").getBytes(StandardCharsets.UTF_8), output.out, describeRuntime());
        }
    }

    @Test
    void latin1ArgumentsArriveIntactWhereTheArgumentCharsetHasThem() throws Exception {
        assumeTrue(argumentsCanCarry(LATIN1_PASSWORD + "Grüße"),
                "arguments cannot carry Latin-1 letters here: " + describeRuntime());
        Output output = cli(JVM_OPTIONS[0], NO_ENV, "encrypt", "-p", LATIN1_PASSWORD, "-v", "Grüße").ok();
        assertEquals("Grüße",
                new Encryptor(LATIN1_PASSWORD).decryptPrefixed(output.outText().trim()), describeRuntime());
        assertEquals("", output.errText(), "no '?' arrived, so no warning");
    }

    @Test
    void anyUnicodeArgumentArrivesIntactOnUtf8Systems() throws Exception {
        assumeTrue(argumentsCanCarry(UNICODE_PASSWORD + UTF8),
                "arguments cannot carry these characters here: " + describeRuntime());
        Output output = cli(JVM_OPTIONS[0], NO_ENV, "encrypt", "-p", UNICODE_PASSWORD, "-v", UTF8).ok();
        assertEquals(UTF8, new Encryptor(UNICODE_PASSWORD).decryptPrefixed(output.outText().trim()),
                describeRuntime());
        assertEquals("", output.errText());
    }

    @Test
    void windowsWarnsWhenAnArgumentWasDamagedByTheCodePage() throws Exception {
        // The measured hazard: java.exe receives its arguments through the ANSI code page, so an
        // emoji in -p arrives as "??" and the value would silently be encrypted under another password.
        assumeTrue(windows() && !argumentsCanCarry(UNICODE_PASSWORD),
                "only where arguments are lossy: " + describeRuntime());
        Output output = cli(JVM_OPTIONS[0], NO_ENV, "encrypt", "-p", UNICODE_PASSWORD, "-v", "hello").ok();

        String warning = output.errText();
        assertTrue(warning.startsWith("Warning: "), warning);
        assertTrue(warning.contains("JAVACRYPT_PASSWORD"), warning);
        // The value really was encrypted under the damaged password, which is why the warning matters.
        String wrapped = output.outText().trim();
        try {
            assertFalse("hello".equals(new Encryptor(UNICODE_PASSWORD).decryptPrefixed(wrapped)),
                    "the real password must not open it: the argument was damaged");
        } catch (io.github.farizfadian.javacrypt.JavaCryptException expected) {
            // decryption failed: the expected outcome
        }
    }
}
