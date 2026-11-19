package io.github.farizfadian.javacrypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JasyptEncryptor;
import java.io.DataInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The packaged jar: what a user downloads. Runs after {@code package}, through maven-failsafe.
 *
 * <p>The jar is both the library and the CLI, so these tests check its manifest, that every class
 * in it is Java 8 bytecode, and that {@code java -jar} works with the JVM running the tests.
 */
class JarIT {

    private static final String PASSWORD = "javacrypt-test-2026";

    @TempDir
    Path dir;

    private static Path jar() {
        String path = System.getProperty("javacrypt.jar");
        assertNotNull(path, "the build must pass -Djavacrypt.jar");
        Path jar = Paths.get(path);
        assertTrue(Files.isRegularFile(jar), "not found: " + jar);
        return jar;
    }

    private MainProcessTest.Output javaJar(String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(MainProcessTest.javaExecutable());
        command.add("-jar");
        command.add(jar().toString());
        command.addAll(Arrays.asList(args));
        return MainProcessTest.start(command, Collections.<String, String>emptyMap(), dir);
    }

    @Test
    void javaJarPrintsTheProjectVersion() throws Exception {
        String expected = System.getProperty("javacrypt.expectedVersion");
        assertNotNull(expected);
        MainProcessTest.Output output = javaJar("version").ok();
        assertEquals("javacrypt version " + expected + "\n", output.outText());
        assertTrue(jar().getFileName().toString().equals("javacrypt-" + expected + ".jar"), jar().toString());
    }

    @Test
    void javaJarEncryptsAndDecrypts() throws Exception {
        String wrapped = javaJar("encrypt", "-p", PASSWORD, "-v", "hello").ok().outText().trim();
        assertEquals("hello", new Encryptor(PASSWORD).decryptPrefixed(wrapped));

        String fromLibrary = new JasyptEncryptor(PASSWORD).encryptWithPrefix(MainTest.UTF8);
        MainProcessTest.Output output = javaJar("decrypt", "--jasypt", "-p", PASSWORD, "-v", fromLibrary).ok();
        assertEquals(MainTest.UTF8 + "\n", output.outText());
    }

    @Test
    void javaJarHelpEndsWithTheFamilyFooter() throws Exception {
        MainProcessTest.Output output = javaJar("help").ok();
        assertTrue(output.outText().endsWith(MainTest.FOOTER + "\n"), output.outText());
    }

    @Test
    void manifestMakesTheJarALibraryAndACommand() throws Exception {
        try (JarFile jar = new JarFile(jar().toFile())) {
            Attributes main = jar.getManifest().getMainAttributes();
            assertEquals("io.github.farizfadian.javacrypt.cli.Main", main.getValue("Main-Class"));
            assertEquals("io.github.farizfadian.javacrypt", main.getValue("Automatic-Module-Name"));
            assertEquals(System.getProperty("javacrypt.expectedVersion"), main.getValue("Implementation-Version"));
            assertNull(main.getValue("Class-Path"), "the jar must not need any other jar");
        }
    }

    @Test
    void everyClassIsJava8BytecodeAndBelongsToThisLibrary() throws Exception {
        int classes = 0;
        boolean license = false;
        try (JarFile jar = new JarFile(jar().toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                license |= name.equals("META-INF/LICENSE");
                if (entry.isDirectory() || name.startsWith("META-INF/")) {
                    continue;
                }
                assertTrue(name.startsWith("io/github/farizfadian/javacrypt/"), "foreign entry: " + name);
                assertFalse(name.contains("Test") || name.endsWith("IT.class"), "test class in the jar: " + name);
                if (name.endsWith(".class")) {
                    try (InputStream in = jar.getInputStream(entry); DataInputStream data = new DataInputStream(in)) {
                        assertEquals(0xCAFEBABE, data.readInt(), name);
                        data.readUnsignedShort(); // minor version
                        assertEquals(52, data.readUnsignedShort(), "class file version of " + name + " (52 = Java 8)");
                    }
                    classes++;
                }
            }
        }
        assertTrue(classes >= 10, "expected the library classes, found " + classes);
        assertTrue(license, "the license text must travel with the jar");
    }
}
