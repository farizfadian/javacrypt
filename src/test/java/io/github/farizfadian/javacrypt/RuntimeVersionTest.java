package io.github.farizfadian.javacrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

/**
 * Makes the "tested on Java N" claim checkable.
 *
 * <p>The build always compiles with a current JDK (to Java 8 bytecode); CI then runs the tests on
 * another runtime through surefire's {@code jvm} option. If that option were ignored, every cell of
 * the matrix would quietly test on the build JDK. CI sets {@code JAVACRYPT_EXPECT_JAVA} to the
 * major version it asked for, and this test fails if the tests are running on anything else.
 */
class RuntimeVersionTest {

    static int runningMajorVersion() {
        // "1.8" on Java 8, then "9", "11", "17", ...
        String specification = System.getProperty("java.specification.version");
        return Integer.parseInt(specification.startsWith("1.") ? specification.substring(2) : specification);
    }

    @Test
    void testsRunOnTheJavaVersionTheBuildAskedFor() {
        String expected = System.getenv("JAVACRYPT_EXPECT_JAVA");
        assumeTrue(expected != null && !expected.isEmpty(), "JAVACRYPT_EXPECT_JAVA is not set (only CI sets it)");
        assertEquals(Integer.parseInt(expected.trim()), runningMajorVersion(),
                "tests are running on Java " + System.getProperty("java.version")
                        + " (" + System.getProperty("java.home") + ")");
    }
}
