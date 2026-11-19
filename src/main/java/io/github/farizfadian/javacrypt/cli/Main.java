package io.github.farizfadian.javacrypt.cli;

import io.github.farizfadian.javacrypt.Encryptor;
import io.github.farizfadian.javacrypt.JasyptEncryptor;
import io.github.farizfadian.javacrypt.JasyptStrongEncryptor;
import io.github.farizfadian.javacrypt.JavaCrypt;
import io.github.farizfadian.javacrypt.JavaCryptException;
import io.github.farizfadian.javacrypt.StringEncryptor;
import java.io.Console;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The {@code javacrypt} command line, the main class of the library jar.
 *
 * <pre>
 * java -jar javacrypt.jar encrypt       -p &lt;password&gt; -v &lt;value&gt; [--no-prefix] [--jasypt | --jasypt-strong]
 * java -jar javacrypt.jar decrypt       -p &lt;password&gt; -v &lt;value&gt;              [--jasypt | --jasypt-strong]
 * java -jar javacrypt.jar encrypt-file  -p &lt;password&gt; -i &lt;in&gt; [-o &lt;out&gt;|-]    [--jasypt | --jasypt-strong]
 * java -jar javacrypt.jar decrypt-file  -p &lt;password&gt; -i &lt;in&gt; [-o &lt;out&gt;|-]    [--jasypt | --jasypt-strong]
 * java -jar javacrypt.jar version | help
 * </pre>
 *
 * <p>It mirrors {@code gocrypt-cli} and {@code rustcrypt}, so the same commands work across the
 * family. The password may also come from the {@code JAVACRYPT_PASSWORD} environment variable.
 * The exit status is 0 on success and 1 on any error.
 */
public final class Main {

    private static final String ENV_PASSWORD = "JAVACRYPT_PASSWORD";

    /** A comment line: {@code #} after optional Unicode white space, as Go's {@code TrimSpace} sees it. */
    private static final Pattern COMMENT = Pattern.compile("\\p{IsWhite_Space}*#");

    private static final String USAGE = String.join("\n",
            "javacrypt - Jasypt-like encryption for Java configurations",
            "",
            "Usage:",
            "  java -jar javacrypt.jar <command> [options]",
            "",
            "Commands:",
            "  encrypt       Encrypt a single value",
            "  decrypt       Decrypt a single value (the ENC(...) wrapper is optional)",
            "  encrypt-file  Encrypt all KEY=VALUE values in a file",
            "  decrypt-file  Decrypt all ENC(...) values in a file",
            "  version       Show version information",
            "  help          Show this help",
            "",
            "Options:",
            "  -p, --password <password>  Encryption password (or set JAVACRYPT_PASSWORD env var)",
            "  -v, --value <value>        Value to encrypt/decrypt",
            "  -i, --input <file>         Input file path",
            "  -o, --output <file>        Output file path (omit or \"-\" for stdout)",
            "      --no-prefix            Don't wrap encrypted value with ENC(...)",
            "      --jasypt               Use the Jasypt-compatible algorithm (PBEWithMD5AndDES)",
            "      --jasypt-strong        Use the family's strong algorithm (PBKDF2 + AES-256-CBC)",
            "",
            "Which mode can be read where:",
            "  (default)        AES-256-GCM. GoCrypt, PyCrypt, NodeCrypt, PHPCrypt, RustCrypt. Not Java Jasypt.",
            "  --jasypt         The whole family, and Java Jasypt itself.",
            "  --jasypt-strong  The whole family. Not Java Jasypt.",
            "  Both sides must use the same mode: an ENC(...) value does not record it.",
            "",
            "Examples:",
            "  # Encrypt a database password",
            "  java -jar javacrypt.jar encrypt -p mySecret -v \"db_password123\"",
            "",
            "  # Decrypt a value",
            "  java -jar javacrypt.jar decrypt -p mySecret -v \"ENC(base64encodedvalue)\"",
            "",
            "  # Encrypt values in a .env file",
            "  java -jar javacrypt.jar encrypt-file -p mySecret -i .env.plain -o .env.encrypted",
            "",
            "  # Decrypt all ENC(...) values in a file",
            "  java -jar javacrypt.jar decrypt-file -p mySecret -i .env.encrypted -o .env.plain",
            "",
            "  # Use Jasypt-compatible encryption (readable by Java Jasypt)",
            "  java -jar javacrypt.jar encrypt -p mySecret -v \"secret\" --jasypt",
            "",
            "Environment Variables:",
            "  JAVACRYPT_PASSWORD  Password for encryption/decryption",
            "",
            "Characters outside ASCII:",
            "  Files are read and written as UTF-8, and so is output that is redirected or piped.",
            "  On Windows, Java receives its arguments in the system code page: characters outside it",
            "  are lost before javacrypt sees them. For such a password use JAVACRYPT_PASSWORD, and for",
            "  such values use encrypt-file and decrypt-file.",
            "",
            "An idea from Fariz (github.com/farizfadian) and made with love by Claude AI (claude.ai)",
            "");

    private Main() {
    }

    /**
     * Runs the command line and exits the JVM with its status.
     *
     * @param args the command and its options
     */
    public static void main(String[] args) {
        Charset charset = outputCharset();
        PrintStream out = printStream(FileDescriptor.out, charset);
        PrintStream err = printStream(FileDescriptor.err, charset);
        int status = run(args, System.getenv(), out, err, ArgumentEncoding.detect());
        out.flush();
        err.flush();
        System.exit(status);
    }

    /**
     * How this JVM received its arguments and environment. On a system whose encoding for them is
     * not Unicode, characters outside that encoding arrive as {@code ?} and cannot be recovered.
     */
    static final class ArgumentEncoding {

        /** Arguments and environment arrive unchanged. */
        static final ArgumentEncoding UNICODE = new ArgumentEncoding(false, false, "UTF-8");

        final boolean argumentsLossy;
        final boolean environmentLossy;
        final String name;

        ArgumentEncoding(boolean argumentsLossy, boolean environmentLossy, String name) {
            this.argumentsLossy = argumentsLossy;
            this.environmentLossy = environmentLossy;
            this.name = name;
        }

        static ArgumentEncoding detect() {
            // The JVM decodes arguments with sun.jnu.encoding: the ANSI code page on Windows, the
            // locale's charset elsewhere. Windows passes the environment as UTF-16; Unix decodes it
            // exactly like the arguments.
            String name = System.getProperty("sun.jnu.encoding");
            if (name == null) {
                return UNICODE;
            }
            String normalized = name.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
            if (normalized.equals("UTF8")) {
                return UNICODE;
            }
            boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
            return new ArgumentEncoding(true, !windows, name);
        }
    }

    /** Runs with the argument encoding of this JVM. Used by embedding code and tests. */
    static int run(String[] args, Map<String, String> env, PrintStream out, PrintStream err) {
        return run(args, env, out, err, ArgumentEncoding.detect());
    }

    static int run(String[] args, Map<String, String> env, PrintStream out, PrintStream err,
            ArgumentEncoding encoding) {
        if (args.length == 0) {
            err.print(USAGE);
            return 1;
        }
        String command = args[0];
        switch (command) {
            case "encrypt":
            case "decrypt":
            case "encrypt-file":
            case "decrypt-file":
                try {
                    return runCommand(command, args, env, out, err, encoding);
                } catch (Failure failure) {
                    err.print(failure.getMessage() + "\n");
                    return 1;
                }
            case "version":
            case "--version":
            case "-V":
            case "-v":
                out.print("javacrypt version " + JavaCrypt.version() + "\n");
                return 0;
            case "help":
            case "--help":
            case "-h":
                out.print(USAGE);
                return 0;
            default:
                err.print("Unknown command: " + command + "\n" + USAGE);
                return 1;
        }
    }

    /** A user-facing error: the message is printed to stderr as it is and the exit status is 1. */
    private static final class Failure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Failure(String message) {
            super(message);
        }
    }

    private static final class Options {
        String password;
        String value;
        String input;
        String output;
        boolean noPrefix;
        boolean jasypt;
        boolean jasyptStrong;
        boolean help;
    }

    private static int runCommand(String command, String[] args, Map<String, String> env, PrintStream out,
            PrintStream err, ArgumentEncoding encoding) {
        boolean fileCommand = command.endsWith("-file");
        Options options = parse(command, fileCommand, args);
        if (options.help) {
            out.print(USAGE);
            return 0;
        }
        if (options.jasypt && options.jasyptStrong) {
            throw new Failure("Error: --jasypt cannot be used with --jasypt-strong");
        }

        boolean passwordFromArguments = options.password != null && !options.password.isEmpty();
        String password = passwordFromArguments ? options.password : env.get(ENV_PASSWORD);
        if (password == null || password.isEmpty()) {
            throw new Failure("Error: password is required (-p or " + ENV_PASSWORD + ")");
        }
        if (fileCommand) {
            if (options.input == null || options.input.isEmpty()) {
                throw new Failure("Error: input file is required (-i)");
            }
        } else if (options.value == null || options.value.isEmpty()) {
            throw new Failure("Error: value is required (-v)");
        }

        warnAboutLossyInput(command, options, password, passwordFromArguments, encoding, err);

        StringEncryptor encryptor;
        try {
            if (options.jasypt) {
                encryptor = new JasyptEncryptor(password);
            } else if (options.jasyptStrong) {
                encryptor = new JasyptStrongEncryptor(password);
            } else {
                encryptor = new Encryptor(password);
            }
        } catch (JavaCryptException e) {
            throw new Failure("Error: " + e.getMessage());
        }

        switch (command) {
            case "encrypt":
                out.print(library(() -> options.noPrefix
                        ? encryptor.encrypt(options.value)
                        : encryptor.encryptWithPrefix(options.value)) + "\n");
                return 0;
            case "decrypt":
                out.print(library(() -> JavaCrypt.isEncrypted(options.value)
                        ? encryptor.decryptPrefixed(options.value)
                        : encryptor.decrypt(options.value)) + "\n");
                return 0;
            case "encrypt-file":
                processFile(options, out, line -> encryptLine(encryptor, line));
                return 0;
            default:
                processFile(options, out, encryptor::decryptAllInStringLossy);
                return 0;
        }
    }

    private interface Action {
        String run();
    }

    /** Runs a library call and reports its error the way gocrypt-cli does: {@code Error: <message>}. */
    private static String library(Action action) {
        try {
            return action.run();
        } catch (JavaCryptException e) {
            throw new Failure("Error: " + e.getMessage());
        }
    }

    // ── argument parsing ──────────────────────────────────────────────────────

    private static Options parse(String command, boolean fileCommand, String[] args) {
        Options options = new Options();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            String name = arg;
            String inline = null;
            int equals = arg.indexOf('=');
            if (arg.startsWith("-") && equals > 0) {
                name = arg.substring(0, equals);
                inline = arg.substring(equals + 1);
            }
            switch (name) {
                case "-h":
                case "--help":
                    options.help = true;
                    return options;
                case "-p":
                case "--password":
                    options.password = inline != null ? inline : next(args, ++i, name);
                    break;
                case "--jasypt":
                    options.jasypt = flag(name, inline);
                    break;
                case "--jasypt-strong":
                    options.jasyptStrong = flag(name, inline);
                    break;
                case "-v":
                case "--value":
                    requireOption(!fileCommand, name);
                    options.value = inline != null ? inline : next(args, ++i, name);
                    break;
                case "--no-prefix":
                    requireOption(command.equals("encrypt"), name);
                    options.noPrefix = flag(name, inline);
                    break;
                case "-i":
                case "--input":
                    requireOption(fileCommand, name);
                    options.input = inline != null ? inline : next(args, ++i, name);
                    break;
                case "-o":
                case "--output":
                    requireOption(fileCommand, name);
                    options.output = inline != null ? inline : next(args, ++i, name);
                    break;
                default:
                    if (arg.startsWith("-") && arg.length() > 1) {
                        throw new Failure("Error: unknown option: " + name);
                    }
                    throw new Failure("Error: unexpected argument: " + arg);
            }
        }
        return options;
    }

    /** The argument after an option is always its value, even if it starts with a dash. */
    private static String next(String[] args, int index, String name) {
        if (index >= args.length) {
            throw new Failure("Error: option " + name + " requires a value");
        }
        return args[index];
    }

    private static boolean flag(String name, String inline) {
        if (inline != null) {
            throw new Failure("Error: option " + name + " does not take a value");
        }
        return true;
    }

    private static void requireOption(boolean valid, String name) {
        if (!valid) {
            throw new Failure("Error: unknown option: " + name);
        }
    }

    // ── arguments the platform may have damaged ───────────────────────────────

    private static void warnAboutLossyInput(String command, Options options, String password,
            boolean passwordFromArguments, ArgumentEncoding encoding, PrintStream err) {
        boolean passwordLossy = passwordFromArguments ? encoding.argumentsLossy : encoding.environmentLossy;
        if (passwordLossy && password.indexOf('?') >= 0) {
            String source = passwordFromArguments ? "the password given with -p" : ENV_PASSWORD;
            String advice = passwordFromArguments && !encoding.environmentLossy
                    ? "set " + ENV_PASSWORD + " instead, which is not affected."
                    : "use a UTF-8 locale.";
            err.print("Warning: " + source + " contains '?'. This Java runtime receives it as " + encoding.name
                    + ", and characters outside that encoding arrive as '?'. If the real password has such"
                    + " characters, " + advice + "\n");
        }
        // Only a plaintext can be damaged: the value of decrypt is base64.
        if (command.equals("encrypt") && encoding.argumentsLossy && options.value.indexOf('?') >= 0) {
            err.print("Warning: the value given with -v contains '?'. This Java runtime receives arguments as "
                    + encoding.name + ", and characters outside that encoding arrive as '?'. If the real value"
                    + " has such characters, put it in a UTF-8 file and use encrypt-file.\n");
        }
    }

    // ── files ─────────────────────────────────────────────────────────────────

    private interface LineTransform {
        String apply(String line);
    }

    /**
     * Applies {@code transform} to every line of the input file and writes the result to the
     * output file, or to stdout when no output (or {@code -}) is given.
     *
     * <p>The whole input is read and transformed before anything is written, so an error leaves no
     * half-written file and the input may be overwritten in place. Lines are written with a line
     * feed on every platform, like the other CLIs of the family do.
     */
    private static void processFile(Options options, PrintStream out, LineTransform transform) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(Paths.get(options.input));
        } catch (IOException | RuntimeException e) {
            throw new Failure("Error opening input file: " + describe(e));
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new Failure("Error reading file: " + options.input + " is not valid UTF-8");
        }

        StringBuilder result = new StringBuilder(text.length() + 64);
        for (String line : lines(text)) {
            result.append(transform.apply(line)).append('\n');
        }

        if (options.output == null || options.output.isEmpty() || options.output.equals("-")) {
            out.print(result);
            return;
        }
        try {
            Files.write(Paths.get(options.output), result.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            throw new Failure("Error creating output file: " + describe(e));
        }
    }

    /**
     * Splits text the way Go's line scanner does: at each line feed, dropping one carriage return
     * before it. A final line without a line end counts; a final line end adds no empty line.
     */
    private static List<String> lines(String text) {
        List<String> lines = new ArrayList<>();
        int start = 0;
        while (start < text.length()) {
            int end = text.indexOf('\n', start);
            int next = end < 0 ? text.length() : end + 1;
            if (end < 0) {
                end = text.length();
            }
            if (end > start && text.charAt(end - 1) == '\r') {
                end--;
            }
            lines.add(text.substring(start, end));
            start = next;
        }
        return lines;
    }

    /**
     * The {@code encrypt-file} rule of gocrypt-cli: in a {@code KEY=VALUE} line whose trimmed form
     * does not start with {@code #}, the value (with surrounding quotes removed) is encrypted,
     * unless it is empty or already {@code ENC(...)}. Every other line is kept as it is.
     */
    private static String encryptLine(StringEncryptor encryptor, String line) {
        int equals = line.indexOf('=');
        if (equals >= 0 && !COMMENT.matcher(line).lookingAt()) {
            String key = line.substring(0, equals);
            String value = trimQuotes(line.substring(equals + 1));
            if (!value.isEmpty() && !JavaCrypt.isEncrypted(value)) {
                try {
                    return key + "=" + encryptor.encryptWithPrefix(value);
                } catch (JavaCryptException e) {
                    throw new Failure("Error encrypting " + key + ": " + e.getMessage());
                }
            }
        }
        return line;
    }

    private static String trimQuotes(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isQuote(s.charAt(start))) {
            start++;
        }
        while (end > start && isQuote(s.charAt(end - 1))) {
            end--;
        }
        return s.substring(start, end);
    }

    private static boolean isQuote(char c) {
        return c == '"' || c == '\'';
    }

    private static String describe(Exception e) {
        if (e instanceof java.nio.file.NoSuchFileException) {
            return e.getMessage() + ": no such file";
        }
        return e.toString();
    }

    // ── output encoding ───────────────────────────────────────────────────────

    /**
     * UTF-8, unless stdout is an interactive console, where the console's own charset is used so
     * that text is displayed correctly.
     *
     * <p>Go and Rust programs write UTF-8 to pipes and files; a JVM would write the platform
     * charset there (a legacy code page on Windows), which the next program in a pipeline could not
     * read. So redirected output is always UTF-8.
     */
    private static Charset outputCharset() {
        Console console = System.console();
        if (console == null || !isTerminal(console)) {
            return StandardCharsets.UTF_8;
        }
        try {
            // Console.charset() exists since Java 17.
            Object charset = Console.class.getMethod("charset").invoke(console);
            if (charset instanceof Charset) {
                return (Charset) charset;
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            // older Java: fall through
        }
        String name = System.getProperty("sun.stdout.encoding");
        try {
            return name != null ? Charset.forName(name) : Charset.defaultCharset();
        } catch (RuntimeException e) {
            return Charset.defaultCharset();
        }
    }

    /** Since Java 22 a Console can exist without a terminal; {@code isTerminal()} tells them apart. */
    private static boolean isTerminal(Console console) {
        try {
            return Boolean.TRUE.equals(Console.class.getMethod("isTerminal").invoke(console));
        } catch (ReflectiveOperationException | RuntimeException e) {
            return true;
        }
    }

    private static PrintStream printStream(FileDescriptor descriptor, Charset charset) {
        try {
            return new PrintStream(new FileOutputStream(descriptor), false, charset.name());
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
