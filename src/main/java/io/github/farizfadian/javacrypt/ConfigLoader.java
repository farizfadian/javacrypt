package io.github.farizfadian.javacrypt;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

/**
 * Loads configuration files and decrypts every {@code ENC(...)} value in them.
 *
 * <pre>{@code
 * ConfigLoader loader = new ConfigLoader(System.getenv("JAVACRYPT_PASSWORD"));
 * Map<String, String> env = loader.loadEnvFile(".env");
 * String dbPassword = env.get("DB_PASS");
 * }</pre>
 *
 * <p>{@link #ConfigLoader(String)} uses {@link Encryptor} (AES-256-GCM), like the loaders of the
 * other members of the family. For a file whose values were written by Java Jasypt, pass a
 * {@link JasyptEncryptor}: {@code new ConfigLoader(new JasyptEncryptor(password))}.
 *
 * <p>A value that looks encrypted but cannot be decrypted is always an error that names its key.
 * It is never returned as the literal {@code ENC(...)} text.
 *
 * <p>Files are read as UTF-8 (a leading byte order mark is ignored); bytes that are not valid
 * UTF-8 are an error. There is no JSON loader, because this library has no dependencies: parse
 * JSON with the library you already use and call {@link StringEncryptor#decryptPrefixed(String)}
 * on its string values.
 *
 * <p>Instances are immutable and safe to share between threads if the encryptor is.
 */
public final class ConfigLoader {

    private final StringEncryptor encryptor;

    /**
     * Creates a loader that decrypts with {@link Encryptor} and its default parameters.
     *
     * @param password the password, encoded as UTF-8
     * @throws JavaCryptException with {@link ErrorCode#EMPTY_PASSWORD} if the password is null or empty
     */
    public ConfigLoader(String password) {
        this(new Encryptor(password));
    }

    /**
     * Creates a loader that decrypts with the given encryptor.
     *
     * @param encryptor any {@link StringEncryptor}, not {@code null}
     */
    public ConfigLoader(StringEncryptor encryptor) {
        this.encryptor = Objects.requireNonNull(encryptor, "encryptor");
    }

    /**
     * Returns the encryptor this loader decrypts with.
     *
     * @return the encryptor
     */
    public StringEncryptor getEncryptor() {
        return encryptor;
    }

    /**
     * Loads a {@code .env} style file: one {@code KEY=VALUE} per line.
     *
     * <p>Blank lines and lines starting with {@code #} are skipped, as are lines without {@code =}.
     * Keys and values are trimmed, and single or double quotes around a value are removed. If a key
     * occurs twice, the later value wins.
     *
     * @param path the file
     * @return the entries in file order, with every {@code ENC(...)} value decrypted
     * @throws JavaCryptException with {@link ErrorCode#IO} if the file cannot be read, or
     *     {@link ErrorCode#KEY_DECRYPT} if a value cannot be decrypted
     */
    public Map<String, String> loadEnvFile(Path path) {
        return loadKeyValues(path, '=');
    }

    /**
     * Loads a {@code .env} style file. See {@link #loadEnvFile(Path)}.
     *
     * @param path the file
     * @return the entries in file order, with every {@code ENC(...)} value decrypted
     */
    public Map<String, String> loadEnvFile(String path) {
        return loadEnvFile(Paths.get(path));
    }

    /**
     * Loads a simple, flat YAML file: one {@code key: value} per line.
     *
     * <p>This is the same line parser as {@link #loadEnvFile(Path)}, splitting on the first
     * {@code :} instead of {@code =}. It is <strong>not a YAML parser</strong> and has the same
     * limits as the loader of GoCrypt: nesting is flattened (a {@code database:} line gives an entry
     * with an empty value, and its indented children become top-level keys), and lists, multi-line
     * values and trailing comments are not understood. For real YAML documents, parse them with a
     * YAML library and call {@link StringEncryptor#decryptPrefixed(String)} on the string values.
     *
     * @param path the file
     * @return the entries in file order, with every {@code ENC(...)} value decrypted
     * @throws JavaCryptException with {@link ErrorCode#IO} if the file cannot be read, or
     *     {@link ErrorCode#KEY_DECRYPT} if a value cannot be decrypted
     */
    public Map<String, String> loadYaml(Path path) {
        return loadKeyValues(path, ':');
    }

    /**
     * Loads a simple, flat YAML file. See {@link #loadYaml(Path)}.
     *
     * @param path the file
     * @return the entries in file order, with every {@code ENC(...)} value decrypted
     */
    public Map<String, String> loadYaml(String path) {
        return loadYaml(Paths.get(path));
    }

    /**
     * Loads a Java {@code .properties} file, read as UTF-8, and decrypts its {@code ENC(...)} values.
     *
     * <p>The syntax is that of {@link Properties#load(java.io.Reader)}, including its escape rules.
     * Only the charset differs from the classic {@code Properties.load(InputStream)}, which reads
     * ISO-8859-1; use {@link #loadProperties(Path, Charset)} for such a file.
     *
     * @param path the file
     * @return the properties, with every {@code ENC(...)} value decrypted
     * @throws JavaCryptException with {@link ErrorCode#IO} if the file cannot be read, or
     *     {@link ErrorCode#KEY_DECRYPT} if a value cannot be decrypted
     */
    public Properties loadProperties(Path path) {
        return loadProperties(path, StandardCharsets.UTF_8);
    }

    /**
     * Loads a Java {@code .properties} file in the given charset and decrypts its {@code ENC(...)}
     * values.
     *
     * @param path the file
     * @param charset the charset of the file, for example {@link StandardCharsets#ISO_8859_1}
     * @return the properties, with every {@code ENC(...)} value decrypted
     * @throws JavaCryptException with {@link ErrorCode#IO} if the file cannot be read, or
     *     {@link ErrorCode#KEY_DECRYPT} if a value cannot be decrypted
     */
    public Properties loadProperties(Path path, Charset charset) {
        String text = Internal.readText(path, charset);
        Properties properties = new Properties();
        try {
            properties.load(new StringReader(text));
        } catch (IOException | IllegalArgumentException e) {
            // IllegalArgumentException: a malformed \\uXXXX escape.
            throw JavaCryptException.io("failed to read file " + path + ": not a valid properties file", e);
        }
        for (String name : properties.stringPropertyNames()) {
            properties.setProperty(name, decryptIfWrapped(name, properties.getProperty(name)));
        }
        return properties;
    }

    /**
     * Loads a Java {@code .properties} file. See {@link #loadProperties(Path)}.
     *
     * @param path the file
     * @return the properties, with every {@code ENC(...)} value decrypted
     */
    public Properties loadProperties(String path) {
        return loadProperties(Paths.get(path));
    }

    /**
     * Loads a {@code .env} style file with {@link #loadEnvFile(Path)} and sets every entry as a
     * system property.
     *
     * <p>This is the counterpart of {@code setToEnv} in the other members of the family: a Java
     * process cannot change its own environment variables. Nothing is set unless the whole file
     * could be read and decrypted.
     *
     * @param path the file
     * @throws JavaCryptException as {@link #loadEnvFile(Path)}, or {@link ErrorCode#INVALID_PARAMETER}
     *     if a line has an empty name
     */
    public void setToSystemProperties(Path path) {
        Map<String, String> config = loadEnvFile(path);
        if (config.containsKey("")) {
            throw JavaCryptException.invalidParameter("cannot set a system property with an empty name");
        }
        for (Map.Entry<String, String> entry : config.entrySet()) {
            System.setProperty(entry.getKey(), entry.getValue());
        }
    }

    /**
     * Sets every entry of a {@code .env} style file as a system property. See
     * {@link #setToSystemProperties(Path)}.
     *
     * @param path the file
     */
    public void setToSystemProperties(String path) {
        setToSystemProperties(Paths.get(path));
    }

    private Map<String, String> loadKeyValues(Path path, char separator) {
        String text = Internal.readText(path, StandardCharsets.UTF_8);
        Map<String, String> config = new LinkedHashMap<>();
        int start = 0;
        while (start <= text.length()) {
            int end = text.indexOf('\n', start);
            if (end < 0) {
                end = text.length();
            }
            // Trimming also removes the carriage return of a CRLF line end.
            String line = Internal.trimSpace(text.substring(start, end));
            start = end + 1;
            if (line.isEmpty() || line.charAt(0) == '#') {
                continue;
            }
            int split = line.indexOf(separator);
            if (split < 0) {
                continue;
            }
            String key = Internal.trimSpace(line.substring(0, split));
            String value = Internal.trimQuotes(Internal.trimSpace(line.substring(split + 1)));
            config.put(key, decryptIfWrapped(key, value));
        }
        return config;
    }

    private String decryptIfWrapped(String key, String value) {
        if (!JavaCrypt.isEncrypted(value)) {
            return value;
        }
        try {
            return encryptor.decryptPrefixed(value);
        } catch (JavaCryptException e) {
            throw JavaCryptException.keyDecrypt(key, e);
        }
    }
}
