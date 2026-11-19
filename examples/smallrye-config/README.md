# JavaCrypt with Quarkus / SmallRye Config

Quarkus reads its configuration through [SmallRye Config](https://smallrye.io/smallrye-config/).
This example is a `ConfigSourceInterceptor` that decrypts every `ENC(...)` value with JavaCrypt,
whichever source the value comes from (`application.properties`, a `.env` file, environment
variables, system properties).

It is an example to copy, not a published artifact.

## Use it in your application

1. Add JavaCrypt to the application:

   ```xml
   <dependency>
     <groupId>io.github.farizfadian</groupId>
     <artifactId>javacrypt</artifactId>
     <version>1.0.0</version>
   </dependency>
   ```

2. Copy [`JavaCryptConfigInterceptor.java`](src/main/java/io/github/farizfadian/javacrypt/examples/smallrye/JavaCryptConfigInterceptor.java)
   into your sources (change the package to yours).

3. Register it. Create `src/main/resources/META-INF/services/io.smallrye.config.ConfigSourceInterceptor`
   containing the fully qualified class name:

   ```
   com.example.config.JavaCryptConfigInterceptor
   ```

4. Encrypt a value with the CLI and put the result in your configuration:

   ```bash
   java -jar javacrypt-1.0.0.jar encrypt -p "$JAVACRYPT_PASSWORD" -v "s3cr3t"
   ```

   ```properties
   # application.properties
   db.password=ENC(...)
   ```

5. Start the application with the password in the environment:

   ```bash
   export JAVACRYPT_PASSWORD=...
   ```

The interceptor reads the password from the property `javacrypt.password`; SmallRye maps that name
to the environment variable `JAVACRYPT_PASSWORD`. A missing password is only an error when an
encrypted value is actually read, and the message names the property, never its value.

## Which mode

The interceptor uses `Encryptor` (AES-256-GCM): the mode every member of the family reads, with
integrity protection. If the values were written by **Java Jasypt**, return a `JasyptEncryptor`
from `encryptor(String)` instead. One application uses one mode: an `ENC(...)` value does not
record how it was encrypted.

## What was tested

`JavaCryptConfigInterceptorTest` builds a real `SmallRyeConfig` with the interceptor discovered
through `META-INF/services`, and checks decryption, untouched plain values, expression expansion,
the `JAVACRYPT_PASSWORD` mapping, a wrong password, a missing password and a value in another mode.
CI runs it with SmallRye Config 4.2.2 (Quarkus 4.0) and 3.18.3 (Quarkus 3.x), on Java 25.

Not tested: a running Quarkus application, and native images.

## Build

```bash
# from the repository root
./mvnw -DskipTests install
./mvnw -f examples/smallrye-config/pom.xml verify
```
