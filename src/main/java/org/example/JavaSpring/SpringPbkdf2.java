package org.example.JavaSpring;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;

public class SpringPbkdf2 {
    public static void main(String[] args) {
        // password hashing example with Spring and pbkdf2.

        CharSequence secret = "secret"; // "pepper" fixed value across all password hashing for more security
        int saltLength = 16;
        int iterations = 10000;
        SecretKeyFactoryAlgorithm algorithm = SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512;

        Pbkdf2PasswordEncoder passwordEncoder = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, algorithm);

        String rawPassword = "myPassword123";

        String hashedPassword = passwordEncoder.encode(rawPassword);

        System.out.println("Hashed Password: " + hashedPassword);

        // Verify the password
        boolean isMatch = passwordEncoder.matches(rawPassword, hashedPassword);
        System.out.println("Password matches: " + isMatch);
    }
}
