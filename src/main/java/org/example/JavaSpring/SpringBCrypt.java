package org.example.JavaSpring;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SpringBCrypt {
    public static void main(String[] args) {
        // in Bcrypt, the salt is 128 bits
        // It is then base64 encoded and will be a 22 length string

        // 10 represents 2^10
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10); // 10 is default and can be omitted

        String rawPassword = "myPassword123";

        String hashedPassword = passwordEncoder.encode(rawPassword);

        System.out.println("Hashed Password: " + hashedPassword);
        System.out.println("Here, $2a$ is the version, $10$ is the strength (work factor), and " + hashedPassword.substring(7, 30) + " is the salt.");

        // Verify the password
        boolean isMatch = passwordEncoder.matches(rawPassword, hashedPassword);
        System.out.println("Password matches: " + isMatch);
    }
}

