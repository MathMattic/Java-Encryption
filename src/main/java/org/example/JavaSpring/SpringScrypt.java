package org.example.JavaSpring;

import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class SpringScrypt {
    public static void main(String[] args) {
        // password hashing example with Spring and Scrypt.

        int cpuCost = 16384; // (N) the CPU "cost" of the algorithm (2^14)
        int memoryCost = 8; // (r) the memory cost of the algorithm (128 * r * p)
        int parallelization = 1; // (p) how many threads to run the algorithm on
        int keyLength = 32; // the key length for the algorithm in bytes (256bit)
        int saltLength = 64; // the salt length for the algorithm in bytes (512bit)

        SCryptPasswordEncoder passwordEncoder = new SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);

        String rawPassword = "myPassword123";

        String hashedPassword = passwordEncoder.encode(rawPassword);

        System.out.println("Hashed Password: " + hashedPassword);

        // Verify the password
        boolean isMatch = passwordEncoder.matches(rawPassword, hashedPassword);
        System.out.println("Password matches: " + isMatch);
    }
}
