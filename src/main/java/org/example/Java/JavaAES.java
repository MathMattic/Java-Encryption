package org.example.Java;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;

public class JavaAES { // TODO add compression step

    private static final int IV_SIZE = 12;  // Initialization Vector size in bytes for the GCM. (96 bits)
    private static final int TAG_LENGTH = 128; // Authentication tag size in bits for the GCM. (128 bits)
    private static final int ITERATION_COUNT = 65536; // how many times to run PBKDF2 hashing algorithm. (2^16)
    private static final int KEY_LENGTH = 256; // in bits. this will determine if its AES128, AES256.
    private SecretKey secretKey;
    private final SecureRandom random = new SecureRandom();

    public SecretKey generatePasswordAESKey(String password, String salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512"); // Password-Based Key Derivation Function that internally uses a cryptographic hash function (HMAC-SHA512).
        SecretKey tmp = factory.generateSecret(spec); // generate temp key material derived from the PBKDF2 password.
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES"); // create AES key from the temp key.
        return secretKey;
    }

    public SecretKey generateRandomizedAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_LENGTH, random);
        secretKey = keyGen.generateKey();
        return secretKey;
    }

    public SecretKey getKey() {
        return secretKey;
    }

    public void setKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public void saveKey(String keyName) throws IOException {
        Files.write(Paths.get(keyName), secretKey.getEncoded());
    }

    public SecretKey loadKey(String keyFilePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        return new SecretKeySpec(keyBytes, "AES");
    }

    public void encryptFile(String inputFileName, String encryptedFileName) throws Exception {
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes); // new random IV for each encryption use
        GCMParameterSpec iv = new GCMParameterSpec(TAG_LENGTH, ivBytes);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // Galois/Counter Mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        processFile(cipher, inputFileName, encryptedFileName, ivBytes);
    }

    public void decryptFile(String encryptedFileName, String outputFileName) throws Exception {
        try (FileInputStream fis = new FileInputStream(encryptedFileName)) {
            byte[] ivBytes = new byte[IV_SIZE];
            int bytesRead = fis.read(ivBytes);
            if (bytesRead != IV_SIZE)
                throw new IOException("Failed to load IV from encrypted file. Bytes read were: " + bytesRead + " expected: " + IV_SIZE);
            GCMParameterSpec iv = new GCMParameterSpec(TAG_LENGTH, ivBytes);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            processFile(cipher, encryptedFileName, outputFileName, null);
        }
    }

    private static void processFile(Cipher cipher, String inputFileName, String outputFileName, byte[] ivBytes) throws IOException, GeneralSecurityException {
        try (FileInputStream fis = new FileInputStream(inputFileName); FileOutputStream fos = new FileOutputStream(outputFileName)) {
            if (ivBytes != null) { // if not null, do encryption mode
                fos.write(ivBytes);
            } else {
                long byteSkipped = fis.skip(IV_SIZE);
                if (byteSkipped != IV_SIZE)
                    throw new IOException("Failed to skip IV bytes. Bytes skipped were: " + byteSkipped + " expected: " + IV_SIZE);
            }
            byte[] inBuffer = new byte[4096];
            byte[] outBuffer;
            int bytesRead;
            while ((bytesRead = fis.read(inBuffer)) != -1) {
                outBuffer = cipher.update(inBuffer, 0, bytesRead);
                if (outBuffer != null) {
                    fos.write(outBuffer);
                }
            }
            outBuffer = cipher.doFinal();
            if (outBuffer != null) {
                fos.write(outBuffer);
            }
        }
    }

}
