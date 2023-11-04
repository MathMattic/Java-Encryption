package org.example.Java;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class JavaAES {

    private static final int IV_SIZE = 16;  // Initialization Vector size in bytes for the CBC.
    private static final int ITERATION_COUNT = 65536; // how many times to run PBKDF2 hashing algorithm.
    private static final int KEY_LENGTH = 256; // in bits. this will determine if its AES128, AES256 etc.
    private SecretKey secretKey;
    private final SecureRandom random = new SecureRandom();

    public void generatePasswordAESKey(String password, String salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); // Password-Based Key Derivation Function that internally uses a cryptographic hash function (HMAC-SHA256).
        SecretKey tmp = factory.generateSecret(spec); // generate temp key derived from the PBKDF2 password.
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES"); // create AES key from the temp key.
    }

    public void generateRandomizedAESKey(String keyName) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_LENGTH, random);
        secretKey = keyGen.generateKey();
        saveKeyAsFile(keyName);
    }

    public void saveKeyAsFile(String keyName) throws Exception {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH:mm:ss");
        int dotIndex = keyName.lastIndexOf('.');
        String extension = dotIndex == -1 ? ".key" : keyName.substring(dotIndex);
        String name = dotIndex == -1 ? keyName : keyName.substring(0, dotIndex);
        String newKeyName = name + "-" + now.format(formatter) + extension;
        Files.write(Paths.get(newKeyName), secretKey.getEncoded());
    }

    public void loadKeyFromFile(String keyFilePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    public void encryptFile(String inputFileName, String encryptedFileName) throws Exception {
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes); // new random IV for each encryption use
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING"); // cypher block chaining
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        processFile(cipher, inputFileName, encryptedFileName, ivBytes);
    }

    public void decryptFile(String encryptedFileName, String outputFileName) throws Exception {
        try (FileInputStream fis = new FileInputStream(encryptedFileName)) {
            byte[] ivBytes = new byte[IV_SIZE];
            int bytesRead = fis.read(ivBytes);
            if (bytesRead != IV_SIZE)
                throw new IOException("Failed to load IV from encrypted file. Bytes read were: " + bytesRead + " expected: " + IV_SIZE);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            processFile(cipher, encryptedFileName, outputFileName, null);
        }
    }

    private static void processFile(Cipher cipher, String inputFileName, String outputFileName, byte[] ivBytes) throws IOException, GeneralSecurityException {
        try (FileInputStream fis = new FileInputStream(inputFileName); FileOutputStream fos = new FileOutputStream(outputFileName)) {
            if (ivBytes != null) {
                fos.write(ivBytes);
            } else {
                fis.skip(IV_SIZE); // Ignore any IDE warning. You need this step.
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


