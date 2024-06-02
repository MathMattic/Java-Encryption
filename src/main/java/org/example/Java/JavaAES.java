package org.example.Java;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * JavaAES class provides methods to generate AES keys, encrypt and decrypt files, and encrypt and decrypt text.
 * Generate Password based keys, or random bit keys
 */
public class JavaAES {

    private static final int IV_SIZE = 12;  // Initialization Vector size in bytes for the GCM. (96 bits)
    private static final int TAG_LENGTH = 128; // Authentication tag size in bits for the GCM. (128 bits)
    private static final int ITERATION_COUNT = 65536; // how many times to run PBKDF2 hashing algorithm. (2^16)
    private final int KEY_LENGTH = 256; // AES key length in bits.
    private SecretKey secretKey;
    private final SecureRandom random = new SecureRandom();
    private byte[] salt = new byte[32];

    // Generate a new AES key from a password.
    // The salt is generated randomly and stored in the class.
    public SecretKey generatePasswordAESKey(String password) throws Exception {
        random.nextBytes(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        SecretKey tmp = factory.generateSecret(spec); // generate temp key material derived from the PBKDF2 password.
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES"); // create AES key from the temp key.
        return secretKey;
    }

    // Regenerate the AES key from a password and a salt.
    // The salt should be provided as a Base64 encoded string.
    public SecretKey reGeneratePasswordAESKey(String password, String salt) throws Exception {
        this.salt = Base64.getDecoder().decode(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), this.salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        SecretKey tmp = factory.generateSecret(spec); // generate temp key material derived from the PBKDF2 password.
        secretKey = new SecretKeySpec(tmp.getEncoded(), "AES"); // create AES key from the temp key.
        return secretKey;
    }

    // Generate a new AES key using a cryptographically strong random bit generator.
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

    public String getSalt() {
        return Base64.getEncoder().encodeToString(salt);
    }

    // Save an AES key to a file on disk.
    public void saveKey(String keyName) throws IOException {
        Files.write(Paths.get(keyName), secretKey.getEncoded());
    }

    // Load an AES key from a file on disk.
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

    public String encryptText(String plainText) throws Exception {
        byte[] ivBytes = new byte[IV_SIZE];
        random.nextBytes(ivBytes);
        GCMParameterSpec ivSpec = new GCMParameterSpec(TAG_LENGTH, ivBytes);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Convert plain text into bytes, assuming UTF-8 encoding
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(plainTextBytes);

        // Combine IV and encrypted data using ByteBuffer
        ByteBuffer byteBuffer = ByteBuffer.allocate(ivBytes.length + encryptedBytes.length);
        byteBuffer.put(ivBytes);
        byteBuffer.put(encryptedBytes);
        byte[] ivAndEncrypted = byteBuffer.array();

        // Convert to Base64 string for easy handling
        return Base64.getEncoder().encodeToString(ivAndEncrypted);
    }

    public String decryptText(String cipherText) throws Exception {
        // Convert Base64 string back to bytes
        byte[] ivAndEncrypted = Base64.getDecoder().decode(cipherText);

        // Separate IV and encrypted data using ByteBuffer
        ByteBuffer byteBuffer = ByteBuffer.wrap(ivAndEncrypted);
        byte[] ivBytes = new byte[IV_SIZE];
        byte[] encryptedBytes = new byte[ivAndEncrypted.length - IV_SIZE];
        byteBuffer.get(ivBytes);
        byteBuffer.get(encryptedBytes);

        GCMParameterSpec ivSpec = new GCMParameterSpec(TAG_LENGTH, ivBytes);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the data
        byte[] plainTextBytes = cipher.doFinal(encryptedBytes);

        // Convert bytes back to string, assuming UTF-8 encoding
        return new String(plainTextBytes, StandardCharsets.UTF_8);
    }

}
