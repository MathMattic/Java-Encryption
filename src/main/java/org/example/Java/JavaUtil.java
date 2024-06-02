package org.example.Java;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class JavaUtil {
    private JavaUtil() {}

    // This method will take 2 strings. One is an existing file to be encrypted. The other is the name of the encrypted file.
    // The function will generate an RSA key pair, generate an AES key, encrypt the file, encrypt the AES key with the RSA public key,
    public static void encryptMessage(String message, String encryptedMessage) throws Exception {

        // Generate an RSA key pair
        JavaRSA rsa = new JavaRSA();
        rsa.RSAKeyPairGenerator("PublicKey.pem", "PrivateKey.pem");

        // Generate the AES key for encryption, and pass the files.
        JavaAES aes = new JavaAES();
        aes.generateRandomizedAESKey();
        aes.encryptFile(message, encryptedMessage);
//        aes.saveKey("AESKey.key");

        // encrypt the AES key with the public RSA key.
        // this will also save the file to the disk.
        rsa.encryptAESKey(rsa.getPublicKey(), aes.getKey());

        // send the user the encrypted text message and the encrypted AES key.
        // the recipient can use their private key to decrypt
        // (AES key could also be prepended to the encrypted message etc.)

        //    Optional Compression :
        //    Before Encrypting: Compress the data using compressData.
        //    After Encrypting: Proceed with your usual encryption routine.
        //    Before Decrypting: Decrypt the data as you normally would.
        //    After Decrypting: Decompress the decrypted data using decompressData.
    }

    // This method loads the encrypted aes key, decrypts it with the private key, and then decrypts the message with the aes key.
    public static void decryptMessage(String encryptedMessage, String decryptedMessage) throws Exception {

        // load the encrypted AES key from disk
        byte[] encryptedAESKeyData = Files.readAllBytes(Paths.get("EncryptedAESKey.key"));

        // Create new instance of RSA class to load the private key and decrypt the AES key.
        JavaRSA rsa = new JavaRSA();
        rsa.setPrivateKey(rsa.loadPrivateKey("PrivateKey.pem"));
        SecretKey decryptedAESKey = rsa.decryptAESKey(rsa.getPrivateKey(), encryptedAESKeyData);

        // Create AES instance and set the now decrypted AES key. and decrypt the message.
        JavaAES aes = new JavaAES();
        aes.setKey(decryptedAESKey);
        aes.decryptFile(encryptedMessage, decryptedMessage);

    }

    public static String convertToBase64(String inputString, String outputString) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(inputString));
        String encodedString = Base64.getEncoder().encodeToString(content);
        Files.writeString(Paths.get(outputString + "Base64"), encodedString);
        return encodedString;
    }

    public static String convertFromBase64(String inputKeyName, String outputKeyName) throws IOException {
        String encodedString = new String(Files.readAllBytes(Paths.get(inputKeyName)));
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
        Files.write(Paths.get(outputKeyName), decodedBytes);
        return encodedString;
    }

    public static String generatePassword(int length) {
        if (length < 16) throw new IllegalArgumentException("Pass must be at least 16 characters.");
        String alphaLower = "abcdefghijklmnopqrstuvwxyz";
        String alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String num = "0123456789";
        String specialChars = "!@#$%&*()_+-=[]?";
        String passChars = alphaLower + alphaUpper + num + specialChars;
        SecureRandom r = new SecureRandom();

        return IntStream.range(0, length)
                .map(i -> passChars.charAt(r.nextInt(passChars.length())))
                .mapToObj(c -> String.valueOf((char) c)).collect(Collectors.joining());
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32]; // 256-bit salt
        random.nextBytes(salt);
        return salt;
    }


    public static void hashSHA3512(String pass, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512"); // fast. dont use for password hashing
        md.update(pass.getBytes(StandardCharsets.UTF_8));
        md.update(salt);
        byte[] hashBytes = md.digest();
        for (byte b : hashBytes) System.out.printf("%02x", b); // %x int in hex format, %02x means 2 digits, with leading 0 if needed.
        System.out.println();
        System.out.println(HexFormat.of().withDelimiter("-").withUpperCase().formatHex(hashBytes));
        System.out.println();
        System.out.println(pass + " " + Arrays.toString(salt));
//        UUID.randomUUID()
    }

    public static byte[] compressData(byte[] data) throws IOException {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DeflaterOutputStream dos = new DeflaterOutputStream(baos, deflater)) {
            dos.write(data);
            return baos.toByteArray();
        }
    }

    public static byte[] decompressData(byte[] data) throws IOException {
        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = iis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    public static void compressFile(String inputFilePath, String outputFilePath) throws IOException {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath);
             DeflaterOutputStream dos = new DeflaterOutputStream(fos, deflater)) {

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void decompressFile(String inputFilePath, String outputFilePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             InflaterInputStream iis = new InflaterInputStream(fis);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = iis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
        }
    }

}
