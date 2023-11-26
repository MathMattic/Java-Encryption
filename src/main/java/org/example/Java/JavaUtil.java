package org.example.Java;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class JavaUtil {

    public void encryptMessage(PublicKey publicKey, String aesKeyName, String message, String encryptedMessage) throws Exception {
        JavaAES aes = new JavaAES();
        // take the public RSA key passed in
        // create a random AES key
        aes.generateRandomizedAESKey();
        // encrypt the message with the AES key
        // encrypt the AES key with the RSA public key
        aes.encryptFile(message, encryptedMessage);
        encryptAESKey(aes.getAESKey(), publicKey, aesKeyName);
    }

    public void decryptMessage(PrivateKey privateKey, String encryptedAESKey, String encryptedMessage, String decryptedMessage) throws Exception {
        JavaAES aes = new JavaAES();
        byte[] aeskey = Files.readAllBytes(Paths.get(encryptedAESKey));
        // take the private RSA passed in
        // take the encrypted AES key and decrypt it with the RSA private key
        SecretKey decryptedAESKey = decryptAESKey(aeskey, privateKey);
        aes.setAESKey(decryptedAESKey);
        aes.decryptFile(encryptedMessage, decryptedMessage);
    }

    private byte[] encryptAESKey(SecretKey aesKey, PublicKey publicKey, String encryptedKeyName) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        Files.write(Paths.get(encryptedKeyName), encryptedKey);
        return encryptedKey;
    }

    public SecretKey decryptAESKey(byte[] encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    public static String convertToBase64(String inputString, String outputString) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(inputString));
        String encodedString = Base64.getEncoder().encodeToString(content);
        Files.writeString(Paths.get(outputString+"Base64"), encodedString);
        return encodedString;
    }

    public static String convertFromBase64(String inputKeyName, String outputKeyName) throws IOException {
        String encodedString = new String(Files.readAllBytes(Paths.get(inputKeyName)));
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
        Files.write(Paths.get(outputKeyName), decodedBytes);
        return encodedString;
    }

}
