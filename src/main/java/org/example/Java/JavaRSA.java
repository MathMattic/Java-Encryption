package org.example.Java;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class JavaRSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private static final String ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 4096;

    public KeyPair RSAKeyPairGenerator(String publicKeyName, String privateKeyName) throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_LENGTH);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        savePublicKey(publicKeyName);
        savePrivateKey(privateKeyName);
        return pair;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void savePublicKey(String filename) throws IOException {
        String publicKeyPEM = convertToPemFormat(publicKey.getEncoded(), "PUBLIC KEY");
        Files.write(Paths.get(filename), publicKeyPEM.getBytes());
    }

    public void savePrivateKey(String filename) throws IOException {
        String privateKeyPEM = convertToPemFormat(privateKey.getEncoded(), "PRIVATE KEY");
        Files.write(Paths.get(filename), privateKeyPEM.getBytes());
    }

    private String convertToPemFormat(byte[] keyBytes, String keyType) {
        String encoded = Base64.getEncoder().encodeToString(keyBytes);
        return "-----BEGIN " + keyType + "-----\n" + encoded + "\n-----END " + keyType + "-----";
    }

    public PublicKey loadPublicKey(String filename) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        keyPEM = keyPEM.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePublic(spec);
    }

    public PrivateKey loadPrivateKey(String filename) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        keyPEM = keyPEM.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePrivate(spec);
    }

    public byte[] encryptAESKey(PublicKey publicKey, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        LocalDateTime now = LocalDateTime.now();
        String formattedTimestamp = now.format(DateTimeFormatter.ofPattern("MM-dd-HHmmss"));
        Files.write(Paths.get(formattedTimestamp + ".key"), encryptedKey);
        return encryptedKey;
    }

    public SecretKey decryptAESKey(PrivateKey privateKey, byte[] encryptedAESKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(encryptedAESKey);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }
}
