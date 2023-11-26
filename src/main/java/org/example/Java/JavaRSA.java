package org.example.Java;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JavaRSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private static final String ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 4096;

    public void RSAKeyPairGenerator(String publicKeyName, String privateKeyName) throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_LENGTH);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        savePublicKeyToFile(publicKeyName);
        savePrivateKeyToFile(privateKeyName);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey savePublicKeyToFile(String filename) throws IOException {
        String publicKeyPEM = convertToPemFormat(publicKey.getEncoded(), "PUBLIC KEY");
        Files.write(Paths.get(filename), publicKeyPEM.getBytes());
        return publicKey;
    }

    public PrivateKey savePrivateKeyToFile(String filename) throws IOException {
        String privateKeyPEM = convertToPemFormat(privateKey.getEncoded(), "PRIVATE KEY");
        Files.write(Paths.get(filename), privateKeyPEM.getBytes());
        return privateKey;
    }

//    public void loadPublicKeyFromFile(String) {
//
//    }

    private String convertToPemFormat(byte[] keyBytes, String keyType) {
        String encoded = Base64.getEncoder().encodeToString(keyBytes);
        return "-----BEGIN " + keyType + "-----\n" + encoded + "\n-----END " + keyType + "-----";
    }

    public static PublicKey loadPublicKey(String filename) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        keyPEM = keyPEM.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        keyPEM = keyPEM.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePrivate(spec);

    }

}
