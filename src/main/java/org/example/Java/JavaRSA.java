package org.example.Java;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

public class JavaRSA {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private static final String ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 4096;

    public void RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_LENGTH);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    public void savePublicKeyToFile(String filename) throws Exception {
        String publicKeyPEM = convertToPemFormat(publicKey.getEncoded(), "PUBLIC KEY");
        Files.write(Paths.get(filename), publicKeyPEM.getBytes());
    }

    public void savePrivateKeyToFile(String filename) throws Exception {
        String privateKeyPEM = convertToPemFormat(privateKey.getEncoded(), "PRIVATE KEY");
        Files.write(Paths.get(filename), privateKeyPEM.getBytes());
    }

    private String convertToPemFormat(byte[] keyBytes, String keyType) {
        String encoded = Base64.getEncoder().encodeToString(keyBytes);
        return "-----BEGIN " + keyType + "-----\n" + encoded + "\n-----END " + keyType + "-----";
    }

}
