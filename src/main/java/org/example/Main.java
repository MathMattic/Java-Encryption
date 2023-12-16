package org.example;

import org.example.Java.JavaAES;
import org.example.Java.JavaRSA;
import javax.crypto.SecretKey;

public class Main {
    public static void main(String[] args) throws Exception {
        // encryption
        JavaRSA rsa = new JavaRSA();
        rsa.RSAKeyPairGenerator("publickey.pem", "privatekey.pem");
        JavaAES aes = new JavaAES();
        aes.generatePasswordAESKey("password", "salt");
        aes.encryptFile("test.txt", "encrypted.txt");
        byte[] encryptedAESKeyData = rsa.encryptAESKey(rsa.getPublicKey(), aes.getKey());

        // decryption
        SecretKey decryptedAESKey = rsa.decryptAESKey(rsa.getPrivateKey(), encryptedAESKeyData);
        aes.setKey(decryptedAESKey);
        aes.decryptFile("encrypted.txt", "decrypted.txt");

    }

}