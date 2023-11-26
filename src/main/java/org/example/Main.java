package org.example;

import org.example.Java.JavaUtil;
import org.example.Java.JavaRSA;

public class Main {
    public static void main(String[] args) throws Exception {

        JavaRSA makeRSAKeys = new JavaRSA();
        makeRSAKeys.RSAKeyPairGenerator("publickey.pem", "privatekey.pem");

        JavaUtil javaUtil = new JavaUtil();
        javaUtil.encryptMessage(makeRSAKeys.getPublicKey(), "aeskey1.txt", "test.txt", "encrypted.txt");

        javaUtil.decryptMessage(makeRSAKeys.getPrivateKey(), "aeskey1.txt", "encrypted.txt", "decrypted.txt");

    }
}