package org.example;

import org.example.Java.JavaAES;
import org.example.Java.JavaRSA;

public class Main {
    public static void main(String[] args) throws Exception {

//        JavaAES AESPasswordEncryption = new JavaAES();
//        AESPasswordEncryption.generatePasswordAESKey("password", "salt");
//        AESPasswordEncryption.encryptFile("test.txt", "testenc.txt");
//        AESPasswordEncryption.decryptFile("testenc.txt", "testdec.txt");


//        JavaAES AESRandomEncryption = new JavaAES();
//        AESRandomEncryption.generateRandomizedAESKey("random");
//        AESRandomEncryption.convertToBase64("random.key", "r.key");
//        AESRandomEncryption.convertToBase64("random", "randomb64");
//        AESRandomEncryption.loadKeyFromFile("random.key");
//        AESRandomEncryption.encryptFile("test.txt", "testenc.txt");
//        AESRandomEncryption.decryptFile("testenc.txt", "testdec.txt");

        JavaRSA rsakeypair = new JavaRSA();
        rsakeypair.RSAKeyPairGenerator();
        rsakeypair.savePublicKeyToFile("public.pem");
        rsakeypair.savePrivateKeyToFile("private.pem");
    }
}