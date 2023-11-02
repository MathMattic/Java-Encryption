package org.example;

import org.example.Java.JavaAES;

public class Main {
    public static void main(String[] args) throws Exception {

        JavaAES AESPasswordEncryption = new JavaAES();
        AESPasswordEncryption.generatePasswordAESKey("pass", "123");
        AESPasswordEncryption.encryptFile("test.txt", "testenc.txt");
        AESPasswordEncryption.decryptFile("testenc.txt", "testdec.txt");


        JavaAES AESRandomEncryption = new JavaAES();
        AESRandomEncryption.generateRandomizedAESKey("random.key");
        AESRandomEncryption.loadKeyFromFile("random.key");
        AESRandomEncryption.encryptFile("test.txt", "testenc.txt");
        AESRandomEncryption.decryptFile("testenc.txt", "testdec.txt");


    }
}