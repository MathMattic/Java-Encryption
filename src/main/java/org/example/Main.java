package org.example;


import org.example.Java.JavaAES;

public class Main {
    public static void main(String[] args) throws Exception {

        JavaAES AESPasswordEncryption = new JavaAES();
        AESPasswordEncryption.generatePasswordAESKey("pass", "123");
//        AESPasswordEncryption.saveKeyAsFile("keyfile.key");
//        AESPasswordEncryption.loadKeyFromFile("keyfile.key");
        AESPasswordEncryption.encryptFile("test.txt", "testenc.txt");
        AESPasswordEncryption.decryptFile("testenc.txt", "testdec.txt");



    }
}