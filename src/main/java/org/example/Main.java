package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.example.Java.JavaAES;
import org.example.Java.JavaRSA;
import org.example.Java.JavaUtil;
import org.example.JavaBC.BCAES;
import org.example.JavaBC.EllipticCurveKeyPairGenerator;
import org.example.JavaBC.JavaBCUtil;
import org.example.JavaBC.RSAKeyPairGenerator;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Set;

public class Main {
    public static void main(String[] args) throws Exception {
//        Security.addProvider(new BouncyCastleProvider());



//        JavaAES aes = new JavaAES();
//        aes.generatePasswordAESKey("myPass");
//        System.out.println(aes.getSalt());
//        String encrypted_text = aes.encryptText("Hello World");
//        System.out.println("encrypted: " + encrypted_text);
//        String decrypted_text = aes.decryptText(encrypted_text);
//        System.out.println("decrypted: " + decrypted_text);
//
//        JavaAES aes2 = new JavaAES();
//        aes2.reGeneratePasswordAESKey("myPass", aes.getSalt());
//        String x = aes2.decryptText(encrypted_text);
//        System.out.println(x);




//        JavaUtil.encryptMessage("test.txt", "encrypted.txt");
//        JavaUtil.decryptMessage("encrypted.txt", "decryptedback.txt");




//        BCAES aes = new BCAES();
//        aes.generatePasswordKey("password".toCharArray(), "salt".getBytes(), 65536);
//        aes.saveKey("aeskey.txt");
//        JavaBCUtil.toAsciiArmored("aeskey.txt", "aeskey.asc");
//        aes.encryptFile("test.txt", "encrypted.txt");
//        aes.decryptFile("encrypted.txt", "decrypted.txt");



//        JavaAES aes = new JavaAES();
//        SecretKey secretKey = aes.generatePasswordAESKey("password", "salt");
//
//        KeyStore keyStore = KeyStore.getInstance("PKCS12"); // PKCS12, JCEKS, JKS
//        keyStore.load(null, null); // load a keystore with optional PW, or nulls to create a new empty keystore
//
//        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(secretKey);
//        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection("keyPassword".toCharArray()); // this is the password for an individual object in the keystore
//        keyStore.setEntry("aesKeyAlias", keyEntry, keyPassword);
//
//        // Save the KeyStore to a file with a password.
//        try (FileOutputStream fos = new FileOutputStream("keystore.jks")) {
//            keyStore.store(fos, "keystorePassword".toCharArray()); // keyStore.load(inputStream, password)
//        }
//
//
//        System.out.println("keystore size: " + keyStore.size());
//        System.out.println(keyStore.getAttributes("aesKeyAlias"));
//        System.out.println(keyStore.getCreationDate("aesKeyAlias"));
//        System.out.println(keyStore.getEntry("aesKeyAlias", keyPassword));
//        System.out.println(keyStore.getProvider());
//        System.out.println(keyStore.getType());
//        System.out.println(keyStore.containsAlias("aesKeyAlias"));
//
//            // List all aliases
//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                System.out.println("Alias: " + alias);
//            }

//// Load the PKCS12 KeyStore
//        KeyStore keyStore = KeyStore.getInstance("PKCS12");
//        try (FileInputStream fis = new FileInputStream("keystore.p12")) {
//            keyStore.load(fis, "keyStorePassword".toCharArray());
//        }
//
//// Retrieve the AES key
//        KeyStore.Entry entry = keyStore.getEntry("aesKeyAlias", new KeyStore.PasswordProtection("keyEntryPassword".toCharArray()));
//        if (entry instanceof KeyStore.SecretKeyEntry) {
//            SecretKey aesKey = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
//            // Now you can use aesKey
//        }


    }

}