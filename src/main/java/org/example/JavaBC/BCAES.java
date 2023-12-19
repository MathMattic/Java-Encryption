package org.example.JavaBC;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class BCAES {

    private static final int KEY_SIZE = 256; // AES key size in bits
    private static final int IV_SIZE = 96; // GCM recommended IV size in bits
    private static final int TAG_LENGTH = 128; // Authentication tag length in bits
    private final SecureRandom random = new SecureRandom();
    KeyParameter key;

    public void saveKey(String keyName) throws IOException {
        byte[] keyBytes = key.getKey();
        Files.write(Paths.get(keyName), keyBytes);
    }

    public KeyParameter loadKey(String keyFilePath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(keyFilePath));
        return new KeyParameter(keyBytes);
    }

    public void generateRandomAESKey() {
        byte[] keyBytes = new byte[KEY_SIZE/8];
        random.nextBytes(keyBytes);
        this.key = new KeyParameter(keyBytes);
    }

    public void generatePasswordKey(char[] password, byte[] salt, int iterationCount) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password), salt, iterationCount);
        this.key = (KeyParameter) generator.generateDerivedMacParameters(KEY_SIZE);
    }

    public void encryptFile(String inputFile, String outputFile) throws IOException {
        if (this.key == null) throw new IllegalStateException("Key not initialized.");
        byte[] ivBytes = new byte[IV_SIZE/8];
        random.nextBytes(ivBytes);
//        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine()); // this is the code from gpt
        GCMBlockCipher cipher = (GCMBlockCipher) GCMBlockCipher.newInstance(AESEngine.newInstance());
        AEADParameters parameters = new AEADParameters(key, TAG_LENGTH, ivBytes);
        cipher.init(true, parameters);
        processFile(cipher, inputFile, outputFile, ivBytes, true);
    }

    public void decryptFile(String inputFile, String outputFile) throws IOException {
        if (this.key == null) throw new IllegalStateException("Key not initialized.");
        byte[] ivBytes = new byte[IV_SIZE/8];

        // Read IV
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            if (fis.read(ivBytes) != ivBytes.length) {
                throw new IOException("Unable to read the full IV from the encrypted file.");
            }
        }
//        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        GCMBlockCipher cipher = (GCMBlockCipher) GCMBlockCipher.newInstance(AESEngine.newInstance());
        AEADParameters parameters = new AEADParameters(key, TAG_LENGTH, ivBytes);
        cipher.init(false, parameters);

        processFile(cipher, inputFile, outputFile, ivBytes, false);
    }


    private void processFile(GCMBlockCipher cipher, String inputFile, String outputFile, byte[] ivBytes, boolean isEncryption) throws IOException {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            if (isEncryption) {
                // Write IV for encryption
                fos.write(ivBytes);
            } else {
                // Skip IV for decryption
                long skippedBytes = fis.skip(ivBytes.length);
                if (skippedBytes != ivBytes.length) {
                    throw new IOException("Failed to skip the IV bytes for decryption.");
                }
            }

            byte[] inBuf = new byte[1024];
            byte[] outBuf = new byte[inBuf.length + (TAG_LENGTH/8)];

            int bytesRead;
            while ((bytesRead = fis.read(inBuf)) != -1) {
                int length = cipher.processBytes(inBuf, 0, bytesRead, outBuf, 0);
                fos.write(outBuf, 0, length);
            }

            try {
                int length = cipher.doFinal(outBuf, 0);
                fos.write(outBuf, 0, length);
            } catch (Exception e) {
                throw new IOException("Error finalizing cipher operation", e);
            }
        }
    }

}

