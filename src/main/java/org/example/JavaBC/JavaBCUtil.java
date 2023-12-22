package org.example.JavaBC;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;

public class JavaBCUtil {

    public static void toAsciiArmored(String inputFile, String outputFile) throws IOException {
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile);
             ArmoredOutputStream aOut = new ArmoredOutputStream(out)) {
            int ch;
            while ((ch = in.read()) >= 0) {
                aOut.write(ch);
            }
        }
    }

    public static void fromAsciiArmored(String inputFile, String outputFile) throws IOException {
        try (FileInputStream inStream = new FileInputStream(inputFile);
             ArmoredInputStream aIn = new ArmoredInputStream(inStream);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            int ch;
            while ((ch = aIn.read()) >= 0) {
                out.write(ch);
            }
        }
    }

    public static void toAsciiArmoredBuffer(String inputFile, String outputFile) throws IOException {
        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(outputFile);
             ArmoredOutputStream aOut = new ArmoredOutputStream(out)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                aOut.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void fromAsciiArmoredBuffer(String inputFile, String outputFile) throws IOException {
        try (FileInputStream inStream = new FileInputStream(inputFile);
             ArmoredInputStream aIn = new ArmoredInputStream(inStream);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = aIn.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }


    // BC version of SHA3-512
    public static void hashBC() {
        SHA3.DigestSHA3 digestSHA3 = new SHA3.Digest512();
        byte[] input = "your password here".getBytes();
        byte[] hashBytes = digestSHA3.digest(input);

        String hashString = Hex.toHexString(hashBytes);
        System.out.println("SHA3-512 Hash: " + hashString);
    }

    // BC version of Whirlpool
    public static void WhirlpoolHashingExample() {
        WhirlpoolDigest digest = new WhirlpoolDigest();
        String input = "your input here";
        byte[] inputBytes = input.getBytes();
        byte[] hash = new byte[digest.getDigestSize()];

        digest.update(inputBytes, 0, inputBytes.length);
        digest.doFinal(hash, 0);

        String hashString = Hex.toHexString(hash);
        System.out.println("Whirlpool Hash: " + hashString);

    }



}
