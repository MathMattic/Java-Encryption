package org.example.Java;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class JavaUtil {
    private JavaUtil(){}

    public static void encryptMessage(JavaRSA rsa, JavaAES aes, String message, String encryptedMessage) throws Exception {
    }

    public static void decryptMessage(PrivateKey privateKey, String encryptedAESKey, String encryptedMessage, String decryptedMessage) throws Exception {
    }

    public static String convertToBase64(String inputString, String outputString) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(inputString));
        String encodedString = Base64.getEncoder().encodeToString(content);
        Files.writeString(Paths.get(outputString + "Base64"), encodedString);
        return encodedString;
    }

    public static String convertFromBase64(String inputKeyName, String outputKeyName) throws IOException {
        String encodedString = new String(Files.readAllBytes(Paths.get(inputKeyName)));
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
        Files.write(Paths.get(outputKeyName), decodedBytes);
        return encodedString;
    }

    public static String generatePassword(int length) {
        String alphaLower = "abcdefghijklmnopqrstuvwxyz";
        String alphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String num = "0123456789";
        String specialChars = "!@#$%&*()_+-=[]?";
        String passChars = alphaLower + alphaUpper + num + specialChars;
        SecureRandom r = new SecureRandom();

        if (length < 16) throw new IllegalArgumentException("Salt must be at least 16 character(s).");

        return IntStream.range(0, length)
                .map(i -> passChars.charAt(r.nextInt(passChars.length())))
                .mapToObj(c -> String.valueOf((char) c)).collect(Collectors.joining());
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 128-bit salt
        random.nextBytes(salt);
        return salt;
    }


    public static void hash() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update("pass".getBytes(StandardCharsets.UTF_8));
        md.update("salt".getBytes(StandardCharsets.UTF_8));
        byte[] hashBytes = md.digest();
        for(byte b : hashBytes) System.out.printf("%02x", b); // %x int in hex format, %02x means 2 digits, with leading 0 if needed.
        System.out.println();
        System.out.println(HexFormat.of().withDelimiter("-").withUpperCase().formatHex(hashBytes));
//        UUID.randomUUID()
    }


}
