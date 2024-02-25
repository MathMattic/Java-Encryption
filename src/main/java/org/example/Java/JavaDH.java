package org.example.Java;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class JavaDH {

    public static void main(String[] args) throws Exception {

        // Generate a key pair for Alice
        KeyPairGenerator aliceKpg = KeyPairGenerator.getInstance("DH"); // discrete log
        aliceKpg.initialize(2048);
        KeyPair aliceKeyPair = aliceKpg.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());

        // Alice encodes her public key and sends it over to Bob
        byte[] alicePubKeyEnc = aliceKeyPair.getPublic().getEncoded();


        // Assuming Alice's public key is transferred to Bob...
        // Bob now has Alice's public key in encoded format
        // Bob creates his own DH key pair
        // The DH public key from Alice is used to configure part of Bobs keypair
        KeyPairGenerator bobKpg = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhParamSpec = ((DHPublicKey) aliceKeyPair.getPublic()).getParams(); // Alice's part
        bobKpg.initialize(dhParamSpec); // keysize not required since it's already in the DH parameters
        KeyPair bobKeyPair = bobKpg.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKeyPair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice
        byte[] bobPubKeyEnc = bobKeyPair.getPublic().getEncoded();

        // Alice uses Bob's public key for the first (and only) phase of her version of the DH protocol.
        // Before she can do so, she has to instantiate a DH public key from Bob's encoded key material.
        // When Alice calls doPhase() with Bob's public key, Alice is mixing her private key with Bob's public key following the DH protocol to generate a partial shared secret.
        KeyFactory aliceKeyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFactory.generatePublic(x509KeySpec);
        aliceKeyAgree.doPhase(bobPubKey, true); // mixing of Alice's private key and Bob's public key

        // Bob does the same with Alice's public key
        KeyFactory bobKeyFactory = KeyFactory.getInstance("DH");
        x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFactory.generatePublic(x509KeySpec);
        bobKeyAgree.doPhase(alicePubKey, true); // mixing of Bob's private key and Alice's public key

        // Both Alice and Bob generate the shared secret
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
//        SecretKey sce = aliceKeyAgree.generateSecret("AES"); // Generate a shared secret using AES

        // prove the keys are the same.
        System.out.println(java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret));


        // Generate an AES key from the shared secret and both parties can derive the same key
        // This will hash the shared secret using SHA3-512 and use the first 32 bytes as the AES key
        // Probably(?) don't need something like HKDF or PBKDF Since shared secret is already of high entropy.
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(aliceSharedSecret);
        byte[] hashBytes = md.digest();
        byte[] aliceaeskeybytes = new byte[32];
        SecretKey sck = new SecretKeySpec(hashBytes, 0, 32, "AES");
    }
}