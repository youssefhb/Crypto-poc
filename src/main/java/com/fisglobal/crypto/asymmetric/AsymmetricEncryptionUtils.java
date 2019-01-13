package com.fisglobal.crypto.asymmetric;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;

public class AsymmetricEncryptionUtils {

    private static final String RSA = "RSA";


    public static KeyPair generateKeyPair() throws Exception{

        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(4096,secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] performRSAEncryption(String plainText, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String performRSADecryption(byte[] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
