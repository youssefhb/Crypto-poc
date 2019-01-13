package com.fisglobal.crypto.symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.*;

public class SymmetricEncryptionUtilsTest {

    @Test
    public void createAESKey() throws Exception{
        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        assertNotNull(secretKey);
        System.out.println(DatatypeConverter.printHexBinary(secretKey.getEncoded()));
    }

    @Test
    public void cryptoRoutine() throws Exception {

        SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
        assertNotNull(secretKey);
        byte[] initializationvector = SymmetricEncryptionUtils.createInitInitializationVector();
        String plainText = "Please hide me ..";
        byte[] ciphertext = SymmetricEncryptionUtils.performAESEncryption(plainText,secretKey,initializationvector);
        String decryptedText = SymmetricEncryptionUtils.performAESDecryption(ciphertext,secretKey,initializationvector);
        assertEquals(plainText,decryptedText);
        System.out.println("Decrypted Text="+decryptedText);

    }
}