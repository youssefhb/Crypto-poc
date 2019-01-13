package com.fisglobal.crypto.asymmetric;

import org.junit.Test;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import static org.junit.Assert.*;

public class AsymmetricEncryptionUtilsTest {

    @Test
    public void generateKeyPair() throws Exception {

        KeyPair keyPair = AsymmetricEncryptionUtils.generateKeyPair();
        System.out.println("Public Key ="+ DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
        System.out.println("Private Key ="+ DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
    }


    @Test
    public void cryptoRoutine() throws Exception {

        KeyPair keyPair = AsymmetricEncryptionUtils.generateKeyPair();
        assertNotNull(keyPair);
        String plainText = "Please encrypt for me this text";
        byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption(plainText,keyPair.getPublic());
        String decryptedText = AsymmetricEncryptionUtils.performRSADecryption(cipherText,keyPair.getPrivate());
        assertEquals(plainText,decryptedText);
    }
}