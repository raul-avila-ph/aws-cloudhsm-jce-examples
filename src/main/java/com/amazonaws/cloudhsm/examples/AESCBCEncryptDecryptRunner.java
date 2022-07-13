/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.security.KeyStore;

/**
 * This sample demonstrates how to encrypt data with AES GCM. It shows where the IV is generated
 * and how to pass authenticated tags to the encrypt and decrypt functions.
 */
public class AESCBCEncryptDecryptRunner {

    public static byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    public static void main(String[] z) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Generate a new AES Key to use for encryption.
        Key key = SymmetricKeys.generateAESKey(256, "AesCBCTest");

        //getKeyByLabel("aes256");

        // Generate some random data to encrypt
        byte[] plainText = new byte[1024];
        Random r = new Random();
        r.nextBytes(plainText);

        // Encrypt the plaintext with authenticated data.
        String aad = "16 bytes of data";
        String result = encrypt(key, plainText);

        System.out.println("Text: " + plainText);

        System.out.println("Encrypted: " + result);

        // Decrypt the ciphertext.
//        byte[] decryptedText = decrypt(key, cipherText, iv, aad.getBytes());
//        assert(Arrays.equals(plainText, decryptedText));
//        System.out.println("Successful decryption");

        String decrypted = decrypt(key, result);
        System.out.println("Decrypted: " + decrypted);
    }

    private static Key getKeyByLabel(String label)
            throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException,
            UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keystore.load(null, null);
        return keystore.getKey(label, null);
    }

    /**
     * Encrypt some plaintext and authentication data using the GCM cipher mode.
     * @param key
     * @param plainText
     * @param aad
     * @return List of byte[] containing the IV and cipherText
     */
    public static String encrypt(Key key, byte[] plainText) throws Exception {
        try {
            IvParameterSpec ivspec = new IvParameterSpec(IV);

            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("AES/CBC/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            encCipher.init(Cipher.ENCRYPT_MODE, key, ivspec);

            //encCipher.update(plainText);
            return Base64.getEncoder()
                    .encodeToString(encCipher.doFinal(plainText));

            //return new String(Hex.encodeHex(encCipher.doFinal(plainText)));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Decrypt the ciphertext using the HSM supplied IV and the user supplied tag data.
     * @param key
     * @param cipherText
     * @param iv
     * @param aad
     * @return byte[] of the decrypted ciphertext.
     */
    public static String decrypt(Key key, String encrypted) throws Exception {
        Cipher decCipher;
        try {
            IvParameterSpec ivspec = new IvParameterSpec(IV);

            decCipher = Cipher.getInstance("AES/CBC/NoPadding", CloudHsmProvider.PROVIDER_NAME);
            decCipher.init(Cipher.DECRYPT_MODE, key, ivspec);

            return new String(decCipher.doFinal(Base64.getDecoder().decode(encrypted)));
            //return new String(decCipher.doFinal(Hex.decodeHex(encrypted)));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
