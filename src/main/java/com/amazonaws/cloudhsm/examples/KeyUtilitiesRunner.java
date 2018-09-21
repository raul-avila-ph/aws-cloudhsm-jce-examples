/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.ImportKey;
import com.cavium.cfm2.Util;
import com.cavium.key.*;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * This sample demonstrates how to work with keys. This could be importing keys, exporting keys, loading keys by handle,
 * or deleting keys.
 */
public class KeyUtilitiesRunner {
    private static String helpString = "KeyUtilitiesRunner\n" +
            "This sample demonstrates the different utility methods for working with keys in the HSM.\n" +
            "\n" +
            "Options\n" +
            "\t[--label <key label>] [--handle <numeric key handle>]\n" +
            "\t--get-key\t\tGet information about a key in the HSM\n" +
            "\t--delete-key\t\tDelete a key from the HSM\n" +
            "\t--import-key\t\tGenerates a key locally and imports it into the HSM\n" +
            "\t--export-key\t\tExport the bytes from a key in the HSM\n\n";

    private enum modes {
        INVALID,
        GET_KEY,
        DELETE_KEY,
        EXPORT_KEY,
        IMPORT_KEY
    }

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String label = null;
        long handle = 0;
        modes mode = modes.INVALID;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--label":
                    label = args[++i];
                    System.out.println(label);
                    break;
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    break;
                case "--get-key":
                    mode = modes.GET_KEY;
                    break;
                case "--delete-key":
                    mode = modes.DELETE_KEY;
                    break;
                case "--export-key":
                    mode = modes.EXPORT_KEY;
                    break;
                case "--import-key":
                    mode = modes.IMPORT_KEY;
                    break;
            }
        }

        if (null != label && 0 != handle) {
            System.out.println("Please specify one of key handle or label");
            help();
            return;
        } else if (null == label && 0 == handle && modes.IMPORT_KEY != mode) {
            System.out.println("Please specify either key handle or label");
            help();
            return;
        }

        // Using the supplied label, find the associated key handle.
        // The handle for the *first* key found using the label will be the handle returned.
        // If multiple keys have the same label, only the first key can be returned.
        if (0 == handle && modes.IMPORT_KEY != mode) {
            try {
                long[] handles = { 0 };
                Util.findKey(label, handles);
                handle = handles[0];
            } catch (CFM2Exception ex) {
                if (CFM2Exception.isAuthenticationFailure(ex)) {
                    System.out.println("Could not find credentials to login to the HSM");
                    return;
                }

                throw ex;
            }
        }

        try {
            switch (mode) {
                case IMPORT_KEY: {
                    // Generate a 256-bit AES symmetric key.
                    // This key is not yet in the HSM. It will have to be imported using a CaviumKeySpec.
                    KeyGenerator kg = KeyGenerator.getInstance("AES");
                    kg.init(256);
                    Key keyToBeImported = kg.generateKey();

                    // Import the key as a session key that is extractable.
                    // You can use the key handle to identify the key in other operations.
                    Key importedKey = importKey(keyToBeImported, "Test", true, false);
                    displayKeyInfo((CaviumKey) importedKey);
                    break;
                }
                case GET_KEY: {
                    CaviumKey key = getKeyByHandle(handle);
                    if (null != key) {
                        displayKeyInfo(key);
                    } else {
                        System.out.println("Could not find the given key handle");
                    }
                    break;
                }
                case DELETE_KEY: {
                    deleteKey(handle);
                    break;
                }
                case EXPORT_KEY: {
                    Key key = exportKey(handle);
                    if (null != key) {
                        System.out.println("Base64 wrapped key bytes = " + Base64.getEncoder().encodeToString(key.getEncoded()));
                    }
                }
            }
        } catch (CFM2Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void help() {
        System.out.println(helpString);
    }

    /**
     * Get an existing key from the HSM using a key handle.
     * @param handle The key handle in the HSM.
     * @return CaviumKey object
     */
    private static CaviumKey getKeyByHandle(long handle) throws CFM2Exception {
        // There is no direct method to load a key, but there is a method to load key attributes.
        // Using the key attributes and the handle, a new CaviumKey object can be created. This method shows
        // how to create a specific key type based on the attributes.
        byte[] keyAttribute = Util.getKeyAttributes(handle);
        CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);

        if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
            CaviumAESKey aesKey = new CaviumAESKey(handle, cka);
            return aesKey;
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
            CaviumRSAPrivateKey privKey = new CaviumRSAPrivateKey(handle, cka);
            return privKey;
        }
        else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
            CaviumRSAPublicKey pubKey = new CaviumRSAPublicKey(handle, cka);
            return pubKey;
        }

        return null;
    }

    /**
     * Delete a key by handle.
     * The Util.deleteKey method takes a CaviumKey object, so we have to lookup the key handle before deletion.
     * @param handle The key handle in the HSM.
     */
    private static void deleteKey(long handle) throws CFM2Exception {
        CaviumKey ck = getKeyByHandle(handle);
        Util.deleteKey(ck);
    }

    /**
     * Export an existing persisted key.
     * @param handle The key handle in the HSM.
     * @return Key object
     */
    private static Key exportKey(long handle) {
        try {
            byte[] keyAttribute = Util.getKeyAttributes(handle);
            CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
            System.out.println(cka.isExtractable());
            byte[] encoded = Util.exportKey( handle);
            if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
                Key aesKey = new SecretKeySpec(encoded, 0, encoded.length, "AES");
                return aesKey;
            }
            else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
                PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
                return privateKey;
            }
            else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
                return publicKey;
            }
        } catch (BadPaddingException | CFM2Exception e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Import a key into the HSM.
     * @param key Key object.
     * @param keyLabel Label to store with the key.
     * @param isExtractable Whether this key can be extracted later.
     * @param isPersistent Whether this key will persist beyond the current session.
     */
    private static Key importKey(Key key, String keyLabel, boolean isExtractable, boolean isPersistent) {
        // Create a new key parameter spec to identify the key. Specify a label
        // and Boolean values for extractable and persistent.
        CaviumKeyGenAlgorithmParameterSpec spec = new CaviumKeyGenAlgorithmParameterSpec(keyLabel, isExtractable, isPersistent);
        try {
            Key importedKey = ImportKey.importKey(key, spec);
            return importedKey;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static void displayKeyInfo(CaviumKey key) {
        if (null != key) {
            System.out.printf("Key handle %d with label %s\n", key.getHandle(), key.getLabel());
            // Display whether the key can be extracted from the HSM.
            System.out.println("Is Key Extractable? : " + key.isExtractable());

            // Display whether this key is a token key.
            System.out.println("Is Key Persistent? : " + key.isPersistent());

            // The algorithm and size used to generate this key.
            System.out.println("Key Algo : " + key.getAlgorithm());
            System.out.println("Key Size : " + key.getSize());
        }
    }
}