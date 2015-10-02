package com.jrconlin.encryptiontest;

import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import javax.crypto.Cipher;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by firefox-dev on 23.09.15.
 */

public class Decrypt {
    byte[] salt;
    byte[] dh_raw;
    EllipticCurve ec;
    BigInteger remote_ecdh;
    int record_size;
    byte[] remote_public_key;

    private String TAG = "Decrypt";
    static byte[] ENCRYPT_INFO = "Content-Encoding: aesgcm128".getBytes();
    static int ENCRYPT_INFO_ITR = 16;
    static byte[] NONCE_INFO = "Content-Encoding: nonce".getBytes();
    static int NONCE_INFO_ITR = 12;


    public Decrypt(String sharedKey) {
        this.remote_public_key = Base64.decode(sharedKey, Base64.URL_SAFE);
    }

    public Decrypt setSalt(String saltStr) {
        this.salt = Base64.decode(saltStr, Base64.URL_SAFE);
        return this;
    }

    public Decrypt setEncryptionKey(String encryptionKey) {
        byte[] bytes = Base64.decode(encryptionKey, Base64.URL_SAFE);
        this.remote_ecdh = new BigInteger(bytes);
        this.dh_raw = bytes;

        return this;
    }

    public Decrypt loadKeys(String[] headers) throws Exception {
        for (String header : headers){
            if (header.toLowerCase().startsWith("encryption")){
                String[] headerBody = header.split(":", 2);
                if (headerBody.length < 2) {
                    continue;
                }
                String[] items = headerBody[1].split(";");
                for (String item : items) {
                    String[] keyval = header.split("=", 2);
                    byte[] bytes;
                    switch (keyval[0].toLowerCase()) {
                        case "keyid":
                            if (!keyval[1].equalsIgnoreCase("p256dh")) {
                                throw new Exception("Unknown key id: expecting 'p256dh'");
                            }
                        case "salt":
                            this.setSalt(keyval[1]);
                        case "dh":
                            this.setEncryptionKey(keyval[1]);
                            if (this.remote_public_key != null) {
                                Log.w(TAG, "Both key and dh defined");
                            };
                        case "rs":
                            this.record_size = Integer.parseInt(keyval[1]);
                        case "key":
                            this.remote_public_key = Base64.decode(keyval[1], Base64.URL_SAFE);
                            if (this.dh_raw != null) {
                                Log.w(TAG, "Both key and dh defined");
                            }
                    }
                }
            }
        }
        return this;
    }
    public byte[] decrypt(byte[] inbuffer) throws Exception {
        if (inbuffer.length == 0) {
            return null;
        }
        if (this.record_size > 0) {
            if (inbuffer.length + 16 != this.record_size) {
                throw new Exception("Invalid record size");
            }
            // TODO trim inbuffer to record_size
        }
        PushKeyPair localKey = new PushKeyPair().generateECPair();
        byte[] prk = HKDF.hkdfExtract(salt, this.remote_public_key);
//        byte[] nonce = HKDF.hkdfExpand(prk, NONCE_INFO, NONCE_INFO_ITR);
        byte[] okm = HKDF.hkdfExpand(prk, ENCRYPT_INFO, ENCRYPT_INFO_ITR);

        Cipher tc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        SecretKeySpec sk = new SecretKeySpec(okm, "AES");
        tc.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(new byte[12]));
        return tc.doFinal(inbuffer);
    }
}
