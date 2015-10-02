/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package com.jrconlin.encryptiontest;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * HMAC uses HMAC SHA256 standard.
 */
public class HKDF {
    public static String HMAC_ALGORITHM = "hmacSHA256";


    public static byte[] concatAll(byte[] first, byte[]... rest) {
        int totalLength = first.length;
        for (byte[] array : rest) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];
        int offset = first.length;

        System.arraycopy(first, 0, result, 0, offset);

        for (byte[] array : rest) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    public static byte[] hex2Byte(String str, int byteLength) {
        byte[] second = hex2Byte(str);
        if (second.length >= byteLength) {
            return second;
        }
        // New Java arrays are zeroed:
        // http://docs.oracle.com/javase/specs/jls/se7/html/jls-4.html#jls-4.12.5
        byte[] first = new byte[byteLength - second.length];
        return concatAll(first, second);
    }

    public static byte[] hex2Byte(String str) {
        if (str.length() % 2 == 1) {
            str = "0" + str;
        }

        byte[] bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /**
     * Used for conversion in cases in which you *know* the encoding exists.
     */
    public static final byte[] bytes(String in) {
        try {
            return in.getBytes("UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return null;
        }
    }

    public static final int BLOCKSIZE     = 256 / 8;
    public static final byte[] HMAC_INPUT = bytes("Sync-AES_256_CBC-HMAC256");

    /*
     * Step 1 of RFC 5869
     * Get sha256HMAC Bytes
     * Input: salt (message), IKM (input keyring material)
     * Output: PRK (pseudorandom key)
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] IKM) throws NoSuchAlgorithmException, InvalidKeyException {
        return digestBytes(IKM, makeHMACHasher(salt));
    }

    /*
     * Step 2 of RFC 5869.
     * Input: PRK from step 1, info, length.
     * Output: OKM (output keyring material).
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacHasher = makeHMACHasher(prk);

        byte[] T  = {};
        byte[] Tn = {};

        int iterations = (int) Math.ceil(((double)len) / ((double)BLOCKSIZE));
        for (int i = 0; i < iterations; i++) {
            Tn = digestBytes(concatAll(Tn, info, hex2Byte(Integer.toHexString(i + 1))),
                    hmacHasher);
            T = concatAll(T, Tn);
        }

        byte[] result = new byte[len];
        System.arraycopy(T, 0, result, 0, len);
        return result;
    }

    /*
     * Make HMAC key
     * Input: key (salt)
     * Output: Key HMAC-Key
     */
    public static Key makeHMACKey(byte[] key) {
        if (key.length == 0) {
            key = new byte[BLOCKSIZE];
        }
        return new SecretKeySpec(key, HMAC_ALGORITHM);
    }

    /*
     * Make an HMAC hasher
     * Input: Key hmacKey
     * Ouput: An HMAC Hasher
     */
    public static Mac makeHMACHasher(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmacHasher = null;
        hmacHasher = Mac.getInstance(HMAC_ALGORITHM);

        // If Mac.getInstance doesn't throw NoSuchAlgorithmException, hmacHasher is
        // non-null.
        assert(hmacHasher != null);

        hmacHasher.init(makeHMACKey(key));
        return hmacHasher;
    }

    /*
     * Hash bytes with given hasher
     * Input: message to hash, HMAC hasher
     * Output: hashed byte[].
     */
    public static byte[] digestBytes(byte[] message, Mac hasher) {
        hasher.update(message);
        byte[] ret = hasher.doFinal();
        hasher.reset();
        return ret;
    }
}