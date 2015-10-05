package com.jrconlin.encryptiontest;

import android.util.Base64;
import android.util.Log;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;
import org.spongycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* Notes
 * There's hidden entropy.
 *
 * Presume that the encryption bit is working, ish.
 * Create the decryption half to render the data.
 * Test using the webpush.js script (remember, it's from
 * https://github.com/martinthomson/webpush-client/blob/gh-pages/webpush.js )
 *
 * Finally, try sending data to a push endpoint on client.
 *  Set the key headers and non zero timeout.
 */

public class Crypt {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }
    static byte[] ENCRYPT_INFO = "Content-Encoding: aesgcm128".getBytes();
    static int ENCRYPT_INFO_ITR = 16;
    static byte[] NONCE_INFO = "Content-Encoding: nonce".getBytes();
    static int NONCE_INFO_ITR = 12;
    static String TAG = "Crypt";
    static String PROVIDER = "SC";

    public byte[] salt;
    public byte[] body;
    private byte[] dh;
    int record_size;
    public String keyid = "p256dh";
    byte[] key;


    Crypt(String key){
        this.key = Base64.decode(key, Base64.URL_SAFE);
    }

    /** Generate a random salt
     *
     * @return potentially random salt value
     */
    public byte[] salt() {
        // for debugging
        if (this.salt != null) {
            return this.salt;
        }
        byte[] reply = new byte[16];
        (new Random()).nextBytes(reply);
        return reply;
    }

    public void salt(String saltStr){
        Log.w(TAG, "Setting salt value for debug purposes.");
        this.salt = Base64.decode(saltStr, Base64.URL_SAFE);
    }

    /** A nonce is a 96 bit (12 byte) IV field, which is generated
     *
     * See https://tools.ietf.org/html/draft-thomson-http-encryption-01#section-3.3
     *
     *  @return calculated nonce
     */
    public byte[] generateNonce(byte[] base, int index) {
        byte[] nonce = new byte[12];
        // copy as much of the base as we can into the new nonce.
        double d = 0;
        for (; d < Math.min(base.length, 12); d++) {
            nonce[(int)d] = base[(int)d];
        }
        // derive the top order bytes.
        for (int i = 0; i < 6; ++i) {
            byte n = nonce[12 - 1 - i];
            nonce[i] ^= (byte)(index / Math.pow(256, i)) & 0xff;
        }
        return nonce;
     }

    // HKDF encodes correctly.
    static public void hkdf_test(byte[] salt, byte[] ikm) {
        try {
            byte[] prk = HKDF.hkdfExtract(salt, ikm);
            byte[] nonce = HKDF.hkdfExpand(prk, NONCE_INFO, NONCE_INFO_ITR);
            Log.i("hkdf", "Nonce: " + Base64.encodeToString(nonce, Base64.URL_SAFE));
        } catch (Exception x) {
            Log.e("hkdf", "Crap", x);
        }
    }

    private byte[] getKASecret(byte[] remote_public_key) throws Exception{
        PushKeyPair localKey = new PushKeyPair().generateECPair();
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PROVIDER);
        KeyFactory kf = KeyFactory.getInstance("ECDH", PROVIDER);
        ECPoint point = spec.getCurve().decodePoint(remote_public_key);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);
        keyAgreement.init(localKey.private_key);
        keyAgreement.doPhase(publicKey, true);

        return keyAgreement.generateSecret();
    }

    public Crypt encrypt(byte[] data) throws Exception {
        // Convert the sent bytes to a public Key
        // No, really, these are the steps.
        Log.i(TAG, "Converting shared key to dh public key...");
        byte[] ka_secret = this.getKASecret(this.key);
        // Loop over the data in 4K chunk
        Log.i(TAG, "Encoding data...");
        int rs = Math.min(data.length, 4096);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Cipher tc = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
        byte[] prk = HKDF.hkdfExtract(salt, ka_secret);
        Log.d(TAG, "prk    : " + Base64.encodeToString(prk, Base64.URL_SAFE));
        byte[] nonce_root = HKDF.hkdfExpand(prk, NONCE_INFO, NONCE_INFO_ITR);
        Log.d(TAG, "nonce  : " + Base64.encodeToString(nonce_root, Base64.URL_SAFE));
        byte[] gcmBits = HKDF.hkdfExpand(prk, ENCRYPT_INFO, ENCRYPT_INFO_ITR);
        Log.d(TAG, "encrypt gcmbits: " + Base64.encodeToString(gcmBits, Base64.URL_SAFE));
        Log.i(TAG, "Starting encoding...");
        tc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(gcmBits, "AES"),
                new IvParameterSpec(nonce_root));
        // Chunk through data in 4095 blocks
        outputStream.write(tc.doFinal(data));
        Log.i(TAG, "encoding written");
        // end chunk
        this.body = outputStream.toByteArray();
        Log.i(TAG, "Done Encoding.");
        return this;
    }

    public Crypt decrypt(byte[] inbuffer) throws Exception {
        if (inbuffer.length == 0) {
            return null;
        }
        if (this.record_size > 0) {
            if (inbuffer.length + 16 != this.record_size) {
                throw new Exception("Invalid record size");
            }
            // TODO trim inbuffer to record_size
        }
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Cipher tc = Cipher.getInstance("AES/GCM/NoPadding", PROVIDER);
        //Nonce is first 16 bytes;
        byte[]nonce = Arrays.copyOfRange(inbuffer, 0, 16);
        byte[]newData = Arrays.copyOfRange(inbuffer, 16, inbuffer.length - 16);
        // Loop over data in 4K chunks
        Log.i(TAG, "Decoding data...");
        try {
            tc.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(this.key, "AES"),
                    new IvParameterSpec(nonce));
            outputStream.write(tc.doFinal(newData));
            this.body = outputStream.toByteArray();
            Log.d(TAG, Arrays.toString(this.body));
        } catch (Exception x) {
            Log.w(TAG, "straight: ", x);
        }
        Log.i(TAG, "Done Decoding.");
        return this;
    }

    // Decryption stuff.
    public Crypt setSalt(String saltStr) {
        this.salt = Base64.decode(saltStr, Base64.URL_SAFE);
        return this;
    }

    public Crypt setEncryptionKey(String encryptionKey) {
        this.dh = Base64.decode(encryptionKey, Base64.URL_SAFE);
        return this;
    }


    public Crypt loadKeys(String[] headers) throws Exception {
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
                            if (this.key != null) {
                                Log.w(TAG, "Both key and dh defined");
                            }
                        case "rs":
                            this.record_size = Integer.parseInt(keyval[1]);
                        case "key":
                            this.key = Base64.decode(keyval[1], Base64.URL_SAFE);
                            if (this.dh != null) {
                                Log.w(TAG, "Both key and dh defined");
                            }
                    }
                }
            }
        }
        return this;
    }

}
