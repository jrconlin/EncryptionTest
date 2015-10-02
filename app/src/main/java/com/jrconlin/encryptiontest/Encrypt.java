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
import java.security.KeyPair;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by jrconlin on 9/24/2015.
 */
public class Encrypt {

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }
    static byte[] ENCRYPT_INFO = "Content-Encoding: aesgcm128".getBytes();
    static int ENCRYPT_INFO_ITR = 16;
    static byte[] NONCE_INFO = "Content-Encoding: nonce".getBytes();
    static int NONCE_INFO_ITR = 12;
    static String TAG = "Encrypt";

    public byte[] salt;
    public byte[] body;
    public String keyid = "p256dh";
    byte[] remote_public_key;


    Encrypt(String sharedKey){
        this.remote_public_key = Base64.decode(sharedKey, Base64.URL_SAFE);
    }

    /** Generate a random salt
     *
     * @return
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
     *  @return
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

    private void encode(byte[] localKey, byte[]salt, byte[] data, int pad) throws Exception {
        int rs = Math.min(data.length, 4096);
        byte[] prk = HKDF.hkdfExtract(salt, this.remote_public_key);
        byte[] nonce_root = HKDF.hkdfExpand(prk, NONCE_INFO, NONCE_INFO_ITR);
        byte[] gcmBits = HKDF.hkdfExpand(prk, ENCRYPT_INFO, ENCRYPT_INFO_ITR);
        Cipher tc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Log.i(TAG, "Starting encryption...");
        tc.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(gcmBits, "AES"),
                new IvParameterSpec(nonce_root));
        // Chunk through data in 4095 blocks
        outputStream.write(tc.doFinal(data));
        Log.i(TAG, "Encryption written");
        // end chunk
        this.body = outputStream.toByteArray();
    }

    public Encrypt encrypt(byte[] data) throws Exception {
        PushKeyPair localKey = new PushKeyPair().generateECPair();

        // Convert the sent bytes to a public Key
        // No, really, these are the steps.
        Log.i(TAG, "Converting shared key to public key...");
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        ECPoint point = spec.getCurve().decodePoint(this.remote_public_key);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, spec);
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec);

        keyAgreement.init(localKey.private_key);
        keyAgreement.doPhase(publicKey,true);

        byte[] ka_secret = keyAgreement.generateSecret();

        // Do the actual encryption
        int maxBufferLen = 4095;
        int start = 0;

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[]salt = salt();
        // Loop over the data in 4K chunk
        Log.i(TAG, "Encoding data...");
        this.encode(ka_secret, salt, data, 0);
        Log.i(TAG, "Done Encoding.");
        return this;
    }
}
