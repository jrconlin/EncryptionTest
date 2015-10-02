package com.jrconlin.encryptiontest;

import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Iterator;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PushKeyPair {
    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    private KeyPair kp;
    public PublicKey public_key;
    public PrivateKey private_key;
    private static String TAG = "PushKeyPair";

    public PushKeyPair() {
        // dumpProviders();
    }

    public PushKeyPair generateECPair() throws Exception {
        try {
            ECGenParameterSpec ecp = new ECGenParameterSpec("secp256r1");
            // For Android 5+ this is probably AndroidOpenSSL
            // Calling this without provider took a shockingly long time in the debugger.
            // Generate the local EC key pair
            // ECDH may not be in the default BC implementation, and may only be in SpongyCastle.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "SC");
            kpg.initialize(ecp);
            this.kp = kpg.generateKeyPair();
            this.public_key = kp.getPublic();
            this.private_key = kp.getPrivate();
        } catch (Exception x) {
            Log.e(TAG, "PushKeyPair ", x);
            throw x;
        }
        return this;
    }

    public String join(Iterator<String> items, String joint) {
        StringBuilder reply = new StringBuilder();
        while (items.hasNext()) {
            reply.append(items.next());
            if (items.hasNext()) {
                reply.append(joint);
            }
        }
        return reply.toString();
    }

    public String dumpProviders() {
        String TAG = "dumpProvider";
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                Log.i(TAG, "   : " + provider.getName() + " : " + service.getAlgorithm() + " [" + service.getType() + "]");
            }
        }
        return null;
    }

    public String getProvider(String type) {
        String TAG = "getProvider";
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {
                // ECDH is for key agreement (generator side)
                if (service.getAlgorithm().equalsIgnoreCase(type)) {
                    // just return the first one we find that does EC
                    Log.i(TAG, "Found " + type + " provider " + provider.getName());
                    return provider.getName();
                }
            }
        }
        return null;
    }
}
