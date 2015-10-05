package com.jrconlin.encryptiontest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.util.Arrays;

public class MainActivity extends Activity {

    static TextView mDisplay;
    static String TAG = "Main";

    // The following were taken from a js test client
    static String TestString = "Mary had a little lamb with some fresh mint jelly";
    static String PrivateKeyStr = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQggtEvRfut4H5P31vTRhKl71X3d70eNjA4bV1_CX_iyV2gCgYIKoZIzj0DAQehRANCAAQpqLq_Ugmv8dxbFHxNa6v97GnUNSQ-CdhVhOhTI7R73kszJSeUS7zaGXsH-MR1yQ9mNsObsygkcox_QJqm8hHC";
    static String PublicKeyStr = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKai6v1IJr_HcWxR8TWur_exp1DUkPgnYVYToUyO0e95LMyUnlEu82hl7B_jEdckPZjbDm7MoJHKMf0CapvIRwg==";
    static String RemoteSharedKeyStr = "BG9GNB9gB0mO5SEIKJOOif9W4SpXryJm8rqacp4M3opbkxd8mp4uF_NE89e5FyZwMxFQtGVAbQYSgaquMOO3gk8";
    static String RemoteEncryptionKeyStr = "BFN4-N0q1xkbDsk9Epf94iGkfUUVmdgLVzMfqTIEIikOwW9CM0R98PYEhiZB-fQmVXtIR4uGx7X5Ip8fGg1L7jE";
    static String StaticSaltStr = "a4UV9oUyAtX6ztg4CNiLww";
    static String[] headers = {
            "Content-Encoding: aesgcm128",
            "Encryption: keyid=p256dh;salt=" + StaticSaltStr,
            "Encryption-Key: keyid=p256dh;dh=" + RemoteSharedKeyStr};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mDisplay = (TextView) findViewById(R.id.TextView);
        // Generate the keys

        PushKeyPair pk;
//*
        try {
            pk = new PushKeyPair().generateECPair();
            Log.i(TAG, "Private Key: " + Base64.encodeToString(pk.private_key.getEncoded(), Base64.URL_SAFE));
            Log.i(TAG, "Public Key:  " + Base64.encodeToString(pk.public_key.getEncoded(), Base64.URL_SAFE));
        } catch (Exception x) {
            Log.e(TAG, "onCreate ", x);
            return;
        }
/*
        Crypt encrypt = new Crypt(RemoteSharedKeyStr);
        encrypt.salt(StaticSaltStr);
        try {
            mDisplay.append("encryption ==== \n");
            encrypt.encrypt(TestString.getBytes());
            String dh = Base64.encodeToString(encrypt.body, Base64.URL_SAFE);
            mDisplay.append((RemoteBodyStr.equals(dh)) + "\n");
        } catch(Exception x){
            Log.e(TAG, "Exception", x);
        }
//*/
        //Crypt.hkdf_test(Base64.decode(StaticSaltStr, Base64.URL_SAFE), Base64.decode(RemoteSharedKeyStr, Base64.URL_SAFE));
        // For current values, this should produce "bka0O47Qe5jTRsqZ"

        Crypt decrypt = new Crypt(PrivateKeyStr);
        String dh = "BOoIAgjWRInfplagK7cB6qTlXKFK1ER7ObwZkD2Lq_NGmZWglqNtbY8Pdyn6BM6zMMUSYqKhXQSDp11lvGWz-bE";
        byte[] body = Base64.decode("s-P19iGxf4qRnNq7jcci9hRZFjEb_EEn2TjmR9LhaJwcyP3XW3sDKbvp0oiZGpAK0rTy9_W3O3qas8WL7RxpNbob", Base64.URL_SAFE);
        try {
            // decrypt.loadKeys(headers);
            mDisplay.append("decryption ==== \n");
            byte[] result = decrypt.setSalt(StaticSaltStr).setEncryptionKey(dh).decrypt(body).body;
            mDisplay.append("Source " + TestString + "\n");
            mDisplay.append("Result " + Arrays.toString(result) + "\n");
        }catch(Exception x) {
            Log.e(TAG, "Exception", x);
        }
        mDisplay.append("\n Done.");
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
