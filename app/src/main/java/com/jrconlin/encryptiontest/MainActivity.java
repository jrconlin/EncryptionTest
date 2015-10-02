package com.jrconlin.encryptiontest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

public class MainActivity extends Activity {

    static TextView mDisplay;
    static String TAG = "Main";

    // The following were taken from a js test client
    static String TestString = "Mary had a little lamb with some fresh mint jelly";
    static String RemoteSharedKeyStr = "BG9GNB9gB0mO5SEIKJOOif9W4SpXryJm8rqacp4M3opbkxd8mp4uF_NE89e5FyZwMxFQtGVAbQYSgaquMOO3gk8";
    static String RemoteEncryptionKeyStr = "BFN4-N0q1xkbDsk9Epf94iGkfUUVmdgLVzMfqTIEIikOwW9CM0R98PYEhiZB-fQmVXtIR4uGx7X5Ip8fGg1L7jE";
    static String RemoteBodyStr = "JQZVoKnUjeAeFkvPsJ1Zdetk6Aff_eq6jIcXMhLh2kCOTaDVEvCayeASSoUm-B1icbLeD_igpgNzMYE4luxStvM3";
    static String RemoteSaltStr = "a4UV9oUyAtX6ztg4CNiLww";
    static String[] headers = {
            "Content-Encoding: aesgcm128",
            "Encryption: keyid=p256dh;salt=" + RemoteSaltStr,
            "Encryption-Key: keyid=p256dh;dh=" + RemoteSharedKeyStr};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mDisplay = (TextView) findViewById(R.id.TextView);
        // Generate the keys

        PushKeyPair pk;

        try {
            pk = new PushKeyPair().generateECPair();
            Log.i(TAG, "Public Key: Private " + pk.private_key);
            Log.i(TAG, "Public Key: Public  " + pk.public_key);
        } catch (Exception x) {
            Log.e(TAG, "onCreate ", x);
            return;
        }

        Encrypt encrypt = new Encrypt(RemoteSharedKeyStr);
        encrypt.salt(RemoteSaltStr);
        try {
            mDisplay.append("encryption ==== \n");
            encrypt.encrypt(TestString.getBytes());
            String dh = Base64.encodeToString(encrypt.body, Base64.URL_SAFE);
            mDisplay.append((dh == RemoteBodyStr) + "\n");
        } catch(Exception x){
            Log.e(TAG, "Exception", x);
        }

        Decrypt decrypt = new Decrypt(RemoteSharedKeyStr);
        byte[] body = Base64.decode(RemoteBodyStr,Base64.URL_SAFE);
        try {
            // decrypt.loadKeys(headers);
            mDisplay.append("decryption ==== \n");
            byte[] result = decrypt.setSalt(RemoteSaltStr).setEncryptionKey(RemoteEncryptionKeyStr).decrypt(body);
            mDisplay.append("Source " + TestString + "\n");
            mDisplay.append("Result " + result.toString() + "\n");
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
