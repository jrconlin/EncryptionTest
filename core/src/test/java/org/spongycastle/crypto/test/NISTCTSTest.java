package org.spongycastle.crypto.test;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.NISTCTSBlockCipher;
import org.spongycastle.crypto.modes.SICBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.SimpleTest;

/**
 * CTS tester
 */
public class NISTCTSTest
    extends SimpleTest
{
    private static KeyParameter key = new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f"));
    private static byte[] iv = Hex.decode("101112131415161718191a1b1c1d1e1f");

    private static byte[] singleBlock = Hex.decode("4920616d206f6e6520626c6f636b2e2e");
    private static byte[] singleOut = Hex.decode("8aad2098847a2d74ac87de22745d2537");

    private static byte[] twoBlock = Hex.decode("4920616d206174206c656173742074776f20626c6f636b73206c6f6e672e2e2e");

    private static byte[] cs1TwoBlockOut = Hex.decode("3f07fd5816c3b96349eb9f6a074909d67237eb8aa9a7467b8a388c61d0e8f35a");
    private static byte[] cs2TwoBlockOut = Hex.decode("3f07fd5816c3b96349eb9f6a074909d67237eb8aa9a7467b8a388c61d0e8f35a");
    private static byte[] cs3TwoBlockOut = Hex.decode("7237eb8aa9a7467b8a388c61d0e8f35a3f07fd5816c3b96349eb9f6a074909d6");

    private static byte[] notQuiteTwo = Hex.decode("4920616d206e6f742071756974652074776f2e2e2e");

    private static byte[] cs1NotQuiteTwoBlockOut = Hex.decode("22ecf2ac77f098097ca69b72e3a46e9ca21bb5ebbc");
    private static byte[] cs2NotQuiteTwoBlockOut = Hex.decode("f098097ca69b72e3a46e9ca21bb5ebbc22ecf2ac77");
    private static byte[] cs3NotQuiteTwoBlockOut = Hex.decode("f098097ca69b72e3a46e9ca21bb5ebbc22ecf2ac77");

    static byte[]   in1 = Hex.decode("4e6f7720697320746865207420");
    static byte[]   in2 = Hex.decode("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");
    static byte[]   out1 = Hex.decode("9952f131588465033fa40e8a98");
    static byte[]   out2 = Hex.decode("358f84d01eb42988dc34efb994");
    static byte[]   out3 = Hex.decode("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6");
    
    private void testCTS(
        int                 id,
        int                 type,
        BlockCipher         cipher,
        CipherParameters    params,
        byte[]              input,
        byte[]              output)
        throws Exception
    {
        byte[]                  out = new byte[input.length];
        BufferedBlockCipher     engine = new NISTCTSBlockCipher(type, cipher);

        engine.init(true, params);

        int len = engine.processBytes(input, 0, input.length, out, 0);

        engine.doFinal(out, len);

        if (!areEqual(output, out))
        {
            fail(id + " failed encryption expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }

        engine.init(false, params);

        len = engine.processBytes(output, 0, output.length, out, 0);

        engine.doFinal(out, len);

        if (!areEqual(input, out))
        {
            fail(id + " failed decryption expected " + new String(Hex.encode(input)) + " got " + new String(Hex.encode(out)));
        }
    }

    private void testExceptions() throws InvalidCipherTextException
    {
        BufferedBlockCipher engine = new NISTCTSBlockCipher(NISTCTSBlockCipher.CS1, new AESEngine());
        CipherParameters params = new KeyParameter(new byte[engine.getBlockSize()]);
        engine.init(true, params);

        byte[] out = new byte[engine.getOutputSize(engine.getBlockSize())];
        
        engine.processBytes(new byte[engine.getBlockSize() - 1], 0, engine.getBlockSize() - 1, out, 0);
        try 
        {
            engine.doFinal(out, 0);
            fail("Expected CTS encrypt error on < 1 block input");
        } catch(DataLengthException e)
        {
            // Expected
        }

        engine.init(true, params);
        engine.processBytes(new byte[engine.getBlockSize()], 0, engine.getBlockSize(), out, 0);
        try 
        {
            engine.doFinal(out, 0);
        } catch(DataLengthException e)
        {
            fail("Unexpected CTS encrypt error on == 1 block input");
        }

        engine.init(false, params);
        engine.processBytes(new byte[engine.getBlockSize() - 1], 0, engine.getBlockSize() - 1, out, 0);
        try 
        {
            engine.doFinal(out, 0);
            fail("Expected CTS decrypt error on < 1 block input");
        } catch(DataLengthException e)
        {
            // Expected
        }

        engine.init(false, params);
        engine.processBytes(new byte[engine.getBlockSize()], 0, engine.getBlockSize(), out, 0);
        try 
        {
            engine.doFinal(out, 0);
        } catch(DataLengthException e)
        {
            fail("Unexpected CTS decrypt error on == 1 block input");
        }

    }

    public String getName()
    {
        return "CTS";
    }

    public void performTest() 
        throws Exception
    {
        testCTS(1, NISTCTSBlockCipher.CS1, new AESEngine(), new ParametersWithIV(key, iv), singleBlock, singleOut);
        testCTS(2, NISTCTSBlockCipher.CS2, new AESEngine(), new ParametersWithIV(key, iv), singleBlock, singleOut);
        testCTS(3, NISTCTSBlockCipher.CS3, new AESEngine(), new ParametersWithIV(key, iv), singleBlock, singleOut);

        testCTS(4, NISTCTSBlockCipher.CS1, new AESEngine(), new ParametersWithIV(key, iv), twoBlock, cs1TwoBlockOut);
        testCTS(5, NISTCTSBlockCipher.CS2, new AESEngine(), new ParametersWithIV(key, iv), twoBlock, cs2TwoBlockOut);
        testCTS(6, NISTCTSBlockCipher.CS3, new AESEngine(), new ParametersWithIV(key, iv), twoBlock, cs3TwoBlockOut);

        testCTS(7, NISTCTSBlockCipher.CS1, new AESEngine(), new ParametersWithIV(key, iv), notQuiteTwo, cs1NotQuiteTwoBlockOut);
        testCTS(8, NISTCTSBlockCipher.CS2, new AESEngine(), new ParametersWithIV(key, iv), notQuiteTwo, cs2NotQuiteTwoBlockOut);
        testCTS(9, NISTCTSBlockCipher.CS3, new AESEngine(), new ParametersWithIV(key, iv), notQuiteTwo, cs3NotQuiteTwoBlockOut);

        testExceptions();
    }

    public static void main(
        String[]    args)
    {
        runTest(new NISTCTSTest());
    }
}
