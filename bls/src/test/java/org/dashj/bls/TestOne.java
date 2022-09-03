package org.dashj.bls;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class TestOne extends BaseTest {




    @Test
    public void test() {
        // Example seed, used to generate private key. Always use
// a secure RNG with sufficient entropy to generate a seed (at least 32 bytes).
        //assertTrue(isLibraryLoaded);
        short[] seed = {0, 50, 6, (byte) 244, 24, (byte) 199, 1, 25, 52, 88, (byte) 192,
                19, 18, 12, 89, 6, (byte) 220, 18, 102, 58, (byte) 209, 82,
                12, 62, 89, 110, (byte) 182, 9, 44, 20, (byte) 254, 22};

        Uint8Vector seedBytes = new Uint8Vector(seed);

        PrivateKey sk = new AugSchemeMPL().keyGen(seedBytes);
        G1Element pk = sk.getG1Element();

        short[] message = {1, 2, 3, 4, 5};  // Message is passed in as a byte vector
        Uint8Vector messageVec = new Uint8Vector(message);
        G2Element signature = new AugSchemeMPL().sign(sk, messageVec);

        // Verify the signature
        boolean ok = new AugSchemeMPL().verify(pk, messageVec, signature);
        assertTrue(ok);
    }
}
