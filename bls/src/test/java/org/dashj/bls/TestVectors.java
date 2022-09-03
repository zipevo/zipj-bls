package org.dashj.bls;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TestVectors extends BaseTest {
    @Test
    public void basicTestVectors() {
        Uint8Vector seed1 = new Uint8Vector(32, (short) 0x00);  // All 0s
        Uint8Vector seed2 = new Uint8Vector(32, (short) 0x01);  // All 1s
        Uint8Vector message1 = new Uint8Vector(new short[]{7, 8, 9});
        Uint8Vector message2 = new Uint8Vector(new short[]{10, 11, 12});

        PrivateKey sk1 = new BasicSchemeMPL().keyGen(seed1);
        G1Element pk1 = sk1.getG1Element();
        G2Element sig1 = new BasicSchemeMPL().sign(sk1, message1);


        PrivateKey sk2 = new BasicSchemeMPL().keyGen(seed2);
        G1Element pk2 = sk2.getG1Element();
        G2Element sig2 = new BasicSchemeMPL().sign(sk2, message2);

        assertEquals(pk1.getFingerprint(), 0xb40dd58aL);
        assertEquals(pk2.getFingerprint(), 0xb839add1L);

        assertEquals(
                Util.hexStr(sig1.serialize()),
                "b8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1f" +
                        "fa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a" +
                        "1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1");
        assertEquals(
                Util.hexStr(sk1.serialize()),
                "4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604");
        assertEquals(
                Util.hexStr(pk1.serialize()),
                "85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911e" +
                        "f1e2e08749bddbf165352");

        assertEquals(
                Util.hexStr(sig2.serialize()),
                "a9c4d3e689b82c7ec7e838dac2380cb014f9a08f6cd6ba044c263746e39a8f7a60ffee4afb7" +
                        "8f146c2e421360784d58f0029491e3bd8ab84f0011d258471ba4e87059de295d9aba845c044e" +
                        "e83f6cf2411efd379ef38bf4cf41d5f3c0ae1205d");

        G2Element aggSig1 = new BasicSchemeMPL().aggregate(new G2ElementVector(new G2Element[]{sig1, sig2}));

        assertEquals(
                Util.hexStr(aggSig1.serialize()),
                "aee003c8cdaf3531b6b0ca354031b0819f7586b5846796615aee8108fec75ef838d181f9d24" +
                        "4a94d195d7b0231d4afcf06f27f0cc4d3c72162545c240de7d5034a7ef3a2a03c0159de982fb" +
                        "c2e7790aeb455e27beae91d64e077c70b5506dea3");

        assertTrue(new BasicSchemeMPL().aggregateVerify(new G1ElementVector(new G1Element[]{pk1, pk2}),
                new Uint8VectorVector(new Uint8Vector[]{message1, message2}), aggSig1));
        assertFalse(new BasicSchemeMPL().aggregateVerify(new G1ElementVector(new G1Element[]{pk1, pk2}),
                new Uint8VectorVector(new Uint8Vector[]{message1, message2}), sig1));
        assertFalse(new BasicSchemeMPL().verify(pk1, message1, sig2));
        assertFalse(new BasicSchemeMPL().verify(pk1, message2, sig1));

        Uint8Vector message3 = new Uint8Vector(new short[]{1, 2, 3});
        Uint8Vector message4 = new Uint8Vector(new short[]{1, 2, 3, 4});
        Uint8Vector message5 = new Uint8Vector(new short[]{1, 2});

        G2Element sig3 = new BasicSchemeMPL().sign(sk1, message3);
        G2Element sig4 = new BasicSchemeMPL().sign(sk1, message4);
        G2Element sig5 = new BasicSchemeMPL().sign(sk2, message5);

        G2Element aggSig2 = new BasicSchemeMPL().aggregate(new G2ElementVector(new G2Element[]{sig3, sig4, sig5}));

        assertTrue(new BasicSchemeMPL().aggregateVerify(new G1ElementVector(new G1Element[]{pk1, pk1, pk2}),
                new Uint8VectorVector(new Uint8Vector[]{message3, message4, message5}), aggSig2));
        assertEquals(
                Util.hexStr(aggSig2.serialize()),
                "a0b1378d518bea4d1100adbc7bdbc4ff64f2c219ed6395cd36fe5d2aa44a4b8e710b607afd9" +
                        "65e505a5ac3283291b75413d09478ab4b5cfbafbeea366de2d0c0bcf61deddaa521f6020460f" +
                        "d547ab37659ae207968b545727beba0a3c5572b9c");
    }

    @Test
    public void augmentedTestVectors() {
        Uint8Vector message1 = new Uint8Vector(new short[]{1, 2, 3, 40});
        Uint8Vector message2 = new Uint8Vector(new short[]{5, 6, 70, 201});
        Uint8Vector message3 = new Uint8Vector(new short[]{9, 10, 11, 12, 13});
        Uint8Vector message4 = new Uint8Vector(new short[]{15, 63, 244, 92, 0, 1});

        Uint8Vector seed1 = new Uint8Vector(32, (short) 0x02);  // All 2s
        Uint8Vector seed2 = new Uint8Vector(32, (short) 0x03);  // All 3s

        PrivateKey sk1 = new AugSchemeMPL().keyGen(seed1);
        PrivateKey sk2 = new AugSchemeMPL().keyGen(seed2);

        G1Element pk1 = sk1.getG1Element();
        G1Element pk2 = sk2.getG1Element();

        G2Element sig1 = new AugSchemeMPL().sign(sk1, message1);
        G2Element sig2 = new AugSchemeMPL().sign(sk2, message2);
        G2Element sig3 = new AugSchemeMPL().sign(sk2, message1);
        G2Element sig4 = new AugSchemeMPL().sign(sk1, message3);
        G2Element sig5 = new AugSchemeMPL().sign(sk1, message1);
        G2Element sig6 = new AugSchemeMPL().sign(sk1, message4);


        G2ElementVector sig1_2 = new G2ElementVector(new G2Element[]{sig1, sig2});
        G2Element aggSigL = new AugSchemeMPL().aggregate(sig1_2);
        G2ElementVector sig3_4_5 = new G2ElementVector(new G2Element[]{sig3, sig4, sig5});
        G2Element aggSigR = new AugSchemeMPL().aggregate(sig3_4_5);

        G2Element aggSig = new AugSchemeMPL().aggregate(new G2ElementVector(new G2Element[]{aggSigL, aggSigR, sig6}));


        assertTrue(new AugSchemeMPL().aggregateVerify(
                new G1ElementVector(new G1Element[]{pk1, pk2, pk2, pk1, pk1, pk1}),
                new Uint8VectorVector(new Uint8Vector[]{
                        message1, message2, message1, message3, message1, message4
                }), aggSig));

        assertEquals(Util.hexStr(aggSig.serialize()),
                "a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd4" +
                        "6eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871" +
                        "997b9bceeab37a4c2565876da19382ea32a962200");
    }

    @Test
    public void popTestVectors() {
        byte[] message1 = {1, 2, 3, 40, 50};

        Uint8Vector seed1 = new Uint8Vector(32, (short) 0x0004);  // All 4s

        PrivateKey sk1 = new PopSchemeMPL().keyGen(seed1);

        G2Element pop = new PopSchemeMPL().popProve(sk1);
        assertTrue(new PopSchemeMPL().popVerify(sk1.getG1Element(), pop));

        assertEquals(Util.hexStr(pop.serialize()), "84f709159435f0dc73b3e8bf6c78d85282d19231555a8ee3b6e2573aaf66872d9203fefa1ef" +
                "700e34e7c3f3fb28210100558c6871c53f1ef6055b9f06b0d1abe22ad584ad3b957f3018a8f5" +
                "8227c6c716b1e15791459850f2289168fa0cf9115");
    }
}
