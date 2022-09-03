package org.dashj.bls;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dashj.bls.Util.bytes;
import static org.dashj.bls.Util.shortArrayToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class PrivateKeyTest extends BaseTest {
    byte[] buffer;
    private static Logger log = LoggerFactory.getLogger(PrivateKeyTest.class);

    @Before
    public void beforeEach() {
        buffer = Entropy.getRandomSeed(PrivateKey.PRIVATE_KEY_SIZE);
    }

    @Test
    public void copyConstructorAssignmentOperator() {
        PrivateKey pk1 = PrivateKey.randomPrivateKey();
        PrivateKey pk2 = PrivateKey.randomPrivateKey();
        PrivateKey pk3 = new PrivateKey(pk2);
        assertFalse(pk1.isZero());
        assertFalse(pk2.isZero());
        assertFalse(pk3.isZero());
        assertNotEquals(pk1, pk2);
        assertTrue(DASHJBLS.objectEquals(pk3, pk2));
        assertTrue(pk2.getG1Element().isValid()); // cache previous g1
        assertTrue(pk2.getG2Element().isValid()); // cache previous g2
        pk2 = pk1;
        assertEquals(pk1, pk2);
        assertTrue(DASHJBLS.objectEquals(pk1.getG1Element(), pk2.getG1Element()));
        assertTrue(DASHJBLS.objectEquals(pk1.getG2Element(), pk2.getG2Element()));
        assertNotEquals(pk3, pk2);
    }

    @Test
    public void multiplicationOperatorTest() {
        PrivateKey pk1 = PrivateKey.randomPrivateKey();
        PrivateKey pk2 = PrivateKey.randomPrivateKey();

        G1Element publicKey1 = pk1.getG1Element();
        G1Element publicKey2 = pk2.getG1Element();

        G1Element publicKeyFirst1 = DASHJBLS.multiply(publicKey1, pk2);
        G1Element privateKeyFirst1 = DASHJBLS.multiply(pk2, publicKey1);
        G1Element publicKeyFirst2 = DASHJBLS.multiply(publicKey2, pk1);
        G1Element privateKeyFirst2 = DASHJBLS.multiply(pk1, publicKey2);


        assertTrue(DASHJBLS.objectEquals(publicKeyFirst1, privateKeyFirst1));
        assertTrue(DASHJBLS.objectEquals(publicKeyFirst2, privateKeyFirst2));
        assertTrue(DASHJBLS.objectEquals(publicKeyFirst1, privateKeyFirst2));
    }

    @Test
    public void equalityOperators() {
        PrivateKey pk1 = PrivateKey.randomPrivateKey();
        PrivateKey pk2 = PrivateKey.randomPrivateKey();
        PrivateKey pk3 = new PrivateKey(pk2);
        //pk3.assign(pk2);
        assertFalse(DASHJBLS.objectEquals(pk1, pk2));
        assertFalse(DASHJBLS.objectEquals(pk1, pk3));
        assertTrue(DASHJBLS.objectEquals(pk2, pk3));
    }

    @Test
    public void de_serialization() {
        log.info("lol");
        PrivateKey pk1 = PrivateKey.randomPrivateKey();
        pk1.serialize(buffer);
        assertArrayEquals(buffer, shortArrayToByteArray(pk1.serialize()));
        PrivateKey pk2 = PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), true);
        assertTrue(DASHJBLS.objectEquals(pk1, pk2));
        assertThrows(IllegalArgumentException.class, () -> PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE - 1), true));
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE + 1), true));
        PrivateKey pk3 = PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), true);

        Uint8Vector bytes_ = pk3.serialize();
        PrivateKey.fromByteVector(bytes_);
        //BigInteger order = new BigInteger();
        //bn_new(order);
        //g1_get_ord(order);
        //bn_write_bin(buffer, PrivateKey.PRIVATE_KEY_SIZE, order);
        //assertTrue_NOTHROW(PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), false));
        //assertTrue_NOTHROW(PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), true));
        //bn_add(order, order, order);
        //bn_write_bin(buffer, PrivateKey.PRIVATE_KEY_SIZE, order);
        //assertTrue_THROWS(PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), false));
        //assertTrue_NOTHROW(PrivateKey.fromBytes(bytes(buffer, PrivateKey.PRIVATE_KEY_SIZE), true));
    }

    @Test
    public void BIP32Seed() {
        byte[] aliceSeed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        PrivateKey pk1 = PrivateKey.fromSeedBIP32(aliceSeed);
        assertTrue(pk1.hasKeyData());
        Uint8Vector privateKey = pk1.serialize(true);
        Uint8Vector knownPrivateKey = Util.hexToUint8Vector("46891c2cec49593c81921e473db7480029e0fc1eb933c6b93d81f5370eb19fbd");
        assertEquals(privateKey, knownPrivateKey);
        G1Element pubKey1 = pk1.getG1Element();
        Uint8Vector pubKey1Bytes = pubKey1.serialize(true);
        Uint8Vector knownPublicKey = Util.hexToUint8Vector("1790635de8740e9a6a6b15fb6b72f3a16afa0973d971979b6ba54761d6e2502c50db76f4d26143f05459a42cfd520d44");
        assertEquals(pubKey1Bytes, knownPublicKey);
    }

    @Test
    public void keydataChecks() {
        PrivateKey pk1 = PrivateKey.randomPrivateKey();
        G1Element g1 = pk1.getG1Element();
        G2Element g2 = pk1.getG2Element();
        PrivateKey pk2 = new PrivateKey(pk1);
        pk1 = new PrivateKey();
        final PrivateKey emptyPk1 = pk1;
        /*assertThrows(IllegalArgumentException.class, () -> new PrivateKey(emptyPk1));
        assertTrue_THROWS(pk1 = pk2);
        assertTrue_THROWS(pk1.getG1Element());
        assertTrue_THROWS(pk1.getG2Element());
        assertTrue_THROWS(g1 * pk1);
        assertTrue_THROWS(pk1 * g1);
        assertTrue_THROWS(g2 * pk1);
        assertTrue_THROWS(pk1 * g2);
        assertTrue_THROWS(pk1.getG2Power(g2));
        assertTrue_THROWS(PrivateKey.Aggregate({pk1, pk2}));
        assertTrue_THROWS(pk1.isZero());
        assertTrue_THROWS(pk1 == pk2);
        assertTrue_THROWS(pk1 != pk2);
        assertTrue_THROWS(pk1.Serialize(buffer));
        assertTrue_THROWS(pk1.Serialize());
        assertTrue_THROWS(pk1.SignG2(buffer, sizeof(buffer), buffer, sizeof(buffer)));*/
    }
}

