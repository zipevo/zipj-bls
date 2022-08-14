package org.dashj.bls.v1;

import org.dashj.bls.BaseTest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class KeyGenerationTest extends BaseTest {
    @Test
    public void shouldGenerateKeypairFromSeed() {
        Uint8Vector seed1 = new Uint8Vector(31, (short)0x08);
        Uint8Vector seed2 = new Uint8Vector(32, (short)0x08);

        assertThrows(IllegalArgumentException.class, () -> new BasicSchemeMPL().keyGen(seed1));
        PrivateKey sk = new BasicSchemeMPL().keyGen(seed2);
        G1Element pk = sk.getG1Element();
        BLS.checkRelicErrors();
        assertEquals(pk.getFingerprint(), 0x8ee7ba56L);
    }
}
