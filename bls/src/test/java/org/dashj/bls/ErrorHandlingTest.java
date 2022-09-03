package org.dashj.bls;

import org.junit.Test;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class ErrorHandlingTest extends BaseTest {
    @Test
    public void shouldThrowOnBadPrivateKey() {}
    {
        Uint8Vector seed = new Uint8Vector(32, (short)0x10);
        PrivateKey sk1 = new BasicSchemeMPL().keyGen(seed);
        byte [] skData = new byte[G2Element.SIZE];
        sk1.serialize(skData);
        skData[0] = (byte)255;
        assertThrows(IllegalArgumentException.class,() -> PrivateKey.fromBytes(Util.bytes(skData, PrivateKey.PRIVATE_KEY_SIZE)));
    }

    @Test public void shouldThrowOnBadPublicKey()
    {
        Uint8Vector buf = new Uint8Vector(G1Element.SIZE, (short)0);
        for (int i = 0; i < 0xFF; i++) {
            buf.set(0, (short)i);
            if (i == 0xc0) { // Infinity prefix shouldn't throw here as we have only zero values
                G1Element.fromByteVector(buf);
            } else {
                assertThrows(IllegalArgumentException.class, () -> G1Element.fromByteVector(buf));
            }
        }
    }

    @Test public void shouldThrowOnBadG2Element()
    {
        Uint8Vector buf = new Uint8Vector(G2Element.SIZE, (short)0);
        for (int i = 0; i < 0xFF; i++) {
            buf.set(0, (short)i);
            if (i == 0xc0) { // Infinity prefix shouldn't throw here as we have only zero values
                G2Element.fromByteVector(buf);
            } else {
                assertThrows(IllegalArgumentException.class, () -> G2Element.fromByteVector(buf));
            }
        }
        // Trigger "G2 element must always have 48th byte start with 0b000" error case
        buf.set(48, (short)0xFF);
        assertThrows(IllegalArgumentException.class, () -> G2Element.fromByteVector(buf));
    }

    @Test
    public void errorHandlingShouldBeThreadSafe() throws InterruptedException {
        BLS.setContextError(10);
        assertEquals(BLS.getContextError(), 10);

        long ctx1 = BLS.getContext();

        // spawn a thread and make sure it uses a different/same context depending on relic's multithreading setup
        Thread thread = new Thread(() -> {
            BLS.init();
            assertNotEquals(ctx1, BLS.getContext());

            assertNotEquals(BLS.getContextError(), BLS.RLC_OK);
            // this should not modify the code of the main thread
            BLS.setContextError(1);
        });
        thread.start();

        thread.join();

        // other thread should not modify code
        assertEquals(10, BLS.getContextError());

        // reset so that future test cases don't fail
        BLS.setContextError(BLS.RLC_OK);
    }
}
