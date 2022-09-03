package org.dashj.bls;

import java.security.SecureRandom;

public class Entropy {
    static SecureRandom secureRandom;
    static {
        secureRandom = new SecureRandom();
    }
    public static byte [] getRandomSeed(int size) {
        byte [] bytes = new byte [size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static Uint8Vector getRandomSeedAsUint8Vector(int size) {
        byte [] bytes = new byte [size];
        secureRandom.nextBytes(bytes);
        return new Uint8Vector(Util.byteArrayToShortArray(bytes));
    }
}
