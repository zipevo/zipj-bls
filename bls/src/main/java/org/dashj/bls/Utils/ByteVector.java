package org.dashj.bls.Utils;

import org.dashj.bls.Uint8Vector;

public class ByteVector extends Uint8Vector {

    public ByteVector() {
        super();
    }
    public ByteVector(byte[] byteArray) {
        for (byte b : byteArray) {
            add((short)b);
        }
    }
}
