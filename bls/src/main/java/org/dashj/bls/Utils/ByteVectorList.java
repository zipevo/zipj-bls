package org.dashj.bls.Utils;

import org.dashj.bls.Uint8Vector;
import org.dashj.bls.Uint8VectorVector;

import java.util.List;

public class ByteVectorList extends Uint8VectorVector {

    public ByteVectorList() {
        super();
    }
    public ByteVectorList(List<byte[]> list) {
        for (byte [] array : list) {
            add(new Uint8Vector(Util.byteArrayToShortArray(array)));
        }
    }

    public ByteVectorList(byte[][] arrays) {
        for (byte [] array : arrays) {
            add(new Uint8Vector(Util.byteArrayToShortArray(array)));
        }
    }
}
