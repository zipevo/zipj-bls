package org.dashj.bls.Utils;

import org.dashj.bls.G1Element;
import org.dashj.bls.G1ElementVector;
import org.dashj.bls.PrivateKey;
import org.dashj.bls.PrivateKeyVector;

import java.util.Arrays;
import java.util.List;

public class PrivateKeyList extends PrivateKeyVector {

    public PrivateKeyList() {
        super();
    }
    public PrivateKeyList(List<PrivateKey> list) {
        super(list);
    }

    public PrivateKeyList(PrivateKey [] array) {
        super(Arrays.asList(array));
    }

    public PrivateKeyList(PrivateKey first, PrivateKey... elements) {
        add(first);
        addAll(Arrays.asList(elements));
    }
}
