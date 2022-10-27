/**
 * Copyright (c) 2022-present, Dash Core Group
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
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
