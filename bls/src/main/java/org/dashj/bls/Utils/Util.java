package org.dashj.bls.Utils;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import org.dashj.bls.G1Element;
import org.dashj.bls.G1ElementVector;
import org.dashj.bls.G2Element;
import org.dashj.bls.G2ElementVector;
import org.dashj.bls.PrivateKey;
import org.dashj.bls.PrivateKeyVector;
import org.dashj.bls.Uint8Vector;
import org.dashj.bls.Uint8VectorVector;

import java.util.Arrays;

public class Util {
    public static final BaseEncoding HEX = BaseEncoding.base16().lowerCase();

    static public byte [] hexToBytes(String hex) {
        return HEX.decode(hex);
    }

    public static byte[] reverse(byte[] data) {
        for (int i = 0, j = data.length - 1; i < data.length / 2; i++, j--) {
            data[i] ^= data[j];
            data[j] ^= data[i];
            data[i] ^= data[j];
        }
        return data;
    }

    /*static public short[] byteArrayToShortArray(byte [] bytes) {
        short [] elements = new short[bytes.length];
        for (int i = 0; i < bytes.length; ++i) {
            elements[i] = (short)(bytes[i] & 0x00ff);
        }
        return elements;
    }*/

    /*public static String hexStr(Uint8Vector bytes) {
        StringBuilder builder = new StringBuilder();
        for (Short aByte : bytes) {
            builder.append(String.format("%02x", (byte) (aByte & 0xff)));
        }
        return builder.toString();
    }*/

    public static String hexStr(byte [] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte aByte : bytes) {
            builder.append(String.format("%02x", (byte) (aByte & 0xff)));
        }
        return builder.toString();
    }

    /*public static G1ElementVector makeG1ElementVector(G1Element... pks) {
        G1ElementVector vec = new G1ElementVector();
        vec.addAll(Arrays.asList(pks));
        return vec;
    }

    public static G2ElementVector makeG2ElementVector(G2Element... sigs) {
        G2ElementVector vec = new G2ElementVector();
        vec.addAll(Arrays.asList(sigs));
        return vec;
    }

    public static PrivateKeyVector makePrivateKeyVector(PrivateKey... pks) {
        PrivateKeyVector vec = new PrivateKeyVector();
        vec.addAll(Arrays.asList(pks));
        return vec;
    }*/
}
