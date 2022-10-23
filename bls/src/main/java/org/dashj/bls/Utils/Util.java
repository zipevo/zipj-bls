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

    static public Uint8Vector hexToUint8Vector(String hex) {
        byte [] bytes = HEX.decode(hex);
        short [] elements = byteArrayToShortArray(bytes);
        return new Uint8Vector(elements);
    }

    static public Uint8Vector reverse(Uint8Vector bytes) {
        return new Uint8Vector(Lists.reverse(bytes));
    }

    static public Uint8VectorVector reverse(Uint8VectorVector bytesVector) {
        Uint8VectorVector result = new Uint8VectorVector();
        for (int i = bytesVector.size() - 1; i < 0; --i) {
            result.add(reverse(bytesVector.get(i)));
        }
        return result;
    }

    static public byte [] bytes(byte [] buffer, int size) {
        byte [] bufferCopy = new byte[size];
        System.arraycopy(buffer, 0, bufferCopy, 0, size);
        return bufferCopy;
    }

    static public byte [] bytes(Uint8Vector byteVector) {
        byte [] buffer = new byte[byteVector.size()];
        int i = 0;
        for (short b : byteVector) {
            buffer[i++] = (byte)(b & 0xff);
        }
        return buffer;
    }

    static public short[] byteArrayToShortArray(byte [] bytes) {
        short [] elements = new short[bytes.length];
        for (int i = 0; i < bytes.length; ++i) {
            elements[i] = (short)(bytes[i] & 0x00ff);
        }
        return elements;
    }

    static public byte[] shortArrayToByteArray(Uint8Vector bytes) {
        byte [] elements = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); ++i) {
            elements[i] = (byte)(bytes.get(i) & 0xff);
        }
        return elements;
    }

    public static String hexStr(Uint8Vector bytes) {
        StringBuilder builder = new StringBuilder();
        for (Short aByte : bytes) {
            builder.append(String.format("%02x", (byte) (aByte & 0xff)));
        }
        return builder.toString();
    }

    public static String hexStr(byte [] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte aByte : bytes) {
            builder.append(String.format("%02x", (byte) (aByte & 0xff)));
        }
        return builder.toString();
    }

    public static Uint8VectorVector makeUintVectorVector(byte []... byteArrays) {
        Uint8VectorVector vec = new Uint8VectorVector();
        for (byte [] byteArray: byteArrays) {
            vec.add(new Uint8Vector(byteArrayToShortArray(byteArray)));
        }
        return vec;
    }

    public static G1ElementVector makeG1ElementVector(G1Element... pks) {
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
    }
}
