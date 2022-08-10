package org.dashj.bls.v1;

import com.google.common.io.BaseEncoding;

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

    static public byte [] bytes(byte [] buffer, int size) {
        byte [] bufferCopy = new byte[size];
        System.arraycopy(buffer, 0, bufferCopy, 0, size);
        return bufferCopy;
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
}
