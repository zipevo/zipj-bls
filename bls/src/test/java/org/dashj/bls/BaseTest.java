package org.dashj.bls;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by hashengineering on 11/13/18.
 */
public class BaseTest {
    public static final String DASHJ_VERSION = "1.0-SNAPSHOT";
    public static String LIBRARY_NAME = "dashjbls";


    static boolean isLibraryLoaded;
    static {

        try {
            System.loadLibrary(LIBRARY_NAME);
            isLibraryLoaded = true;
        } catch (UnsatisfiedLinkError x) {
            isLibraryLoaded = false;
            throw new RuntimeException(x.getMessage());
        }
    }

    static void assertObjectEquals(G1Element a, G1Element b) {
        assertTrue(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectEquals(G2Element a, G2Element b) {
        assertTrue(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectEquals(PrivateKey a, PrivateKey b) {
        assertTrue(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectEquals(ExtendedPublicKey a, ExtendedPublicKey b) {
        assertTrue(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectEquals(ExtendedPrivateKey a, ExtendedPrivateKey b) {
        assertTrue(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectNotEquals(G1Element a, G1Element b) {
        assertFalse(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectNotEquals(G2Element a, G2Element b) {
        assertFalse(DASHJBLS.objectEquals(a, b));
    }

    static void assertObjectNotEquals(PrivateKey a, PrivateKey b) {
        assertFalse(DASHJBLS.objectEquals(a, b));
    }
}
