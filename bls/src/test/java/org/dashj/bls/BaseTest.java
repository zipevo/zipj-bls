package org.dashj.bls;

/**
 * Created by hashengineering on 11/13/18.
 */
public class BaseTest {
    public static final String DASHJ_VERSION = "1.0-SNAPSHOT";

    static boolean isLibraryLoaded;
    static {

        try {
            System.loadLibrary(JNI.LIBRARY_NAME);
            //Preconditions.checkState(GetVersionString().equals(DASHJ_VERSION),
            //        "dashjbls:  C++ Source Version doesn't match Java Source version:" +
            //                "C++: " + GetVersionString() + " Java: " + DASHJ_VERSION);
            isLibraryLoaded = true;
        } catch (UnsatisfiedLinkError x) {
            isLibraryLoaded = false;
            throw new RuntimeException(x.getMessage());
        }
    }
}
