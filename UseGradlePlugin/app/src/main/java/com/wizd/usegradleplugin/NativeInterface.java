package com.wizd.usegradleplugin;

public class NativeInterface {
    static {
        System.loadLibrary("native-lib");
    }

    public native static byte[] a(byte[] in, byte[] key);
}
