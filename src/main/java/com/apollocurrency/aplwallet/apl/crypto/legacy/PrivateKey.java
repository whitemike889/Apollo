package com.apollocurrency.aplwallet.apl.crypto.legacy;

import java.util.Arrays;

public class PrivateKey implements java.security.PrivateKey{

    static final String ALGORITHM = "apl-crypto-legacy-private-key";
    static final String FORMAT = "key-private-binary";

    private final byte[] key;

    public PrivateKey(byte[] key) {
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public byte[] getEncoded() {
        return Arrays.copyOf(key, key.length);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrivateKey that = (PrivateKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

}
