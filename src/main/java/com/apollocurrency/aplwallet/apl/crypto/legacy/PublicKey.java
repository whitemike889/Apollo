package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.util.Convert;

import java.security.InvalidKeyException;
import java.util.Arrays;

public class PublicKey implements java.security.PublicKey {

    static final String ALGORITHM = "apl-crypto-legacy-public-key";
    static final String FORMAT = "key-public-binary";

    private final byte[] key;

    public PublicKey(byte[] key) throws InvalidKeyException {
        this.key = key;
        if (!Crypto.isCanonicalPublicKey(key)) {
            throw new InvalidKeyException("Invalid public key " + Convert.toHexString(key));
        }
    }

    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    /**
     * Do not use this method directly outside "legacy" package
     * @return
     */
    @Override
    public byte[] getEncoded() {
        return Arrays.copyOf(key, key.length);
    }
}
