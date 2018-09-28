package com.apollocurrency.aplwallet.apl.crypto.asymmetric;

import com.apollocurrency.aplwallet.apl.AplException;

/**
 * Interface for PublicKeyEncoder component
 */
public abstract class PublicKeyEncoder {

    /**
     * get byte[] representation of Public Key without any metadata
     * @param key
     * @return
     */
    public abstract byte[] encode(java.security.PublicKey key);

    /**
     * Decode previously encoded using same KeyEncoder key
     * @param bytes
     * @return
     */
    public abstract java.security.PublicKey decode(byte[] bytes);

    /**
     * Length in bytes of the encoded key data
     * this should basically return a constant value
     * @return
     */
    public abstract int getEncodedLength();

    /**
     * encode array of keys
     * @param keys
     * @return
     */
    public byte[][] encode(java.security.PublicKey[] keys) {
        byte[][] result = new byte[keys.length][];
        for(int i = 0; i < keys.length; i++) {
            result[i] = encode(keys[i]);
        }
        return result;
    }

    /**
     * decode array of keys
     * @param bytes
     * @return
     */
    public java.security.PublicKey[] decode(byte[][] bytes) {
        java.security.PublicKey[] result = new java.security.PublicKey[bytes.length];
        for(int i = 0; i < bytes.length; i++) {
            result[i] = decode(bytes[i]);
        }
        return result;
    }



}
