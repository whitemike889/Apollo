package com.apollocurrency.aplwallet.apl.crypto.symmetric;


import java.security.InvalidKeyException;

public interface AnonymouslyEncryptedData {

    /**
     * Decrypt
     * @param secretPhrase
     * @return
     */
    byte[] decrypt(String secretPhrase);

    /**
     * Decrypt
     * @param keySeed
     * @param theirPublicKey
     * @return
     */
    byte[] decrypt(byte[] keySeed, java.security.PublicKey theirPublicKey) throws InvalidKeyException;

    /**
     * Encrypted data
     * @return
     */
    byte[] getData();

    /**
     * Public key
     * @return
     */
    java.security.PublicKey getPublicKey();

    /**
     * should return a value equals to getBytes().length
     * @return
     */
    int getBytesSize();

    /**
     * Get this serialized to bytes
     * @return
     */
    byte[] getBytes();

}
