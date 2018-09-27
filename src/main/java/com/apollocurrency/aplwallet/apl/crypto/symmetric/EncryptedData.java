package com.apollocurrency.aplwallet.apl.crypto.symmetric;


public interface EncryptedData {

    /**
     *
     * @param secretPhrase
     * @param theirPublicKey
     * @return
     */
    byte[] decrypt(String secretPhrase, java.security.PublicKey theirPublicKey);

    /**
     * Decrypt by symmetric key
     * @param symmetricKey
     * @return
     */
    byte[] decrypt(byte[] symmetricKey);

    /**
     * get encrypted data. just data without metadata
     * @return
     */
    byte[] getData();

    /**
     * get nonce used to encrypt this data
     * @return
     */
    byte[] getNonce();

    /**
     * should return a value equals to getBytes().length
     * @return
     */
    int getBytesSize();

    /**
     * get all bytes. data + metadata
     * @return
     */
    byte[] getBytes();

}