package com.apollocurrency.aplwallet.apl.crypto.symmetric;

import com.apollocurrency.aplwallet.apl.AplException;

import java.nio.ByteBuffer;

public interface DataEncryptor {

    /**
     * Create EncryptedData by data and nonce
     * @param encrypted
     * @param nonce
     * @return
     */
    EncryptedData createEncryptedData(byte[] encrypted, byte[] nonce);

    /**
     *
     * @param plaintext
     * @param secretPhrase
     * @param theirPublicKey
     * @return
     */
    EncryptedData encrypt(byte[] plaintext, String secretPhrase, java.security.PublicKey theirPublicKey);

    /**
     * Read encrypted data from byte buffer
     * @param buffer
     * @param length
     * @param maxLength
     * @return
     */
    EncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException;

    /**
     * read encrypted data from bytes
     * @param bytes
     * @return
     */
    EncryptedData readEncryptedData(byte[] bytes);

    /**
     * get length of the plaintext encryption result (data length only without metadata)
     * @param plaintext
     * @return
     */
    int getEncryptedDataLength(byte[] plaintext);

    /**
     * get length of the plaintext encryption result including metadata
     * @param plaintext
     * @return
     */
    int getEncryptedBytesSize(byte[] plaintext);

}
