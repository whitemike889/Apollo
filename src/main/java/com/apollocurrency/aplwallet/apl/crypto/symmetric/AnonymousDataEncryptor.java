package com.apollocurrency.aplwallet.apl.crypto.symmetric;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.crypto.legacy.AnonymouslyEncryptedData;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public interface AnonymousDataEncryptor {

    /**
     * Create AnonymouslyEncryptedData instance
     * @param encrypted
     * @param publicKey
     * @return
     */
    AnonymouslyEncryptedData createEncryptedData(byte[] encrypted, java.security.PublicKey publicKey) throws InvalidKeyException;

    /**
     * Encrypt
     * @param plaintext
     * @param secretPhrase
     * @param theirPublicKey
     * @param nonce
     * @return
     */
    AnonymouslyEncryptedData encrypt(byte[] plaintext, String secretPhrase, java.security.PublicKey theirPublicKey, byte[] nonce) throws InvalidKeyException;

    /**
     * Parse encrypted data from buffer
     * @param buffer
     * @param length
     * @param maxLength
     * @return
     */
    AnonymouslyEncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException, InvalidKeyException;

    /**
     * Parse encrypted data from bytes array
     * @param bytes
     * @return
     */
    AnonymouslyEncryptedData readEncryptedData(byte[] bytes) throws InvalidKeyException;

}
