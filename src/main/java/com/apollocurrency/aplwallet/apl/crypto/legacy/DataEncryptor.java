package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.EncryptedData;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DataEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor {

    private static final com.apollocurrency.aplwallet.apl.crypto.legacy.EncryptedData EMPTY_DATA = new com.apollocurrency.aplwallet.apl.crypto.legacy.EncryptedData(new byte[0], new byte[0]);


    @Override
    public EncryptedData createEncryptedData(byte[] encrypted, byte[] nonce) {
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.EncryptedData(encrypted, nonce);
    }

    @Override
    public EncryptedData encrypt(byte[] plaintext, String secretPhrase, java.security.PublicKey theirPublicKey) {
        if (plaintext.length == 0) {
            return EMPTY_DATA;
        }
        byte[] nonce = new byte[32];
        RandomProvider.getSecureRandom().nextBytes(nonce);
        byte[] sharedKey = Crypto.getSharedKey(Crypto.getPrivateKey(secretPhrase), theirPublicKey.getEncoded(), nonce);
        byte[] data = Crypto.aesEncrypt(plaintext, sharedKey);
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.EncryptedData(data, nonce);
    }

    @Override
    public EncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException {
        if (length == 0) {
            return EMPTY_DATA;
        }
        if (length > maxLength) {
            throw new AplException.NotValidException("Max encrypted data length exceeded: " + length);
        }
        byte[] data = new byte[length];
        buffer.get(data);
        byte[] nonce = new byte[32];
        buffer.get(nonce);
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.EncryptedData(data, nonce);
    }

    @Override
    public EncryptedData readEncryptedData(byte[] bytes) {
        if (bytes.length == 0) {
            return EMPTY_DATA;
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        try {
            return readEncryptedData(buffer, bytes.length - 32, Integer.MAX_VALUE);
        } catch (AplException.NotValidException e) {
            throw new RuntimeException(e.toString(), e); // never
        }
    }

    @Override
    public int getEncryptedDataLength(byte[] plaintext) {
        if (plaintext.length == 0) {
            return 0;
        }
        return Crypto.aesEncrypt(plaintext, new byte[32]).length;
    }

    @Override
    public int getEncryptedBytesSize(byte[] plaintext) {
        if (plaintext.length == 0) {
            return 0;
        }
        return getEncryptedDataLength(plaintext) + 32;
    }

}
