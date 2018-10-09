package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymouslyEncryptedData;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.PublicKey;

public class AnonymousDataEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor {

    @Override
    public AnonymouslyEncryptedData createEncryptedData(byte[] encrypted, PublicKey publicKey) throws InvalidKeyException {
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.AnonymouslyEncryptedData(encrypted, publicKey);
    }

    @Override
    public AnonymouslyEncryptedData encrypt(byte[] plaintext, String secretPhrase, java.security.PublicKey theirPublicKey, byte[] nonce) throws InvalidKeyException {
        if (!(theirPublicKey instanceof com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }
        byte[] keySeed = Crypto.calcKeySeed(secretPhrase, theirPublicKey.getEncoded(), nonce);
        byte[] myPrivateKey = Crypto.getPrivateKey(keySeed);
        byte[] myPublicKey = Crypto.getPublicKey(keySeed);
        byte[] sharedKey = Crypto.getSharedKey(myPrivateKey, theirPublicKey.getEncoded());
        byte[] data = Crypto.aesGCMEncrypt(plaintext, sharedKey);
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.AnonymouslyEncryptedData(data, new com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey(myPublicKey));
    }

    @Override
    public AnonymouslyEncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException, InvalidKeyException {
        if (length > maxLength) {
            throw new AplException.NotValidException("Max encrypted data length exceeded: " + length);
        }
        byte[] data = new byte[length];
        buffer.get(data);
        byte[] publicKey = new byte[32];
        buffer.get(publicKey);
        return new com.apollocurrency.aplwallet.apl.crypto.legacy.AnonymouslyEncryptedData(data, new com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey(publicKey));
    }

    @Override
    public AnonymouslyEncryptedData readEncryptedData(byte[] bytes) throws InvalidKeyException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        try {
            return readEncryptedData(buffer, bytes.length - 32, Integer.MAX_VALUE);
        } catch (AplException.NotValidException e) {
            throw new RuntimeException(e.toString(), e); // never
        }
    }

}
