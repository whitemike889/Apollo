package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.dataformat.AEAD;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;

import java.security.KeyPair;
import java.security.PublicKey;

public class EncryptedData implements com.apollocurrency.aplwallet.apl.crypto.symmetric.EncryptedData {

    private static KeyGenerator keyGenerator = new KeyGenerator();
    private static SharedKeyCalculator sharedKeyCalculator = new SharedKeyCalculator();

    private final AEADMessage message;

    public EncryptedData(AEADMessage message) {
        this.message = message;
    }

    @Override
    public byte[] decrypt(String secretPhrase, PublicKey theirPublicKey) {
        KeyPair keyPair = keyGenerator.generateKeyPair(secretPhrase);
        byte[] key = sharedKeyCalculator.getSharedKey(keyPair.getPublic(), keyPair.getPrivate(), theirPublicKey);
        return decrypt(key);
    }

    @Override
    public byte[] decrypt(byte[] symmetricKey) {

        if (message == null) {
            return null;
        } else if(message.encrypted.length == 0) {
            return message.encrypted;
        }

        InitializationVector iv = new FBInitializationVector(message.getIV());

        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, symmetricKey, message.aatext);
            AEAD aead = encryptor.decrypt(message.toBytes());
            return aead.decrypted;
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public byte[] getData() {
        // TODO check this
        // return here the whole thing because we ignore nonce
        return getBytes();
    }

    @Override
    public byte[] getNonce() {
        // TODO check this
        // nonce just zero here because it stored together with data and additional data
        return new byte[0];
    }

    @Override
    public byte[] getBytes() {
        return message.toBytes();
    }

    @Override
    public int getBytesSize() {
        return message.calcBytesSize();
    }

}
