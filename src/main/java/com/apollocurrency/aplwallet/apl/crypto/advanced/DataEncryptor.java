package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.EncryptedData;
import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

public class DataEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor {

    private static final SecureRandom random = new SecureRandom();

    private static final String ADDITIONAL_DATA = "<<<TEXT TO STAY OPEN>>>";
    private static final EncryptedData EMPTY_DATA = new com.apollocurrency.aplwallet.apl.crypto.advanced.EncryptedData(null);

    private static KeyGenerator keyGenerator = new KeyGenerator();
    private static SharedKeyCalculator sharedKeyCalculator = new SharedKeyCalculator();

    @Override
    public EncryptedData createEncryptedData(byte[] encrypted, byte[] nonce) {
        // TODO check this;
        // nonce is just ignored here and passed as part of @encrypted parameter
        return new com.apollocurrency.aplwallet.apl.crypto.advanced.EncryptedData(
                AEADMessage.fromBytes(encrypted, FBCryptoParams.createDefault())
        );
    }

    @Override
    public EncryptedData encrypt(byte[] plaintext, String secretPhrase, PublicKey theirPublicKey) {

        if (plaintext.length == 0) {
            return EMPTY_DATA;
        }

        KeyPair keyPair = keyGenerator.generateKeyPair(secretPhrase);
        byte[] key = sharedKeyCalculator.getSharedKey(keyPair.getPublic(), keyPair.getPrivate(), theirPublicKey);

        byte[] salt = {0,0,0,0}; // just 0 salt
        byte[] nonce = new byte[8];

        random.nextBytes(nonce);

        InitializationVector iv = new FBInitializationVector(salt, nonce);
        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, key, ADDITIONAL_DATA.getBytes());
            return new com.apollocurrency.aplwallet.apl.crypto.advanced.EncryptedData(encryptor.encrypt(plaintext));
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return EMPTY_DATA;

    }

    @Override
    public EncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException {
        if (length == 0) {
            return EMPTY_DATA;
        }
        if (length > maxLength) {
            throw new AplException.NotValidException("Max encrypted data length exceeded: " + length);
        }
        byte[] bytes = new byte[length];
        buffer.get(bytes);

        AEADMessage message = AEADMessage.fromBytes(bytes, FBCryptoParams.createDefault());
        return new com.apollocurrency.aplwallet.apl.crypto.advanced.EncryptedData(message);
    }

    @Override
    public EncryptedData readEncryptedData(byte[] bytes) {
        if (bytes.length == 0) {
            return EMPTY_DATA;
        }
        AEADMessage message = AEADMessage.fromBytes(bytes, FBCryptoParams.createDefault());
        return new com.apollocurrency.aplwallet.apl.crypto.advanced.EncryptedData(message);
    }

    @Override
    public int getEncryptedDataLength(byte[] plaintext) {
        return getDummyEncryptedMessage(plaintext).encrypted.length;
    }

    @Override
    public int getEncryptedBytesSize(byte[] plaintext) {
        return getDummyEncryptedMessage(plaintext).calcBytesSize();
    }

    private static AEADMessage getDummyEncryptedMessage(byte[] plaintext) {

        if (plaintext.length == 0) {
            return null;
        }

        byte[] key = new byte[32 /* 256bit */];
        byte[] iv = new byte[12];
        random.nextBytes(key);
        random.nextBytes(iv);

        InitializationVector vector = new FBInitializationVector(iv);
        try {
            AEADEncryptor encryptor = new AEADEncryptor(vector, key, ADDITIONAL_DATA.getBytes());
            return encryptor.encrypt(plaintext);
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;

    }

}
