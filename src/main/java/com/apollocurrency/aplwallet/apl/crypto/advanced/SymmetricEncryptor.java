package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.dataformat.AEAD;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;

import java.security.SecureRandom;

public class SymmetricEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor {

    // TODO discus if its better to use encryptSymmetric without additional data

    private static final String ADDITIONAL_DATA = "<<<TEXT TO STAY OPEN>>>";
    private static final SecureRandom random = new SecureRandom();

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        byte[] salt = {0,0,0,0}; // just 0 salt
        byte[] nonce = new byte[8];

        random.nextBytes(nonce);

        InitializationVector iv = new FBInitializationVector(salt, nonce);
        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, key, ADDITIONAL_DATA.getBytes());
            return encryptor.encrypt(plaintext).toBytes();
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] ivCiphertext, byte[] key) {

        AEADMessage message = AEADMessage.fromBytes(ivCiphertext, FBCryptoParams.createDefault());
        InitializationVector iv = new FBInitializationVector(message.getIV());

        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, key, message.aatext);
            AEAD aead = encryptor.decrypt(message.toBytes());
            return aead.decrypted;
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;
    }

}
