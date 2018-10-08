package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.FBCryptoSym;
import io.firstbridge.cryptolib.dataformat.AEAD;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;
import io.firstbridge.cryptolib.impl.SymJCEImpl;

public class AEADEncryptor {

    private final byte[] aeaData;
    private final FBCryptoSym crypto;

    public AEADEncryptor(InitializationVector iv, byte[] key, byte[] aeaData) throws CryptoNotValidException {
        this.aeaData = aeaData;
        this.crypto = new SymJCEImpl(FBCryptoParams.createDefault());
        this.crypto.setSymmetricIV(iv.getBytes());
        this.crypto.setSymmetricKey(key);
    }

    /**
     * Encrypt and return result in form of @see AEADMessage
     * @param plainData
     * @return
     * @throws CryptoNotValidException
     */
    public AEADMessage encrypt(byte[] plainData) throws CryptoNotValidException {
        return crypto.encryptSymmetricWithAEAData(plainData, aeaData);
    }

    /**
     * Decrypt encrypted data and return result in form of @see AEAD
     * @param encryptedData
     * @return
     * @throws CryptoNotValidException
     */
    public AEAD decrypt(byte[] encryptedData) throws CryptoNotValidException {
        crypto.setSymmetricNounce(null); // prevent nonce reuse error
        return crypto.decryptSymmetricWithAEAData(encryptedData);
    }

}
