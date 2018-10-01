package com.apollocurrency.aplwallet.apl.crypto.legacy;

public class SymmetricEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor {

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] key) {
        return Crypto.aesEncrypt(plaintext, key);
    }

    @Override
    public byte[] decrypt(byte[] ivCiphertext, byte[] key) {
        return Crypto.aesDecrypt(ivCiphertext, key);
    }

}
