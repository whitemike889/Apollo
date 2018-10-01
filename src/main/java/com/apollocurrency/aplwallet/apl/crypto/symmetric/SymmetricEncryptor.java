package com.apollocurrency.aplwallet.apl.crypto.symmetric;

public interface SymmetricEncryptor {

    byte[] encrypt(byte[] plaintext, byte[] key);
    byte[] decrypt(byte[] ivCiphertext, byte[] key);

}
