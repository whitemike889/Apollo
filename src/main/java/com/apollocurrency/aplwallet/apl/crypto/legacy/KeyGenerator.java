package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator;

import java.security.InvalidKeyException;
import java.security.KeyPair;

public class KeyGenerator implements AsymmetricKeyGenerator {

    @Override
    public KeyPair generateKeyPair(String secretPhrase) {
        java.security.PublicKey publicKey = null;
        try {
            publicKey = new PublicKey(Crypto.getPublicKey(secretPhrase));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        java.security.PrivateKey privateKey = new PrivateKey(Crypto.getPrivateKey(secretPhrase));
        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public KeyPair generateFromKeySeed(byte[] keySeed) {
        java.security.PublicKey publicKey = null;
        try {
            publicKey = new PublicKey(Crypto.getPublicKey(keySeed));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        java.security.PrivateKey privateKey = new PrivateKey(Crypto.getPrivateKey(keySeed));
        return new KeyPair(publicKey, privateKey);
    }

}
