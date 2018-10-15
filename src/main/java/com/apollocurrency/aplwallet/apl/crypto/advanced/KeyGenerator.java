package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator;
import io.firstbridge.cryptolib.FBCryptoParams;

import java.security.KeyPair;

public class KeyGenerator implements AsymmetricKeyGenerator {

    private io.firstbridge.cryptolib.KeyGenerator keyGenerator = new io.firstbridge.cryptolib.KeyGenerator(FBCryptoParams.createDefault());

    @Override
    public KeyPair generateKeyPair(String secretPhrase) {
        return keyGenerator.generateKeys(secretPhrase);
    }

    @Override
    public KeyPair generateFromKeySeed(byte[] keySeed) {
        return keyGenerator.generateKeys(new String(keySeed));
    }

}
