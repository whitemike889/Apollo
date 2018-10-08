package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoAsym;
import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.impl.AsymJCEImpl;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SharedKeyCalculator implements com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator {

    @Override
    public byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey) {
        FBCryptoAsym crypto = new AsymJCEImpl(FBCryptoParams.createDefault());
        try {
            crypto.setAsymmetricKeys(myPublicKey, myPrivateKey, theirPublicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException("SharedKeyCalculator.calcSharedKey() call failed. Check crypto config");
        }
        return crypto.calculateSharedKey();
    }

    @Override
    public byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey, byte[] nonce) {
        return getSharedKey(myPublicKey, myPrivateKey, theirPublicKey); // nonce ignored
    }

    @Override
    public int getCalculatedLength() {
        return 32;
    }

}
