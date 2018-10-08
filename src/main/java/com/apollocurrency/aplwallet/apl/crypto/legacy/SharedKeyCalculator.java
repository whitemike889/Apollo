package com.apollocurrency.aplwallet.apl.crypto.legacy;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SharedKeyCalculator implements com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator {

    @Override
    public byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey) {
        return Crypto.getSharedKey(myPrivateKey.getEncoded(), theirPublicKey.getEncoded());
    }

    @Override
    public byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey, byte[] nonce) {
        return Crypto.getSharedKey(myPrivateKey.getEncoded(), theirPublicKey.getEncoded(), nonce);
    }

    @Override
    public int getCalculatedLength() {
        return 32;
    }
}
