package com.apollocurrency.aplwallet.apl.crypto.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SharedKeyCalculator {

    byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey);

    byte[] getSharedKey(PublicKey myPublicKey, PrivateKey myPrivateKey, PublicKey theirPublicKey, byte[] nonce);

    /**
     * length in bytes if the calculated key
     * @return
     */
    int getCalculatedLength();

}