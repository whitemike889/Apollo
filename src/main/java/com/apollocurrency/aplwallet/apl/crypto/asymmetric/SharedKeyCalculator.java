package com.apollocurrency.aplwallet.apl.crypto.asymmetric;

public interface SharedKeyCalculator {

    byte[] getSharedKey(java.security.PrivateKey myPrivateKey, java.security.PublicKey theirPublicKey);

    byte[] getSharedKey(java.security.PrivateKey myPrivateKey, java.security.PublicKey theirPublicKey, byte[] nonce);

    /**
     * length in bytes if the calculated key
     * @return
     */
    int getCalculatedLength();

}