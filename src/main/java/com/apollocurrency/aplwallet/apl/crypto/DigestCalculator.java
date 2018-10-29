package com.apollocurrency.aplwallet.apl.crypto;

import java.security.MessageDigest;

public interface DigestCalculator {

    /**
     * Calc message digest
     * @param message
     * @return
     */
    byte[] calcDigest(byte[] message);

    /**
     * create digest
     * @return
     */
    MessageDigest createDigest();

}
