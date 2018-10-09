package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.util.Convert;

import java.security.MessageDigest;

public class Utils {

    private static DigestCalculator digestCalculator = new DigestCalculator();

    static byte[] calcKeySeed(String secretPhrase, byte[]... nonces) {
        MessageDigest digest = digestCalculator.createDigest();
        digest.update(Convert.toBytes(secretPhrase));
        for (byte[] nonce : nonces) {
            digest.update(nonce);
        }
        return digest.digest();
    }

}