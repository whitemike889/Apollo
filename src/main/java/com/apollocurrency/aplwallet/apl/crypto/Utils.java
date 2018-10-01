package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.util.Convert;

import java.security.MessageDigest;

public class Utils {

    public static byte[] calcKeySeed(String secretPhrase, byte[]... nonces) {
        MessageDigest digest = CryptoComponent.getDigestCalculator().createDigest();
        digest.update(Convert.toBytes(secretPhrase));
        for (byte[] nonce : nonces) {
            digest.update(nonce);
        }
        return digest.digest();
    }

}