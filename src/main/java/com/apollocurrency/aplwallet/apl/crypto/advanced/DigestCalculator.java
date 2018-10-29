package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoParams;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestCalculator implements com.apollocurrency.aplwallet.apl.crypto.DigestCalculator {

    public static final int CALCULATED_LENGTH = 64;

    private static final FBCryptoParams fbCryptoDefaultParams = FBCryptoParams.createDefault();

    @Override
    public byte[] calcDigest(byte[] message) {
        MessageDigest hash = createDigest();
        hash.update(message);
        return hash.digest();
    }

    @Override
    public MessageDigest createDigest() {
        try {
            return MessageDigest.getInstance(fbCryptoDefaultParams.getDigester());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

}
