package com.apollocurrency.aplwallet.apl.crypto.legacy;

import java.security.MessageDigest;

public class DigestCalculator implements com.apollocurrency.aplwallet.apl.crypto.DigestCalculator {

    public static final int CALCULATED_LENGTH = 32;

    @Override
    public byte[] calcDigest(byte[] message) {
        return Crypto.sha256().digest(message);
    }

    @Override
    public MessageDigest createDigest() {
        return Crypto.sha256();
    }

}
