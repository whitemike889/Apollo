package com.apollocurrency.aplwallet.apl.crypto.legacy;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Signer implements com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer {

    public static final int SIGNATURE_LENGTH = 64;

    @Override
    public byte[] sign(byte[] message, PrivateKey privateKey) {
        return Crypto.signWithPrivateKey(message, privateKey.getEncoded());
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, PublicKey theirPublicKey) {
        if(signature.length != SIGNATURE_LENGTH) {
            throw new RuntimeException("Invalid signature length");
        }
        return Crypto.verify(signature, message, theirPublicKey.getEncoded());
    }

}
