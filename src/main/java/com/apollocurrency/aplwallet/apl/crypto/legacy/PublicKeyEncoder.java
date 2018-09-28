package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.AplException;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PublicKey;

public class PublicKeyEncoder extends com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder {

    @Override
    public byte[] encode(PublicKey key) {
        if(!com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey.FORMAT.equals(key.getFormat())) {
            throw new InvalidParameterException("Invalid public key format. Check crypto config");
        }
        return key.getEncoded();
    }

    @Override
    public PublicKey decode(byte[] bytes) {
        if(bytes.length != getEncodedLength()) {
            throw new InvalidParameterException("Invalid public key format. Check crypto config");
        }
        try {
            return new com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey(bytes);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null; // TODO check this
        }

    }

    @Override
    public int getEncodedLength() {
        return 32;
    }

}
