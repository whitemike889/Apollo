package com.apollocurrency.aplwallet.apl.crypto.compatibility;

import com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.PublicKey;

public class PublicKeyEncoderCompat extends PublicKeyEncoder {

    private static final PublicKeyEncoder ENCODER_LEGACY = new com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKeyEncoder();
    private static final PublicKeyEncoder ENCODER_ADVANCED = new com.apollocurrency.aplwallet.apl.crypto.advanced.PublicKeyEncoder();

    @Override
    public byte[] encode(PublicKey key) {
        if(key == null) {
            return null;
        }
        if(key instanceof BCECPublicKey) {
            return ENCODER_ADVANCED.encode(key);
        } else if(key instanceof com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey) {
            return ENCODER_LEGACY.encode(key);
        }
        throw new RuntimeException("Invalid key type");
    }

    @Override
    public PublicKey decode(byte[] bytes) {
        if(bytes == null) {
            return null;
        }
        if(bytes.length == com.apollocurrency.aplwallet.apl.crypto.advanced.PublicKeyEncoder.ENCODED_BYTE_SIZE) {
            return ENCODER_ADVANCED.decode(bytes);
        } else if(bytes.length == com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKeyEncoder.ENCODED_BYTE_SIZE) {
            return ENCODER_LEGACY.decode(bytes);
        }
        throw new RuntimeException("Invalid key bytes");
    }

}
