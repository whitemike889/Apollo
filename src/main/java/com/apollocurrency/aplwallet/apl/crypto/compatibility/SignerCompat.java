package com.apollocurrency.aplwallet.apl.crypto.compatibility;

import com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SignerCompat implements Signer {

    private static final Signer LEGACY_SIGNER = new com.apollocurrency.aplwallet.apl.crypto.legacy.Signer();
    private static final Signer ADVANCED_SIGNER = new com.apollocurrency.aplwallet.apl.crypto.advanced.Signer();

    @Override
    public byte[] sign(byte[] message, PrivateKey privateKey) {
        if(privateKey instanceof BCECPrivateKey) {
            return ADVANCED_SIGNER.sign(message, privateKey);
        } else if(privateKey instanceof com.apollocurrency.aplwallet.apl.crypto.legacy.PrivateKey) {
            return LEGACY_SIGNER.sign(message, privateKey);
        }
        throw new RuntimeException("Invalid privateKey");
    }

    @Override
    public boolean verify(byte[] message, byte[] signature, PublicKey theirPublicKey) {
        if(theirPublicKey instanceof BCECPublicKey) {
            return ADVANCED_SIGNER.verify(message, signature, theirPublicKey);
        } else if(theirPublicKey instanceof com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey) {
            return LEGACY_SIGNER.verify(message, signature, theirPublicKey);
        }
        throw new RuntimeException("Invalid theirPublicKey");
    }

}
