package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoAsym;
import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;
import io.firstbridge.cryptolib.impl.AsymJCEImpl;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Signer implements com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer {

    public static final int SIGNATURE_LENGTH = 4 /* length */ + 140 /* max key size */;


    /**
     * Signs message with privateKey and return signature aligned to the constant length
     * @param message
     * @param privateKey
     * @return
     * @throws CryptoNotValidException
     */
    @Override
    public byte[] sign(byte[] message, PrivateKey privateKey) {

        /* get signature byte array */
        FBCryptoAsym crypto = new AsymJCEImpl(FBCryptoParams.createDefault());
        crypto.setOurKeyPair(new KeyPair(null, privateKey));
        byte[] signature = new byte[0];
        try {
            signature = crypto.sign(message);
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        /* wrap signature as follows (length, signature, padding zero bytes) */
        byte[] bytes = new byte[SIGNATURE_LENGTH];
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.putInt(signature.length);
        buffer.put(signature);

        return bytes;

    }

    /**
     * Verifies signature using theirPublicKey
     * @param message
     * @param signatureBytes
     * @param theirPublicKey
     * @return
     * @throws CryptoNotValidException
     */
    @Override
    public boolean verify(byte[] message, byte[] signatureBytes, PublicKey theirPublicKey) {

        if(signatureBytes.length != SIGNATURE_LENGTH) {
            throw  new RuntimeException("Invalid signature length. Check getSignatureLength() method of the Signer");
        }

        /* unwrap signature */
        ByteBuffer buffer = ByteBuffer.wrap(signatureBytes);
        int length = buffer.getInt();
        byte[] signature = new byte[length];
        buffer.get(signature);

        /* verify signature */
        FBCryptoAsym crypto = new AsymJCEImpl(FBCryptoParams.createDefault());
        crypto.setTheirPublicKey(theirPublicKey);
        return crypto.verifySignature(message, signature);

    }


}
