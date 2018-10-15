package com.apollocurrency.aplwallet.apl.crypto.advanced;

import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.impl.JCEInitializer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class PublicKeyEncoder  extends com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder {

    private JCEInitializer initializer = new JCEInitializer();

    private static final FBCryptoParams cryptoParams = FBCryptoParams.createDefault();

    public static final String KEY_ALGORITHM = "ECDSA";
    public static final String PROVIDER_BOUNCY_CASTLE = "BC";
    public static final int ENCODED_BYTE_SIZE = 133;

    @Override
    public byte[] encode(PublicKey key) {
        if(key == null) {
            return null;
        }
        try {
            return getBCECPublicKeyPointData(key);
        } catch (InvalidKeyException e) {
            e.printStackTrace(); // TODO think of better error handling
        }
        return null;
    }

    @Override
    public PublicKey decode(byte[] bytes) {
        if(bytes == null) {
            return null;
        }
        try {
            return reconstructBCECPublicKey(bytes);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace(); // TODO think of better error handling
        }
        return null;
    }

    @Override
    public int getEncodedLength() {
        return ENCODED_BYTE_SIZE;
    }

    /**
     * Get point data from BCECPublicKey
     * @param key
     * @return
     */
    private static byte[] getBCECPublicKeyPointData(java.security.PublicKey key) throws InvalidKeyException {
        if(key instanceof BCECPublicKey) {
            return ((BCECPublicKey) key).getQ().getEncoded(false);
        }
        throw new InvalidKeyException("Key not supported by the system");
    }

    /**
     * Create BCECPublicKey from point data. Using FBCrypto.DEFAULT_CURVE
     *
     * @param pointEncoded
     * @return
     */
    private static java.security.PublicKey reconstructBCECPublicKey(byte[] pointEncoded) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec(cryptoParams.getDefaultCurve());
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM, PROVIDER_BOUNCY_CASTLE);
        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, pointEncoded);
        java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point,params2);
        return factory.generatePublic(keySpec);
    }

}