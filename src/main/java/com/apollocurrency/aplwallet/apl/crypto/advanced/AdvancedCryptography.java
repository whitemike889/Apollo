package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.crypto.Cryptography;

import java.security.SecureRandom;

public class AdvancedCryptography implements Cryptography {

    private static SecureRandom secureRandom = new SecureRandom();

    private static final com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder PUBLIC_KEY_ENCODER_INSTANCE = new PublicKeyEncoder();
    private static final com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator ASYMMETRIC_KEY_GENERATOR = new KeyGenerator();
    private static final com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer SIGNER = new Signer();
    private static final com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator SHARED_KEY_CALCULATOR = new SharedKeyCalculator();
    private static final com.apollocurrency.aplwallet.apl.crypto.DigestCalculator DIGEST_CALCULATOR = new DigestCalculator();
    private static final com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor DATA_ENCRYPTOR = new DataEncryptor();
    private static final com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor ANONYMOUS_DATA_ENCRYPTOR = new AnonymousDataEncryptor();
    private static final com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor SYMMETRIC_ENCRYPTOR = new SymmetricEncryptor();

    @Override
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder getPublicKeyEncoder() {
        return PUBLIC_KEY_ENCODER_INSTANCE;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator getKeyGenerator() {
        return ASYMMETRIC_KEY_GENERATOR;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer getSigner() {
        return SIGNER;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator getSharedKeyCalculator() {
        return SHARED_KEY_CALCULATOR;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.DigestCalculator getDigestCalculator() {
        return DIGEST_CALCULATOR;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor getDataEncryptor() {
        return DATA_ENCRYPTOR;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor getAnonymousDataEncryptor() {
        return ANONYMOUS_DATA_ENCRYPTOR;
    }

    @Override
    public com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor getSymmetricEncryptor() {
        return SYMMETRIC_ENCRYPTOR;
    }

}
