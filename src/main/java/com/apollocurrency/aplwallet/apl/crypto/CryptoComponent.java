package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.crypto.advanced.AdvancedCryptography;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor;

import java.security.SecureRandom;

/**
 * Class to configure crypto-components
 * Add cryptography related components here
 */
public class CryptoComponent {

    private static final Cryptography crypto = new AdvancedCryptography();

    public static SecureRandom getSecureRandom() {
        return crypto.getSecureRandom();
    }

    public static PublicKeyEncoder getPublicKeyEncoder() {
        return crypto.getPublicKeyEncoder();
    }

    public static AsymmetricKeyGenerator getKeyGenerator() {
        return crypto.getKeyGenerator();
    }

    public static Signer getSigner() {
        return crypto.getSigner();
    }

    public static SharedKeyCalculator getSharedKeyCalculator() {
        return crypto.getSharedKeyCalculator();
    }

    public static DigestCalculator getDigestCalculator() {
        return crypto.getDigestCalculator();
    }

    public static DataEncryptor getDataEncryptor() {
        return crypto.getDataEncryptor();
    }

    public static AnonymousDataEncryptor getAnonymousDataEncryptor() {
        return crypto.getAnonymousDataEncryptor();
    }

    public static SymmetricEncryptor getSymmetricEncryptor() {
        return crypto.getSymmetricEncryptor();
    }

}
