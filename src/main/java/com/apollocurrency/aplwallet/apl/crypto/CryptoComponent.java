package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.crypto.advanced.AdvancedCryptography;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer;
import com.apollocurrency.aplwallet.apl.crypto.compatibility.PublicKeyEncoderCompat;
import com.apollocurrency.aplwallet.apl.crypto.compatibility.SignerCompat;
import com.apollocurrency.aplwallet.apl.crypto.legacy.LegacyCryptography;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor;

import java.security.SecureRandom;

/**
 * Class to configure crypto-components
 * Add cryptography related components here
 */
public class CryptoComponent {

    private static final Cryptography CRYPTO_ADVANCED = new AdvancedCryptography();
    private static final Cryptography CRYPTO_LEGACY = new LegacyCryptography();

    private static final PublicKeyEncoder KEY_ENCODER_COMPAT = new PublicKeyEncoderCompat();
    private static final Signer SIGNER_COMPAT = new SignerCompat();

    public static Cryptography getCryptography(Cryptography.Type type) {

        switch (type) {

            case LEGACY:
                return CRYPTO_LEGACY;

            case ADVANCED:
                return CRYPTO_ADVANCED;

        }

        throw new RuntimeException("Unknown crypto type");

    }

    public static SecureRandom getSecureRandom() {
        return CRYPTO_ADVANCED.getSecureRandom();
    }

    public static PublicKeyEncoder getPublicKeyEncoder() {
        return KEY_ENCODER_COMPAT;
    }

    public static int getPublicKeyEncodedByteSize(Cryptography.Type type) {
        switch (type) {
            case LEGACY:
                return com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKeyEncoder.ENCODED_BYTE_SIZE;
            case ADVANCED:
                return com.apollocurrency.aplwallet.apl.crypto.advanced.PublicKeyEncoder.ENCODED_BYTE_SIZE;
        }
        throw new RuntimeException("Unknown crypto type");
    }

    /**
     * TODO remove this method
     * @return
     */
    public static AsymmetricKeyGenerator getKeyGenerator() {
        return getCryptography(Cryptography.Type.ADVANCED).getKeyGenerator();
    }

    /**
     * TODO remove this method
     * @return
     */
    public static Signer getSigner() {
        return SIGNER_COMPAT;
    }

    public static int getSignatureLength(Cryptography.Type type) {
        switch (type) {
            case LEGACY:
                return com.apollocurrency.aplwallet.apl.crypto.legacy.Signer.SIGNATURE_LENGTH;
            case ADVANCED:
                return com.apollocurrency.aplwallet.apl.crypto.advanced.Signer.SIGNATURE_LENGTH;
        }
        throw new RuntimeException("Unknown crypto type");
    }

    /**
     * TODO remove this method
     * @return
     */
    public static SharedKeyCalculator getSharedKeyCalculator() {
        return getCryptography(Cryptography.Type.ADVANCED).getSharedKeyCalculator();
    }

    /**
     * TODO remove this method
     * @return
     */
    public static DigestCalculator getDigestCalculator() {
        return getCryptography(Cryptography.Type.ADVANCED).getDigestCalculator();
    }

    /**
     * TODO remove this method
     * @return
     */
    public static DataEncryptor getDataEncryptor() {
        return getCryptography(Cryptography.Type.ADVANCED).getDataEncryptor();
    }

    /**
     * TODO remove this method
     * @return
     */
    public static AnonymousDataEncryptor getAnonymousDataEncryptor() {
        return getCryptography(Cryptography.Type.ADVANCED).getAnonymousDataEncryptor();
    }

    /**
     * TODO remove this method
     * @return
     */
    public static SymmetricEncryptor getSymmetricEncryptor() {
        return getCryptography(Cryptography.Type.ADVANCED).getSymmetricEncryptor();
    }

}
