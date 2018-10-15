package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.crypto.asymmetric.AsymmetricKeyGenerator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.PublicKeyEncoder;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.SharedKeyCalculator;
import com.apollocurrency.aplwallet.apl.crypto.asymmetric.signature.Signer;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.DataEncryptor;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.SymmetricEncryptor;

import java.security.SecureRandom;

public interface Cryptography {

    SecureRandom getSecureRandom();

    PublicKeyEncoder getPublicKeyEncoder();

    AsymmetricKeyGenerator getKeyGenerator();

    Signer getSigner();

    SharedKeyCalculator getSharedKeyCalculator();

    DigestCalculator getDigestCalculator();

    DataEncryptor getDataEncryptor();

    AnonymousDataEncryptor getAnonymousDataEncryptor();

    SymmetricEncryptor getSymmetricEncryptor();

}
