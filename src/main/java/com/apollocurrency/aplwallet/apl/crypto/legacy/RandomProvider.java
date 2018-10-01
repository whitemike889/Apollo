package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.Apl;
import org.slf4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.slf4j.LoggerFactory.getLogger;

public class RandomProvider {

    private static final Logger LOG = getLogger(RandomProvider.class);

    private static final boolean useStrongSecureRandom = Apl.getBooleanProperty("apl.useStrongSecureRandom");

    private static final ThreadLocal<SecureRandom> secureRandom = new ThreadLocal<SecureRandom>() {
        @Override
        protected SecureRandom initialValue() {
            try {
                SecureRandom secureRandom = useStrongSecureRandom ? SecureRandom.getInstanceStrong() : new SecureRandom();
                secureRandom.nextBoolean();
                return secureRandom;
            } catch (NoSuchAlgorithmException e) {
                LOG.error("No secure random provider available");
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    };

    public static SecureRandom getSecureRandom() {
        return secureRandom.get();
    }

}
