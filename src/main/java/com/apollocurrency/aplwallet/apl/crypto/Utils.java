package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.Account;
import com.apollocurrency.aplwallet.apl.util.Convert;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

public class Utils {

    public static byte[] calcKeySeed(String secretPhrase, byte[]... nonces) {
        MessageDigest digest = CryptoComponent.getDigestCalculator().createDigest();
        digest.update(Convert.toBytes(secretPhrase));
        for (byte[] nonce : nonces) {
            digest.update(nonce);
        }
        return digest.digest();
    }

    public static Cryptography.Type getPublicKeyCryptoType(PublicKey key) {

        if(key instanceof BCECPublicKey) {
            return Cryptography.Type.ADVANCED;
        } else if(key instanceof com.apollocurrency.aplwallet.apl.crypto.legacy.PublicKey) {
            return Cryptography.Type.LEGACY;
        }

        throw new RuntimeException("Unknown key type. Check crypto config");

    }

    public static Cryptography.Type getAccountCryptoType(String passPhrase) {
        if(checkAccountCryptoType(passPhrase, Cryptography.Type.ADVANCED)) {
            return Cryptography.Type.ADVANCED;
        } else if(checkAccountCryptoType(passPhrase, Cryptography.Type.LEGACY)){
            return Cryptography.Type.LEGACY;
        }
        throw new RuntimeException("Invalid pass phrase");
    }

    public static boolean checkAccountCryptoType(String passPhrase, Cryptography.Type type) {
        KeyPair keyPair = CryptoComponent.getCryptography(type).getKeyGenerator().generateKeyPair(passPhrase);
        long id = Account.getId(keyPair.getPublic());
        return Account.getPublicKey(id) != null;
    }

}