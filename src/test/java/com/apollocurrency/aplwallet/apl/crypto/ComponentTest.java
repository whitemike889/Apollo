package com.apollocurrency.aplwallet.apl.crypto;

import com.apollocurrency.aplwallet.apl.crypto.advanced.AdvancedCryptography;
import com.apollocurrency.aplwallet.apl.crypto.legacy.LegacyCryptography;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymouslyEncryptedData;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.EncryptedData;
import org.junit.Assert;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;

public class ComponentTest {

    @Test
    public void signerTest() {
        testSigner(new LegacyCryptography());
        testSigner(new AdvancedCryptography());
    }

    @Test
    public void dataEncryptorTest() {
        testDataEncryptor(new LegacyCryptography());
        testDataEncryptor(new AdvancedCryptography());
    }

    @Test
    public void anonymousEncryptorTest() throws InvalidKeyException {
        testAnonymousDataEncryptor(new LegacyCryptography());
        testAnonymousDataEncryptor(new AdvancedCryptography());
    }

    private void testSigner(Cryptography crypto) {

        String message = "message";
        String secretPhrase = "pass";

        KeyPair keyPair = crypto.getKeyGenerator().generateKeyPair(secretPhrase);
        byte[] signature = crypto.getSigner().sign(message.getBytes(), keyPair.getPrivate());

        Assert.assertEquals(signature.length, crypto.getSigner().getSignatureLength());

        boolean valid = crypto.getSigner().verify(message.getBytes(), signature, keyPair.getPublic());

        Assert.assertTrue(valid);

    }


    private void testDataEncryptor(Cryptography crypto) {

        String message = "message";
        String myPhrase = "myPass";
        String theirPhrase = "theirPass";

        KeyPair myKeys = crypto.getKeyGenerator().generateKeyPair(myPhrase);
        KeyPair theirKeys = crypto.getKeyGenerator().generateKeyPair(theirPhrase);

        EncryptedData sentData = crypto.getDataEncryptor().encrypt(message.getBytes(), myPhrase, theirKeys.getPublic());

        EncryptedData receivedData = crypto.getDataEncryptor().createEncryptedData(sentData.getData(), sentData.getNonce());

        String decryptedMessage = new String(receivedData.decrypt(theirPhrase, myKeys.getPublic()));

        Assert.assertEquals(message, decryptedMessage);

    }

    private void testAnonymousDataEncryptor(Cryptography crypto) throws InvalidKeyException {

        String message = "message";
        String myPhrase = "myPass";
        String theirPhrase = "theirPass";

        KeyPair myKeys = crypto.getKeyGenerator().generateKeyPair(myPhrase);
        KeyPair theirKeys = crypto.getKeyGenerator().generateKeyPair(theirPhrase);

        byte[] nonce = new byte[8];
        crypto.getSecureRandom().nextBytes(nonce);

        AnonymouslyEncryptedData sentData = crypto.getAnonymousDataEncryptor().encrypt(message.getBytes(), myPhrase, theirKeys.getPublic(), nonce);

        AnonymouslyEncryptedData receivedData = crypto.getAnonymousDataEncryptor().createEncryptedData(sentData.getData(), sentData.getPublicKey());

        String decryptedMessage = new String(receivedData.decrypt(theirPhrase));

        Assert.assertEquals(message, decryptedMessage);

    }

}
