package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymouslyEncryptedData;
import io.firstbridge.cryptolib.FBCryptoParams;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

public class AnonymousDataEncryptor implements com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymousDataEncryptor {

    private static final SecureRandom random = new SecureRandom();

    private static final String ADDITIONAL_DATA = "<<<TEXT TO STAY OPEN>>>";

    private static final PublicKeyEncoder keyEncoder = new PublicKeyEncoder();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final SharedKeyCalculator sharedKeyCalculator = new SharedKeyCalculator();

    @Override
    public AnonymouslyEncryptedData createEncryptedData(byte[] encrypted, PublicKey publicKey) throws InvalidKeyException {
        return new com.apollocurrency.aplwallet.apl.crypto.advanced.AnonymouslyEncryptedData(
                AEADMessage.fromBytes(encrypted, FBCryptoParams.createDefault()),
                publicKey
        );
    }

    @Override
    public AnonymouslyEncryptedData encrypt(byte[] plaintext, String secretPhrase, PublicKey theirPublicKey, byte[] nonce) throws InvalidKeyException {

        if (!(theirPublicKey instanceof BCECPublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }

        byte[] keySeed = Utils.calcKeySeed(secretPhrase, theirPublicKey.getEncoded(), nonce);
        KeyPair keyPair = keyGenerator.generateFromKeySeed(keySeed);

        byte[] sharedKey = sharedKeyCalculator.getSharedKey(keyPair.getPublic(), keyPair.getPrivate(), theirPublicKey);

        byte[] salt = {0,0,0,0}; // just 0 salt
        byte[] msgNonce = new byte[8];

        random.nextBytes(msgNonce);

        InitializationVector iv = new FBInitializationVector(salt, nonce);
        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, sharedKey, ADDITIONAL_DATA.getBytes());
            return new com.apollocurrency.aplwallet.apl.crypto.advanced.AnonymouslyEncryptedData(encryptor.encrypt(plaintext), keyPair.getPublic());
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;

    }

    @Override
    public AnonymouslyEncryptedData readEncryptedData(ByteBuffer buffer, int length, int maxLength) throws AplException.NotValidException, InvalidKeyException {

        if (length > maxLength) {
            throw new AplException.NotValidException("Max encrypted data length exceeded: " + length);
        }
        byte[] data = new byte[length];
        buffer.get(data);
        byte[] publicKeyBytes = new byte[keyEncoder.getEncodedLength()];
        buffer.get(publicKeyBytes);
        return createEncryptedData(data, keyEncoder.decode(publicKeyBytes));

    }

    @Override
    public AnonymouslyEncryptedData readEncryptedData(byte[] bytes) throws InvalidKeyException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        try {
            return readEncryptedData(buffer, bytes.length - keyEncoder.getEncodedLength(), Integer.MAX_VALUE);
        } catch (AplException.NotValidException e) {
            throw new RuntimeException(e.toString(), e); // never
        }
    }

}
