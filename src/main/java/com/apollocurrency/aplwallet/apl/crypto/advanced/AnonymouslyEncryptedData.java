package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.util.Convert;
import io.firstbridge.cryptolib.dataformat.AEAD;
import io.firstbridge.cryptolib.dataformat.AEADMessage;
import io.firstbridge.cryptolib.exception.CryptoNotValidException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.KeyPair;

public class AnonymouslyEncryptedData implements com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymouslyEncryptedData {

    private static final PublicKeyEncoder keyEncoder = new PublicKeyEncoder();
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final SharedKeyCalculator sharedKeyCalculator = new SharedKeyCalculator();

    private final AEADMessage message;
    private final java.security.PublicKey publicKey;


    public AnonymouslyEncryptedData(AEADMessage message, java.security.PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BCECPublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }
        this.message = message;
        this.publicKey = publicKey;
    }

    @Override
    public byte[] decrypt(String secretPhrase) {
        KeyPair keyPair = keyGenerator.generateKeyPair(secretPhrase);
        byte[] sharedKey = sharedKeyCalculator.getSharedKey(keyPair.getPublic(), keyPair.getPrivate(), publicKey);

        InitializationVector iv = new FBInitializationVector(message.getIV());

        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, sharedKey, message.aatext);
            AEAD aead = encryptor.decrypt(message.toBytes());
            return aead.decrypted;
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;

    }

    @Override
    public byte[] decrypt(byte[] keySeed, java.security.PublicKey theirPublicKey) throws InvalidKeyException {

        if (!(publicKey instanceof BCECPublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }
        KeyPair keyPair = keyGenerator.generateFromKeySeed(keySeed);
        if (!keyPair.getPublic().equals(publicKey)) {
            throw new RuntimeException("Data was not encrypted using this keySeed");
        }

        byte[] sharedKey = sharedKeyCalculator.getSharedKey(keyPair.getPublic(), keyPair.getPrivate(), publicKey);

        InitializationVector iv = new FBInitializationVector(message.getIV());

        try {
            AEADEncryptor encryptor = new AEADEncryptor(iv, sharedKey, message.aatext);
            AEAD aead = encryptor.decrypt(message.toBytes());
            return aead.decrypted;
        } catch (CryptoNotValidException e) {
            e.printStackTrace();
        }

        return null;

    }

    @Override
    public byte[] getData() {
        return message.toBytes();
    }

    @Override
    public java.security.PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public int getBytesSize() {
        return message.calcBytesSize() + keyEncoder.getEncodedLength();
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(message.calcBytesSize() + keyEncoder.getEncodedLength());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(message.toBytes());
        buffer.put(keyEncoder.encode(publicKey));
        return buffer.array();
    }

    @Override
    public String toString() {
        return "data: " + Convert.toHexString(message.toBytes()) + " publicKey: " + Convert.toHexString(keyEncoder.encode(publicKey));
    }

}
