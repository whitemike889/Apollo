/*
 * Copyright © 2013-2016 The Nxt Core Developers.
 * Copyright © 2016-2017 Jelurida IP B.V.
 *
 * See the LICENSE.txt file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with Jelurida B.V.,
 * no part of the Nxt software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE.txt file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */

/*
 * Copyright © 2018 Apollo Foundation
 */

package com.apollocurrency.aplwallet.apl.crypto.legacy;

import com.apollocurrency.aplwallet.apl.util.Convert;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.util.Arrays;

public final class AnonymouslyEncryptedData implements com.apollocurrency.aplwallet.apl.crypto.symmetric.AnonymouslyEncryptedData {

    private final byte[] data;
    private final byte[] publicKey;

    public AnonymouslyEncryptedData(byte[] data, java.security.PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof PublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }
        this.data = data;
        this.publicKey = publicKey.getEncoded();
    }

    @Override
    public byte[] decrypt(String secretPhrase) {
        byte[] sharedKey = Crypto.getSharedKey(Crypto.getPrivateKey(secretPhrase), publicKey);
        return Crypto.aesGCMDecrypt(data, sharedKey);
    }

    @Override
    public byte[] decrypt(byte[] keySeed, java.security.PublicKey theirPublicKey) throws InvalidKeyException {
        if (!(theirPublicKey instanceof PublicKey)) {
            throw new InvalidKeyException("Invalid key format. Check crypto config");
        }
        if (!Arrays.equals(Crypto.getPublicKey(keySeed), publicKey)) {
            throw new RuntimeException("Data was not encrypted using this keySeed");
        }
        byte[] sharedKey = Crypto.getSharedKey(Crypto.getPrivateKey(keySeed), theirPublicKey.getEncoded());
        return Crypto.aesGCMDecrypt(data, sharedKey);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public java.security.PublicKey getPublicKey() {
        try {
            return new PublicKey(publicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public int getBytesSize() {
        return data.length + 32;
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(data.length + 32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(data);
        buffer.put(publicKey);
        return buffer.array();
    }

    @Override
    public String toString() {
        return "data: " + Convert.toHexString(data) + " publicKey: " + Convert.toHexString(publicKey);
    }

}
