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
import java.security.PublicKey;

public final class EncryptedData implements com.apollocurrency.aplwallet.apl.crypto.symmetric.EncryptedData {

    private final byte[] data;
    private final byte[] nonce;

    public EncryptedData(byte[] data, byte[] nonce) {
        this.data = data;
        this.nonce = nonce;
    }

    @Override
    public byte[] decrypt(String secretPhrase, PublicKey theirPublicKey) {
        if (data.length == 0) {
            return data;
        }
        byte[] sharedKey = Crypto.getSharedKey(Crypto.getPrivateKey(secretPhrase), theirPublicKey.getEncoded(), nonce);
        return Crypto.aesDecrypt(data, sharedKey);
    }

    @Override
    public byte[] decrypt(byte[] symmetricKey) {
        return Crypto.aesDecrypt(data, symmetricKey);
    }

    @Override
    public byte[] getData() {
        return data;
    }

    @Override
    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public int getBytesSize() {
        return data.length + nonce.length;
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(nonce.length + data.length);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(data);
        buffer.put(nonce);
        return buffer.array();
    }

    @Override
    public String toString() {
        return "data: " + Convert.toHexString(data) + " nonce: " + Convert.toHexString(nonce);
    }

}
