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

package com.apollocurrency.aplwallet.apl;


import com.apollocurrency.aplwallet.apl.crypto.CryptoComponent;
import com.apollocurrency.aplwallet.apl.util.Convert;

import java.security.KeyPair;

public final class Token {

    public static String generateToken(String secretPhrase, String messageString) {
        return generateToken(secretPhrase, Convert.toBytes(messageString));
    }

    private static int getTokenSize() {
        return  CryptoComponent.getPublicKeyEncoder().getEncodedLength() +
                4 + /* (timestamp) */
                CryptoComponent.getSigner().getSignatureLength();
    }

    /**
     * 8 - string length to encode 5 bytes
     * 5 - is 5 bytes that are encoded via rad32IntToStr function
     * @return
     */
    private static int getTokenStringLength() {
        int remainder = 5 - (getTokenSize() % 5);
        return (getTokenSize() + remainder) * 8 / 5;
    }

    private static String rad32IntToStr(long number) {
        String zeros = "";
        if (number < 32) {
            zeros = "0000000";
        } else if (number < 1024) {
            zeros = "000000";
        } else if (number < 32768) {
            zeros = "00000";
        } else if (number < 1048576) {
            zeros = "0000";
        } else if (number < 33554432) {
            zeros = "000";
        } else if (number < 1073741824) {
            zeros = "00";
        } else if (number < 34359738368L) {
            zeros = "0";
        }
        return zeros + Long.toString(number, 32);
    }

    public static String generateToken(String secretPhrase, byte[] message) {

        KeyPair keyPair = CryptoComponent.getKeyGenerator().generateKeyPair(secretPhrase);

        byte[] data = new byte[message.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4];
        System.arraycopy(message, 0, data, 0, message.length);
        System.arraycopy(CryptoComponent.getPublicKeyEncoder().encode(keyPair.getPublic()), 0, data, message.length, CryptoComponent.getPublicKeyEncoder().getEncodedLength());
        int timestamp = Apl.getEpochTime();
        data[message.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength()] = (byte)timestamp;
        data[message.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 1] = (byte)(timestamp >> 8);
        data[message.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 2] = (byte)(timestamp >> 16);
        data[message.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 3] = (byte)(timestamp >> 24);

        byte[] token = new byte[getTokenSize()];
        System.arraycopy(data, message.length, token, 0, CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4);
        System.arraycopy(CryptoComponent.getSigner().sign(data, keyPair.getPrivate()), 0, token, CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4, CryptoComponent.getSigner().getSignatureLength());

        StringBuilder buf = new StringBuilder();
        int ptr = 0;
        for (; ptr < getTokenSize() - 5; ptr += 5) {

            long number = ((long)(token[ptr] & 0xFF)) | (((long)(token[ptr + 1] & 0xFF)) << 8) | (((long)(token[ptr + 2] & 0xFF)) << 16)
                    | (((long)(token[ptr + 3] & 0xFF)) << 24) | (((long)(token[ptr + 4] & 0xFF)) << 32);

            buf.append(rad32IntToStr(number));

        }

        int tail = getTokenSize() - ptr; // remainder bytes

        long number = 0;
        for(int i = 0; i < tail; i++) {
            number |= ((long)(token[ptr + i] & 0xFF)) << (8 * i);
            buf.append(rad32IntToStr(number));
        }

        return buf.toString();

    }

    public static Token parseToken(String tokenString, String website) {
        return parseToken(tokenString, Convert.toBytes(website));
    }

    public static Token parseToken(String tokenString, byte[] messageBytes) {

        if (tokenString.length() != getTokenStringLength()) {
            throw new IllegalArgumentException("Invalid token string: " + tokenString);
        }

        byte[] tokenBytes = new byte[getTokenSize()];
        int i = 0, j = 0;

        for (; j < getTokenSize() - 5; i += 8, j += 5) {

            long number = Long.parseLong(tokenString.substring(i, i + 8), 32);
            tokenBytes[j] = (byte)number;
            tokenBytes[j + 1] = (byte)(number >> 8);
            tokenBytes[j + 2] = (byte)(number >> 16);
            tokenBytes[j + 3] = (byte)(number >> 24);
            tokenBytes[j + 4] = (byte)(number >> 32);

        }

        int tail = getTokenSize() - j;
        if(tail > 0) {
            long number = Long.parseLong(tokenString.substring(i, i + 8), 32);
            for (i = 0; i < tail; i++) {
                tokenBytes[j + i] = (byte)(number >> (8 * i));
            }
        }

        byte[] publicKeyBytes = new byte[CryptoComponent.getPublicKeyEncoder().getEncodedLength()];

        System.arraycopy(tokenBytes, 0, publicKeyBytes, 0, CryptoComponent.getPublicKeyEncoder().getEncodedLength());

        int timestamp = ( tokenBytes[CryptoComponent.getPublicKeyEncoder().getEncodedLength()] & 0xFF) |
                ((tokenBytes[CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 1] & 0xFF) << 8) |
                ((tokenBytes[CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 2] & 0xFF) << 16) |
                ((tokenBytes[CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 3] & 0xFF) << 24);

        byte[] signature = new byte[CryptoComponent.getSigner().getSignatureLength()];
        System.arraycopy(tokenBytes, CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4 /* 4 bytes timestamp */, signature, 0, CryptoComponent.getSigner().getSignatureLength());

        byte[] data = new byte[messageBytes.length + CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4];
        System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
        System.arraycopy(tokenBytes, 0, data, messageBytes.length, CryptoComponent.getPublicKeyEncoder().getEncodedLength() + 4);

        java.security.PublicKey publicKey = CryptoComponent.getPublicKeyEncoder().decode(publicKeyBytes);
        java.security.PublicKey announcedPublicKey = Account.getPublicKey(Account.getId(publicKey));

        boolean isValid = CryptoComponent.getSigner().verify(data, signature, publicKey) && (announcedPublicKey == null || publicKey.equals(announcedPublicKey));

        return new Token(publicKey, timestamp, isValid);

    }

    private final java.security.PublicKey publicKey;
    private final int timestamp;
    private final boolean isValid;

    private Token(java.security.PublicKey publicKey, int timestamp, boolean isValid) {
        this.publicKey = publicKey;
        this.timestamp = timestamp;
        this.isValid = isValid;
    }

    public java.security.PublicKey getPublicKey() {
        return publicKey;
    }

    public int getTimestamp() {
        return timestamp;
    }

    public boolean isValid() {
        return isValid;
    }

    @Override
    public String toString() {
        return "Token{" +
                "publicKey=" + Convert.toHexString(CryptoComponent.getPublicKeyEncoder().encode(publicKey)) +
                ", timestamp=" + timestamp +
                ", isValid=" + isValid +
                '}';
    }
}
