package com.apollocurrency.aplwallet.apl.crypto.advanced;

import com.apollocurrency.aplwallet.apl.Account;
import com.apollocurrency.aplwallet.apl.crypto.CryptoComponent;
import com.apollocurrency.aplwallet.apl.crypto.legacy.Crypto;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;

public class BasicTest {


    @Test
    public void basicTest() {

        // curl -X POST 'http://localhost:6876/apl?requestType=startForging&secretPhrase=Hello!'

        generateAccount("Hello!"); // 7618035852359978071 "QM4R-9VK3-STP4-8M7GM"
        generateAccount("Hello!!"); // 2302610582556356678 "9E48-624P-B5PB-366XZ"

    }

    private void generateAccount(String passPhrase) {
        KeyPair keyPair = CryptoComponent.getKeyGenerator().generateKeyPair(passPhrase);
        long id = Account.getId(keyPair.getPublic());

        System.out.println(id);
        System.out.println(Crypto.rsEncode(id));
        System.out.println(Hex.toHexString(CryptoComponent.getPublicKeyEncoder().encode(keyPair.getPublic())));
        System.out.println("");
    }

}
