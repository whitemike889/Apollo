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

package com.apollocurrency.aplwallet.apl.http;

import static com.apollocurrency.aplwallet.apl.http.JSONResponses.PRUNED_TRANSACTION;

import javax.servlet.http.HttpServletRequest;

import com.apollocurrency.aplwallet.apl.Apl;
import com.apollocurrency.aplwallet.apl.AplException;
import com.apollocurrency.aplwallet.apl.PrunableMessage;
import com.apollocurrency.aplwallet.apl.util.JSON;
import org.json.simple.JSONStreamAware;

public final class GetPrunableMessage extends APIServlet.APIRequestHandler {

    private static class GetPrunableMessageHolder {
        private static final GetPrunableMessage INSTANCE = new GetPrunableMessage();
    }

    public static GetPrunableMessage getInstance() {
        return GetPrunableMessageHolder.INSTANCE;
    }

    private GetPrunableMessage() {
        super(new APITag[] {APITag.MESSAGES}, "transaction", "secretPhrase", "sharedKey", "retrieve", "account", "passphrase");
    }

    @Override
    protected JSONStreamAware processRequest(HttpServletRequest req) throws AplException {
        long transactionId = ParameterParser.getUnsignedLong(req, "transaction", true);
        long accountId = ParameterParser.getAccountId(req, false);
        byte[] keySeed = ParameterParser.getKeySeed(req, accountId, false);
        byte[] sharedKey = ParameterParser.getBytes(req, "sharedKey", false);
        if (sharedKey.length != 0 && keySeed != null) {
            return JSONResponses.either("secretPhrase", "sharedKey", "passphrase & account");
        }
        boolean retrieve = "true".equalsIgnoreCase(req.getParameter("retrieve"));
        PrunableMessage prunableMessage = PrunableMessage.getPrunableMessage(transactionId);
        if (prunableMessage == null && retrieve) {
            if (Apl.getBlockchainProcessor().restorePrunedTransaction(transactionId) == null) {
                return PRUNED_TRANSACTION;
            }
            prunableMessage = PrunableMessage.getPrunableMessage(transactionId);
        }
        if (prunableMessage != null) {
            return JSONData.prunableMessage(prunableMessage, keySeed, sharedKey);
        }
        return JSON.emptyJSON;
    }

}
