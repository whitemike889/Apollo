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

package apl.http;

import apl.AplException;
import apl.Transaction;
import apl.crypto.Crypto;
import apl.util.Convert;
import org.json.simple.JSONObject;
import org.json.simple.JSONStreamAware;

import javax.servlet.http.HttpServletRequest;
import java.security.MessageDigest;

import static apl.http.JSONResponses.MISSING_SIGNATURE_HASH;

public final class CalculateFullHash extends APIServlet.APIRequestHandler {

    private static class CalculateFullHashHolder {
        private static final CalculateFullHash INSTANCE = new CalculateFullHash();
    }

    public static CalculateFullHash getInstance() {
        return CalculateFullHashHolder.INSTANCE;
    }

    private CalculateFullHash() {
        super(new APITag[] {APITag.TRANSACTIONS}, "unsignedTransactionBytes", "unsignedTransactionJSON", "signatureHash");
    }

    @Override
    protected JSONStreamAware processRequest(HttpServletRequest req) throws ParameterException {

        String unsignedBytesString = Convert.emptyToNull(req.getParameter("unsignedTransactionBytes"));
        String signatureHashString = Convert.emptyToNull(req.getParameter("signatureHash"));
        String unsignedTransactionJSONString = Convert.emptyToNull(req.getParameter("unsignedTransactionJSON"));

        if (signatureHashString == null) {
            return MISSING_SIGNATURE_HASH;
        }
        JSONObject response = new JSONObject();
        try {
            Transaction transaction = ParameterParser.parseTransaction(unsignedTransactionJSONString, unsignedBytesString, null).build();
            MessageDigest digest = Crypto.sha256();
            digest.update(transaction.getUnsignedBytes());
            byte[] fullHash = digest.digest(Convert.parseHexString(signatureHashString));
            response.put("fullHash", Convert.toHexString(fullHash));
        } catch (AplException.NotValidException e) {
            JSONData.putException(response, e, "Incorrect unsigned transaction json or bytes");
        }
        return response;
    }

    @Override
    protected boolean allowRequiredBlockParameters() {
        return false;
    }

    @Override
    protected boolean requireBlockchain() {
        return false;
    }

}
