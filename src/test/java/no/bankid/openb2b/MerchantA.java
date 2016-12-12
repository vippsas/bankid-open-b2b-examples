package no.bankid.openb2b;

import java.net.URL;

public class MerchantA {
    static final URL KEYSTORE_URL = ReceiverVerifiesBankIDStatusIT.class.getResource("/Merchant A.jks");
    static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
    static final String KEY_ALIAS = "signkey";
    static final char[] KEY_PASSWORD = "changeit".toCharArray();
}
