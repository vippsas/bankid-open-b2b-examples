package no.bankid.openb2b;

import java.net.URL;

public class MerchantB {
    static final URL KEYSTORE_URL = ReceiverVerifiesBankIDStatusIT.class.getResource("/Merchant B.jks");
    static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();
    static final String KEY_ALIAS = "signkey";
    static final char[] KEY_PASSWORD = "changeit".toCharArray();
}
