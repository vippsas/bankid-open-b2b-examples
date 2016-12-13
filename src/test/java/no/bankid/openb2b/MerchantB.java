package no.bankid.openb2b;

import java.net.URL;

public class MerchantB extends Merchant {

    @Override
    protected String getKeyAlias() {
        return "signkey";
    }

    @Override
    protected char[] getKeyStorePassword() {
        return "changeit".toCharArray();
    }

    @Override
    protected URL getKeyStoreUrl() {
        return MerchantB.class.getResource("/Merchant B.jks");
    }

    @Override
    protected char[] getKeyPassword() {
        return "changeit".toCharArray();
    }
}
