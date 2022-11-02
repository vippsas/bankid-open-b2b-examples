package no.bankid.openb2b;

import java.net.URL;

public class MerchantA extends Merchant {

    @Override
    protected String getCommonName() {
        return "Merchant A";
    }

    @Override
    protected String getOrganizationNumber() {
        return "999999999";
    }

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
        return MerchantA.class.getResource("/Merchant A.jks");
    }

    @Override
    protected char[] getKeyPassword() {
        return "changeit".toCharArray();
    }
}
