package no.bankid.openb2b;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

import static java.util.Arrays.asList;

public abstract class Merchant {

    List<Certificate> getCertList() throws Exception {
        return asList(getKeyStore().getCertificateChain(getKeyAlias()));
    }

    public PrivateKey getPrivateKey() throws Exception {
        return (PrivateKey) getKeyStore().getKey(getKeyAlias(), getKeyPassword());
    }

    protected abstract String getKeyAlias();

    protected abstract char[] getKeyStorePassword();

    protected abstract URL getKeyStoreUrl();

    protected abstract char[] getKeyPassword();

    private KeyStore getKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = getKeyStoreUrl().openStream()) {
            keyStore.load(inputStream, getKeyStorePassword());
        }
        return keyStore;
    }

}
