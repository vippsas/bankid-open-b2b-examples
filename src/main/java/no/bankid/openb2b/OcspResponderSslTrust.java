package no.bankid.openb2b;

import java.nio.file.Files;
import java.nio.file.Path;

public class OcspResponderSslTrust {

    public static void init(BankIDEnvironment env) {
        Path trustStorePath = env.getOcspResponderSslTrustStorePath();
        if (!Files.exists(trustStorePath)) {
            throw new RuntimeException("Failed to find OCSP responder SSL trust store: " + trustStorePath);
        }
        System.setProperty("javax.net.ssl.trustStore", trustStorePath.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", env.getOcspResponderSslTrustStorePassword());
    }
}
