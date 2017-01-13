package no.bankid.openb2b;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

class OcspResponderCertProd {

    // TODO: Add certificate
    private static final String OCSP_RESPONDER_CERTIFICATE_PROD =
            "-----BEGIN CERTIFICATE-----\n" +
                    "TODO: Add certificate\n" +
                    "-----END CERTIFICATE-----\n";

    static InputStream getInputStream() {
        return new ByteArrayInputStream(OCSP_RESPONDER_CERTIFICATE_PROD.getBytes());
    }
}
