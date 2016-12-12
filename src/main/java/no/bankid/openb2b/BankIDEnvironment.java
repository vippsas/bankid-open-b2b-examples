package no.bankid.openb2b;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static no.bankid.openb2b.SomeUtils.BANKID_ROOT_CERTIFICATE_PREPROD;
import static no.bankid.openb2b.SomeUtils.CERTIFICATE_FACTORY;
import static no.bankid.openb2b.SomeUtils.NETS_VA_OCSP_RESPONDER_CERTIFICATE_PREPROD;

public enum BankIDEnvironment {

    PREPROD,
    PROD;

    X509Certificate getBankIDRootCert() {

        InputStream certStream = (name().equals(PREPROD.name()) ?
                new ByteArrayInputStream(BANKID_ROOT_CERTIFICATE_PREPROD.getBytes()) :
                // TODO: PROD
                null);

        try {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to load BankID root certificate for " + name());
        }
    }

    X509Certificate getVaOcspResponderCert() {

        InputStream certStream = (name().equals(PREPROD.name()) ?
                new ByteArrayInputStream(NETS_VA_OCSP_RESPONDER_CERTIFICATE_PREPROD.getBytes()) :
                // TODO: PROD
                null);

        try {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to load VA OCSP responder certificate for " + name());
        }
    }
}
