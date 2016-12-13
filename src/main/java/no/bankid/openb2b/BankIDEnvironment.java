package no.bankid.openb2b;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Set;

import static no.bankid.openb2b.SecurityProvider.CERTIFICATE_FACTORY;

public enum BankIDEnvironment {

    PREPROD,
    PROD;

    X509Certificate getBankIDRootCert() {
        // TODO: PROD
        InputStream certStream = name().equals(PREPROD.name()) ? BankIDRootCertPreprod.getInputStream() : null;
        try {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to load BankID root certificate for " + name());
        }
    }

    X509Certificate getOcspResponderCert() {
        // TODO: Lag preprod jks på nytt, med innhold fra brukerstedspakken.
        // TODO: PROD
        InputStream certStream = name().equals(PREPROD.name()) ? OcspResponderCertPreprod.getInputStream() : null;
        try {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to load VA OCSP responder certificate for " + name());
        }
    }

    public Path getOcspResponderSslTrustStorePath() {
        // TODO: PROD
        String keystore = name().equals(PREPROD.name()) ? "/trust-va-preprod1.no.jks" : null;
        try {
            return Paths.get(getClass().getResource(keystore).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Failed to load VA OCSP responder SSL certificate for " + name());
        }
    }

    public String getOcspResponderSslTrustStorePassword() {
        // TODO: PROD
        return name().equals(PREPROD.name()) ? "changeit" : null;
    }

    public Set<PKIXRevocationChecker.Option> getRevocationCheckerOptions() {
        return name().equals(PREPROD.name()) ?
                EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY) :
                EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK);
    }
}
