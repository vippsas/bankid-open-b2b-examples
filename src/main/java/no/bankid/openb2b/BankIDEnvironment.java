package no.bankid.openb2b;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Set;

import static no.bankid.openb2b.SecurityProvider.CERTIFICATE_FACTORY;

public enum BankIDEnvironment {

    PREPROD,
    PROD;

    TrustAnchor getBankIDRoot() {
        try (InputStream certStream = name().equals(PREPROD.name()) ?
                BankIDRootCertPreprod.getInputStream() :
                BankIDRootCertProd.getInputStream()) {
            X509Certificate rootCert = (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
            return new TrustAnchor(rootCert, null);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load BankID root certificate for " + name(), e);
        }
    }

    X509Certificate getOcspResponderCert() {
        try (InputStream certStream = name().equals(PREPROD.name()) ?
                OcspResponderCertPreprod.getInputStream() :
                OcspResponderCertProd.getInputStream()) {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(certStream);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load VA OCSP responder certificate for " + name());
        }
    }

    Path getOcspResponderSslTrustStorePath() {
        String keystore = name().equals(PREPROD.name()) ? "/trust-va-preprod.no.jks" : "/trust-va-prod.no.jks";
        try {
            return Paths.get(getClass().getResource(keystore).toURI());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load VA OCSP responder SSL certificate for " + name(), e);
        }
    }

    String getOcspResponderSslTrustStorePassword() {
        return name().equals(PREPROD.name()) ? "changeit" : "changeit";
    }

    Set<PKIXRevocationChecker.Option> getRevocationCheckerOptions() {
        return name().equals(PREPROD.name()) ?
                EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY) :
                EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK);
    }
}
