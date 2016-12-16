package no.bankid.openb2b;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;


class BankIDStatusChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(BankIDStatusChecker.class);

    private final Set<TrustAnchor> trustAnchors;
    private final X509Certificate ocspResponderCert;
    private final List<? extends Certificate> signerCertChain;
    private final PrivateKey signerKey;
    private final Set<PKIXRevocationChecker.Option> revocationCheckerOptions;
    private final OcspRequester ocspRequester;


    BankIDStatusChecker(BankIDEnvironment environment,
                        PrivateKey signerKey,
                        List<? extends Certificate> signerCertChain) {
        this.trustAnchors = Collections.singleton(environment.getBankIDRoot());
        this.ocspResponderCert = environment.getOcspResponderCert();
        this.revocationCheckerOptions = environment.getRevocationCheckerOptions();
        this.signerKey = signerKey;
        this.signerCertChain = signerCertChain;
        ocspRequester = new OcspRequester();
    }

    BankIDStatus checkOnline(VerifiedSignature verifiedSignature) {

        if (!verifiedSignature.getOcspResponse().isPresent()) {
            LOGGER.info("Checking revocation state by asking VA");
            OcspResponse ocspResponse = fetchOcspResponse(verifiedSignature.getCertPath());
            return ocspResponse.getValue()
                    .map(response -> BankIDStatus.VERIFIED_ONLINE)
                    .orElse(BankIDStatus.NOT_VERIFIED);
        }

        LOGGER.info("Verified signature has an embedded OCSP response, should be verified offline");
        return BankIDStatus.NOT_VERIFIED;
    }

    BankIDStatus checkOffline(VerifiedSignature verifiedSignature) throws IOException {

        if (verifiedSignature.getOcspResponse().isPresent()) {
            LOGGER.info("Checking embedded OCSP response");
            byte[] ocspResponse = verifiedSignature.getOcspResponse().get().getEncoded();
            try {
                validateCertPathAndOcspResponseOffline(verifiedSignature.getCertPath(), ocspResponse);
            } catch (Exception e) {
                return BankIDStatus.NOT_VERIFIED;
            }
            return BankIDStatus.VERIFIED_OFFLINE;
        }

        LOGGER.info("Verified signature has no embedded OCSP response, should be verified online");
        return BankIDStatus.NOT_VERIFIED;
    }

    OcspResponse fetchOcspResponse(CertPath targetPath) {

        X509Certificate targetCertIssuer = (X509Certificate) targetPath.getCertificates().get(1);
        X509Certificate targetCert = (X509Certificate) targetPath.getCertificates().get(0);
        LOGGER.info("Sending OCSP request for certificate {}",
                targetCert.getSubjectX500Principal().getName("RFC1779"));

        byte[] ocspResponse = ocspRequester.post(targetCert, targetCertIssuer, signerCertChain, signerKey);

        try {
            validateCertPathAndOcspResponseOffline(targetPath, ocspResponse);
        } catch (Exception e) {
            return OcspResponse.empty();
        }

        return new OcspResponse(ocspResponse);
    }

    private void validateCertPathAndOcspResponseOffline(CertPath signerPath, byte[] rawOcspResponse) throws Exception {

        Map<X509Certificate, byte[]> ocspResponses = new HashMap<>();
        X509Certificate signerCertificate = (X509Certificate) signerPath.getCertificates().get(0);
        ocspResponses.put(signerCertificate, rawOcspResponse);

        // Build an ocsp revocation checker
        PKIXRevocationChecker revocationChecker =
                (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
        // Tell the ocsp revocation checker who is signing the ocsp response, the actual value used may
        // be found in the debug log for OcspRequester
        revocationChecker.setOcspResponderCert(ocspResponderCert);
        revocationChecker.setOptions(revocationCheckerOptions);
        revocationChecker.setOcspResponses(ocspResponses);

        PKIXParameters params = new PKIXParameters(trustAnchors);

        // Activate certificate revocation checking, otherwise no check for ocsp is done
        params.setRevocationEnabled(true);
        params.addCertPathChecker(revocationChecker);
        try {
            LOGGER.info("Validates BankID status for '{}'",
                    signerCertificate.getSubjectX500Principal().getName("RFC1779"));
            CertPathValidator.getInstance("PKIX").validate(signerPath, params);
            LOGGER.info("BankID status is OK");

        } catch (CertPathValidatorException e) {
            X509Certificate certificate = (X509Certificate) e.getCertPath().getCertificates().get(e.getIndex());
            LOGGER.info("{}: {}", certificate.getSubjectX500Principal().getName("RFC1779"), e.getReason());
            throw e;
        }
    }
}
