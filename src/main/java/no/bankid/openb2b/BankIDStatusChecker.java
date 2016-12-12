package no.bankid.openb2b;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;


public class BankIDStatusChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(BankIDStatusChecker.class);

    private final X509Certificate vaOcspResponderCert;
    private final X509Certificate bankIDRootCert;
    private List<? extends Certificate> signerCertificateChain;
    private PrivateKey signerKey;

    public BankIDStatusChecker(BankIDEnvironment environment,
                               PrivateKey signerKey,
                               List<? extends Certificate> signerCertChain) {
        this.bankIDRootCert = environment.getBankIDRootCert();
        this.vaOcspResponderCert = environment.getVaOcspResponderCert();
        this.signerKey = signerKey;
        this.signerCertificateChain = signerCertChain;
    }

    /**
     * Sends a signed request to the BankID Va based and return its response unvalidated.
     * This is the call which generates a billing to the owner of the OCSP signer certificate owner.
     * @param signerPath the signerpath
     * @return the response received
     */
    public byte[] getOcspResponseFromVa(CertPath signerPath) throws NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, NoSuchProviderException {

        X509Certificate signerCertificateIssuer = (X509Certificate) signerPath.getCertificates().get(1);
        X509Certificate signerCertificate = (X509Certificate) signerPath.getCertificates().get(0);
        LOGGER.info("Sending OCSP request for certificate {}", signerCertificate.getSubjectX500Principal().getName("RFC1779"));

        byte[] ocspResponse = new OcspRequester().sendOcspRequestGetResponse(signerCertificate,
                signerCertificateIssuer, signerCertificateChain, signerKey);

        validateCertPathAndOcspResponseOffline(signerPath, ocspResponse);

        return ocspResponse;
    }

    public void validateCertPathAndOcspResponseOffline(CertPath signerPath, byte[] rawOcspResponse)
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        Map<X509Certificate, byte[]> prCertificateOcspResponses = new HashMap<>();
        X509Certificate signerCertificate = (X509Certificate) signerPath.getCertificates().get(0);
        prCertificateOcspResponses.put(signerCertificate, rawOcspResponse);

        // Build an ocsp revocation checker
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
        // Tell the ocsp revocation checker who is signing the ocsp response, the actual value used may be found in the debug log for OcspRequester
        revocationChecker.setOcspResponderCert(vaOcspResponderCert);
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        revocationChecker.setOcspResponses(prCertificateOcspResponses);

        Set<TrustAnchor> anchors = generateTrustAnchors();
        PKIXParameters params = new PKIXParameters(anchors);

        // Activate certificate revocation checking, otherwise no check for ocsp is done
        params.setRevocationEnabled(true);
        params.addCertPathChecker(revocationChecker);
        try {
            LOGGER.info("Validates BankID status for '{}'",
                    signerCertificate.getSubjectX500Principal().getName("RFC1779"));
            CertPathValidator.getInstance("PKIX").validate(signerPath, params);
            LOGGER.info("BankID status is OK");

        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            X509Certificate certificate = (X509Certificate) e.getCertPath().getCertificates().get(e.getIndex());
            LOGGER.info("{}: {}", certificate.getSubjectX500Principal().getName("RFC1779"), e.getReason());
            throw new IllegalStateException(e);
        }

    }

    private Set<TrustAnchor> generateTrustAnchors() throws CertificateException {

        TrustAnchor bankIDRootAnchor = new TrustAnchor(bankIDRootCert, null);

        Set<TrustAnchor> list = new HashSet<>();
        list.add(bankIDRootAnchor);

        return list;
    }
}
