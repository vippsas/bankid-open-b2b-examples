package no.bankid.openb2b;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Optional;

class VerifiedSignature {

    private final CertPath certPath;
    private final OCSPResponse ocspResponse;
    private final X509Certificate signerCert;

    VerifiedSignature(CMSSignedData signedData, CertPath certPath) {
        this.certPath = certPath;
        this.signerCert = (X509Certificate) certPath.getCertificates().get(0);

        @SuppressWarnings("unchecked") Collection<DERSequence> revokationInfo = signedData
                .getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_response)
                .getMatches(null);
        ocspResponse = revokationInfo.isEmpty() ? null : OCSPResponse.getInstance(revokationInfo.iterator().next());
    }

    CertPath getCertPath() {
        return certPath;
    }

    Optional<OCSPResponse> getOcspResponse() {
        return ocspResponse == null ? Optional.empty() : Optional.of(ocspResponse);
    }

    String getSignerCommonName() throws CertificateEncodingException {
        return getSubjectDNElement(signerCert, "CN");
    }

    String getSignerOrganizationNumber() throws CertificateEncodingException {
        return getSubjectDNElement(signerCert, "OID.2.5.4.5");
    }

    private String getSubjectDNElement(X509Certificate x509Certificate, String elementName) {
        String rfc1779SubjectName = x509Certificate.getSubjectX500Principal().getName("RFC1779");
        for (String namesAndValues : rfc1779SubjectName.split(",")) {
            String[] nameAndValue = namesAndValues.split("=");
            if (nameAndValue[0].trim().equals(elementName)) {
                return nameAndValue[1];
            }
        }
        return "<not found>";
    }
}
