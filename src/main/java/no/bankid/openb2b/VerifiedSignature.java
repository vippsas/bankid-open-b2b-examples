package no.bankid.openb2b;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.CertPath;
import java.util.Collection;
import java.util.Optional;

class VerifiedSignature {

    private final CertPath certPath;
    private final OCSPResponse ocspResponse;

    VerifiedSignature(CMSSignedData signedData, CertPath certPath) {
        this.certPath = certPath;

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
}
