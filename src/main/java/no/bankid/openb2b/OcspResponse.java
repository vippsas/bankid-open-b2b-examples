package no.bankid.openb2b;

import org.bouncycastle.asn1.ocsp.OCSPResponse;

import java.util.Optional;

class OcspResponse {

    private final OCSPResponse ocspResponse;

    OcspResponse(byte[] ocspResponse) {
        this.ocspResponse = ocspResponse == null ? null : OCSPResponse.getInstance(ocspResponse);
    }

    public Optional<OCSPResponse> getValue() {
        return Optional.ofNullable(ocspResponse);
    }

    public static OcspResponse empty() {
        return new OcspResponse(null);
    }
}
