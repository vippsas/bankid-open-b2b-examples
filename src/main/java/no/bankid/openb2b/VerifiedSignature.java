package no.bankid.openb2b;

import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.CertPath;

class VerifiedSignature {
    private final CMSSignedData signedData;
    private final CertPath certPath;

    VerifiedSignature(CMSSignedData signedData, CertPath certPath) {

        this.signedData = signedData;
        this.certPath = certPath;
    }

    public CMSSignedData getSignedData() {
        return signedData;
    }

    public CertPath getCertPath() {
        return certPath;
    }
}
