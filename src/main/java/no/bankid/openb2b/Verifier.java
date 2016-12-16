package no.bankid.openb2b;

import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.*;
import java.util.*;

import static java.util.Optional.empty;

class Verifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(Verifier.class);

    /**
     * see {@link X509Certificate#getKeyUsage() X509Certificate.getKeyUsage()}.
     */
    private static final boolean[] KEY_USAGE_NON_REPUDIATION =
            {false, true, false, false, false, false, false, false, false};

    static Optional<VerifiedSignature> verifyDetachedSignature(TrustAnchor rootCert,
                                                               byte dtbs[],
                                                               byte[] base64EncodedCMS) throws Exception {

        byte[] cmsBytesBlock = Base64.getDecoder().decode(base64EncodedCMS);
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(dtbs), cmsBytesBlock);
        CertStore certsAndCRLs = new JcaCertStoreBuilder().addCertificates(signedData.getCertificates()).build();
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator<SignerInformation> it = signers.getSigners().iterator();

        if (it.hasNext()) {
            SignerInformation signer = it.next();
            X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
            // BankID sign certs has 'non_repudiation', not 'digitalSignature'.
            signerConstraints.setKeyUsage(KEY_USAGE_NON_REPUDIATION);
            CertPath certPath = buildPath(rootCert, signerConstraints, certsAndCRLs);
            List<? extends Certificate> certificates = certPath.getCertificates();
            X509Certificate signerCertificate = (X509Certificate) certificates.get(0);
            LOGGER.info("Message was signed by '{}'", signerCertificate.getSubjectX500Principal().getName("RFC1779"));

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate)) ?
                    Optional.of(new VerifiedSignature(signedData, certPath)) : empty();
        }

        return empty();
    }

    private static CertPath buildPath(TrustAnchor rootCert, X509CertSelector endConstraints, CertStore certsAndCRLs)
            throws Exception {

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(rootCert), endConstraints);

        buildParams.addCertStore(certsAndCRLs);
        // Note: the path is built with revocation checking turned off.
        buildParams.setRevocationEnabled(false);

        return builder.build(buildParams).getCertPath();
    }

}
