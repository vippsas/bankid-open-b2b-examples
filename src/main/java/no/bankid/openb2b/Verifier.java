package no.bankid.openb2b;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.*;
import java.util.*;

public class Verifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(Verifier.class);

    public static boolean verifyDetachedSignature(X509Certificate rootCert,
                                                  byte dtbs[],
                                                  byte[] base64EncodedCMS,
                                                  BankIDStatusChecker bankIDStatusChecker) throws Exception {

        byte[] cmsBytesBlock = Base64.getDecoder().decode(base64EncodedCMS);
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(dtbs), cmsBytesBlock);
        CertStore certsAndCRLs = new JcaCertStoreBuilder().addCertificates(signedData.getCertificates()).build();
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();

        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
            // BankID sign certs has 'non_repudiation', not 'digitalSignature'.
            signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.nonRepudiation));
            CertPath certPath = buildPath(rootCert, signerConstraints, certsAndCRLs);
            List<? extends Certificate> certificates = certPath.getCertificates();
            X509Certificate signerCertificate = (X509Certificate) certificates.get(0);
            LOGGER.info("Message was signed by '{}'", signerCertificate.getSubjectX500Principal().getName("RFC1779"));

            @SuppressWarnings("unchecked") Store<DERSequence> otherRevocationInfoStore =
                    signedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            Collection<DERSequence> allOtherRevocationInfos = otherRevocationInfoStore.getMatches(null);

            if (allOtherRevocationInfos.isEmpty()) {
                LOGGER.info("Checking revocation state by asking VA");
                bankIDStatusChecker.validateCertPathAndOcspResponseOnline(certPath);
            } else {
                LOGGER.info("Checking embedded OCSP response");
                byte[] ocspResponse = OCSPResponse.getInstance(allOtherRevocationInfos.iterator().next()).getEncoded();
                bankIDStatusChecker.validateCertPathAndOcspResponseOffline(certPath, ocspResponse);
            }

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate));
        }

        return false;
    }

    private static boolean[] getKeyUsage(int mask) {
        byte[] bytes = new byte[]{(byte) (mask & 0xff), (byte) ((mask & 0xff00) >> 8)};
        boolean[] keyUsage = new boolean[9];

        for (int i = 0; i != 9; i++) {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }

    private static CertPath buildPath(X509Certificate rootCert, X509CertSelector endConstraints, CertStore certsAndCRLs)
            throws Exception {

        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXBuilderParameters buildParams =
                new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);

        buildParams.addCertStore(certsAndCRLs);
        // Note: the path is built with revocation checking turned off.
        buildParams.setRevocationEnabled(false);

        return builder.build(buildParams).getCertPath();
    }

}
