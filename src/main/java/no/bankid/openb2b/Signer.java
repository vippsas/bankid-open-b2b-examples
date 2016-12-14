package no.bankid.openb2b;

import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.util.Base64;

import static no.bankid.openb2b.Algorithms.SHA512;
import static no.bankid.openb2b.SecurityProvider.toASN1EncodableVector;

/**
 * See rfc5652 (https://tools.ietf.org/html/rfc5652) for details about cms content.
 */
public class Signer {

    private static final Logger LOGGER = LoggerFactory.getLogger(Signer.class);

    public static byte[] signWithoutOCSPResponse(byte[] dataToBeSigned,
                                                 CertPath signerCertPath,
                                                 PrivateKey signerKey) {
        try {
            LOGGER.info("Signs a message, NO OCSP Response in the result");

            Signature signature = new Signature(dataToBeSigned, signerCertPath, signerKey);

            SignedData signedData = new SignedData(  // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å
                    // tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA512.asId())),
                    signature.getDetachedContentInfo(),
                    new BERSet(signature.getCertificatesVector()),
                    null,
                    new DERSet(toASN1EncodableVector(signature.getSignerInfo())));

            ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            CMSSignedData cmsSignedData = new CMSSignedData(signature.getSignedContent(), contentInfo);

            return Base64.getEncoder().encode(cmsSignedData.getEncoded());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] signWithValidatedOCSPResponse(byte[] dataToBeSigned,
                                                       CertPath signerCertPath,
                                                       PrivateKey signerKey,
                                                       BankIDStatusChecker bankIDStatusChecker) {
        try {
            LOGGER.info("Signs a message, EMBEDS an OCSP Response in the result");

            Signature signature = new Signature(dataToBeSigned, signerCertPath, signerKey);

            // TODO: Consider extracting these two lines outside of this class and providing an optional OCSPResponse instead.
            // Check revocation state for our own signing certificate and add the signed response to the CMS
            byte[] ocspResponseBytes = bankIDStatusChecker.validateCertPathAndOcspResponseOnline(signerCertPath);
            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponseBytes);

            SignedData signedData = new SignedData( // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å
                    // tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA512.asId())),
                    signature.getDetachedContentInfo(),
                    new BERSet(signature.getCertificatesVector()),
                    new BERSet(toASN1EncodableVector(new DERTaggedObject(false, 1, new OtherRevocationInfoFormat
                            (OCSPObjectIdentifiers.id_pkix_ocsp_response, ocspResponse)))),
                    new DERSet(toASN1EncodableVector(signature.getSignerInfo())));

            ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            CMSSignedData cmsSignedData = new CMSSignedData(signature.getSignedContent(), contentInfo);

            return Base64.getEncoder().encode(cmsSignedData.getEncoded());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
