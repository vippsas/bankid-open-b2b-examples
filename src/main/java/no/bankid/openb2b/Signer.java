package no.bankid.openb2b;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.OtherSigningCertificate;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Date;

import static no.bankid.openb2b.Algorithms.*;

public class Signer {

    private static final Logger LOGGER = LoggerFactory.getLogger(Signer.class);

    /**
     * See rfc5652 for details about cms content. See BankID (TODO finn doc) for hva som må være med.
     *
     * @param dataToBeSigned
     * @param signerCertPath
     * @param signerKey
     * @return detached signature
     * @throws InvalidKeyException
     */
    public static byte[] signWithoutOCSPResponse(byte[] dataToBeSigned,
                                                 CertPath signerCertPath,
                                                 PrivateKey signerKey) {
        try {
            LOGGER.info("Signs a message, NO OCSP Response in the result");
            X509CertificateHolder signerCertificate = toCertificateHolder(signerCertPath.getCertificates().get(0));

            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);

            SignerInfo signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)),
                    signerKey);

            ContentInfo detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : SecurityProvider.toCertificateHolders(signerCertPath.getCertificates())) {
                certificatesVector.add(c.toASN1Structure());
            }

            SignedData signedData = new SignedData(  // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å
                    // tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA256.asId())),
                    detachedContentInfo,
                    new BERSet(certificatesVector),
                    null,
                    new DERSet(toASN1EncodableVector(signerInfo)));

            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, new ContentInfo(PKCSObjectIdentifiers
                    .signedData, signedData));
            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | IOException |
                SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] signWithValidatedOCSPResponse(byte[] dataToBeSigned,
                                                       CertPath messageSignerPath,
                                                       PrivateKey messageSignerKey,
                                                       BankIDStatusChecker bankIDStatusChecker) {
        try {
            LOGGER.info("Signs a message, EMBEDS an OCSP Response in the result");

            X509CertificateHolder signerCertificate = toCertificateHolder(messageSignerPath.getCertificates().get(0));


            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);
            SignerInfo signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)),
                    messageSignerKey);

            ContentInfo detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : SecurityProvider.toCertificateHolders(messageSignerPath.getCertificates())) {
                certificatesVector.add(c.toASN1Structure());
            }

            // Check revocation state for our own signing certificate and add the signed response to the CMS
            byte[] ocspResponseBytes = bankIDStatusChecker.getOcspResponseFromVa(messageSignerPath);

            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponseBytes);
            SignedData signedData = new SignedData( // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å
                    // tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA256.asId())),
                    detachedContentInfo,
                    new BERSet(certificatesVector),
                    new BERSet(toASN1EncodableVector(new DERTaggedObject(false, 1, new OtherRevocationInfoFormat
                            (OCSPObjectIdentifiers.id_pkix_ocsp_response, ocspResponse)))),
                    new DERSet(toASN1EncodableVector(signerInfo)));

            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, new ContentInfo(PKCSObjectIdentifiers
                    .signedData, signedData));

            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (InvalidAlgorithmParameterException | CertificateException | InvalidKeyException |
                NoSuchAlgorithmException | NoSuchProviderException | IOException | SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignerInfo createSignerInfo(X509CertificateHolder signerCertificate,
                                               ASN1OctetString dtbsDigest,
                                               PrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException,
            NoSuchProviderException {

        ASN1EncodableVector authAttribVector = toASN1EncodableVector( // This is the same attributes as BIDJServer
                // adds to the CMS
                new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)),
                new Attribute(CMSAttributes.messageDigest, new DERSet(dtbsDigest)),
                new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))),
                new Attribute(PKCSObjectIdentifiers.id_aa_ets_otherSigCert,
                        new DERSet(new OtherSigningCertificate(new OtherCertID(SHA256.asId(), doDigest
                                (signerCertificate.getEncoded()))))));

        DERSet authenticatedAttributes = new DERSet(authAttribVector);

        IssuerAndSerialNumber signerId = new IssuerAndSerialNumber(signerCertificate.getIssuer(), signerCertificate
                .getSerialNumber());

        return new SignerInfo(new SignerIdentifier(signerId),
                SHA256.asId(),
                authenticatedAttributes,
                RSA.asId(),
                new DEROctetString(signData(privateKey, authenticatedAttributes.getEncoded())),
                null); // ! Remark: an empty set here is not handled the same as null
    }

    private static byte[] signData(PrivateKey privateKey, byte[] toBeSigned) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature signature = Signature.getInstance(SHA256withRSA.name());
        signature.initSign(privateKey);
        signature.update(toBeSigned);
        return signature.sign();
    }

    private static byte[] doDigest(byte[] tbs) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA256.name());
            md.update(tbs);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ASN1EncodableVector toASN1EncodableVector(ASN1Encodable... elements) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (ASN1Encodable x : elements) {
            vector.add(x);
        }
        return vector;
    }

    private static X509CertificateHolder toCertificateHolder(Certificate c) {
        try {
            return new JcaX509CertificateHolder((X509Certificate) c);
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
