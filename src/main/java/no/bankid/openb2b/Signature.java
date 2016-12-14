package no.bankid.openb2b;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.OtherSigningCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;

import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static no.bankid.openb2b.Algorithms.*;
import static no.bankid.openb2b.SecurityProvider.toASN1EncodableVector;

class Signature {

    private final CMSProcessableByteArray signedContent;
    private final SignerInfo signerInfo;
    private final ContentInfo detachedContentInfo;
    private final ASN1EncodableVector certificatesVector;

    public Signature(byte[] dataToBeSigned, CertPath signerCertPath, PrivateKey signerKey) throws Exception {

        X509CertificateHolder signerCertificate = toCertificateHolder(signerCertPath.getCertificates().get(0));

        signedContent = new CMSProcessableByteArray(dataToBeSigned);
        signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)), signerKey);

        detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
        certificatesVector = new ASN1EncodableVector();

        for (X509CertificateHolder c : SecurityProvider.toCertificateHolders(signerCertPath.getCertificates())) {
            certificatesVector.add(c.toASN1Structure());
        }
    }

    public CMSProcessableByteArray getSignedContent() {
        return signedContent;
    }

    public SignerInfo getSignerInfo() {
        return signerInfo;
    }

    public ContentInfo getDetachedContentInfo() {
        return detachedContentInfo;
    }

    public ASN1EncodableVector getCertificatesVector() {
        return certificatesVector;
    }

    private SignerInfo createSignerInfo(X509CertificateHolder signerCertificate,
                                        ASN1OctetString dtbsDigest,
                                        PrivateKey privateKey) throws Exception {

        ASN1EncodableVector authAttribVector = toASN1EncodableVector(
                new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)),
                new Attribute(CMSAttributes.messageDigest, new DERSet(dtbsDigest)),
                new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))),
                new Attribute(PKCSObjectIdentifiers.id_aa_ets_otherSigCert,
                        new DERSet(new OtherSigningCertificate(new OtherCertID(SHA512.asId(), doDigest
                                (signerCertificate.getEncoded()))))));

        DERSet authenticatedAttributes = new DERSet(authAttribVector);

        IssuerAndSerialNumber signerId = new IssuerAndSerialNumber(signerCertificate.getIssuer(), signerCertificate
                .getSerialNumber());

        // ! Remark: an empty unauthenticatedAttributes is not handled the same as null
        ASN1Set unauthenticatedAttributes = null;
        return new SignerInfo(new SignerIdentifier(signerId),
                SHA512.asId(),
                authenticatedAttributes,
                RSA.asId(),
                new DEROctetString(signData(privateKey, authenticatedAttributes.getEncoded())),
                unauthenticatedAttributes);
    }

    private byte[] signData(PrivateKey privateKey, byte[] toBeSigned) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, NoSuchProviderException {
        java.security.Signature signature = java.security.Signature.getInstance(SHA512withRSA.name());
        signature.initSign(privateKey);
        signature.update(toBeSigned);
        return signature.sign();
    }

    private X509CertificateHolder toCertificateHolder(java.security.cert.Certificate c) {
        try {
            return new JcaX509CertificateHolder((X509Certificate) c);
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] doDigest(byte[] tbs) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA512.name());
            md.update(tbs);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
