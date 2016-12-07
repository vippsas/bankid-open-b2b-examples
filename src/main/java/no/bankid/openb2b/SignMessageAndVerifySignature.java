package no.bankid.openb2b;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.OtherSigningCertificate;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static no.bankid.openb2b.SomeUtils.Algos.*;
import static no.bankid.openb2b.SomeUtils.*;

public class SignMessageAndVerifySignature {


    /**
     * @param dataToBeSigned
     * @param jCertificateChain
     * @param jSignerCertificate
     * @param privateKey
     * @return a base64 mime encode CMS containing the contentinfo with no dataToBeSigned
     * @throws InvalidKeyException
     */

    public byte[] signMessageAndCreateDetachedCMSWithoutOCSPResponse(byte[] dataToBeSigned,
                                                                     List<? extends Certificate> jCertificateChain,
                                                                     X509Certificate jSignerCertificate,
                                                                     PrivateKey privateKey) throws InvalidKeyException {
        try {
            X509CertificateHolder signerCertificate = toCertificateHolder(jSignerCertificate);

            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);

            SignerInfo signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)), privateKey);

            ContentInfo detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : toCertificateHolder(jCertificateChain)) {
                certificatesVector.add(c.toASN1Structure());
            }

            SignedData signedData = new SignedData(
                    new DERSet(toASN1EncodableVector(SHA256.asId())),
                    detachedContentInfo,
                    new DERSet(certificatesVector),
                    null,
                    new DERSet(toASN1EncodableVector(signerInfo)));
            ContentInfo signedDataContentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, signedDataContentInfo);
            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException | SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }


    private SignerInfo createSignerInfo(X509CertificateHolder signerCertificate, ASN1OctetString dtbsDigest, PrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchProviderException {
        ASN1EncodableVector authAttribVector = toASN1EncodableVector(
                new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)),
                new Attribute(CMSAttributes.messageDigest, new DERSet(dtbsDigest)),
                new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))),
                new Attribute(PKCSObjectIdentifiers.id_aa_ets_otherSigCert, new DERSet(new OtherSigningCertificate(new OtherCertID(SHA256.asId(), doDigest(signerCertificate.getEncoded()))))));

        DERSet authenticatedAttributes = new DERSet(authAttribVector);

        final IssuerAndSerialNumber signerId = new IssuerAndSerialNumber(signerCertificate.getIssuer(), signerCertificate.getSerialNumber());

        return new SignerInfo(new SignerIdentifier(signerId),
                SHA256.asId(),
                authenticatedAttributes,
                RSA.asId(),
                new DEROctetString(signData(privateKey, authenticatedAttributes.getEncoded())),
                null); // ! Remark: an empty set here is not handled the same as null
    }

    private byte[] signData(PrivateKey privateKey, byte[] toBeSigned) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature signature = Signature.getInstance(SHA256withRSA.name());

        signature.initSign(privateKey);
        signature.update(toBeSigned);
        return signature.sign();
    }

    public boolean verifySignedMessageCMS(X509Certificate rootCert, byte dtbs[], byte[] base64EncodedCMS) throws Exception {
        final byte[] cmsBytesBlock = Base64.getDecoder().decode(base64EncodedCMS);


        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(dtbs), cmsBytesBlock);
        CertStore certsAndCRLs = new JcaCertStoreBuilder().addCertificates(signedData.getCertificates()).build();

        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();
        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
            signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.nonRepudiation)); // TODO: BankID sign certs er markert med non_repudiation ikke digitalSignature
            List<? extends Certificate> certificates = buildPath(rootCert, signerConstraints, certsAndCRLs).getCertificates();
            X509Certificate signerCertificate = (X509Certificate) certificates.get(0);

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate));
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore messageSignerKeystore = KeyStore.getInstance("JKS");
        final String messageSignerTrustKeystore = "www.kantega.no-sign.jks";
        messageSignerKeystore.load(Files.newInputStream(SomeUtils.RESOURCES_PATH.resolve(messageSignerTrustKeystore).toAbsolutePath()), "changeit".toCharArray());
        final Key signerKey = messageSignerKeystore.getKey("sign", "changeit".toCharArray());
        List<Certificate> messageSignerCertificateChain = Arrays.asList(messageSignerKeystore.getCertificateChain("sign"));

        // extract the certification path from the list of Certificates
        CertPath messageSignerPath = SomeUtils.CERTIFICATE_FACTORY.generateCertPath(messageSignerCertificateChain);

        X509Certificate messageSignerCertificate = (X509Certificate) messageSignerPath.getCertificates().get(0);

        final SignMessageAndVerifySignature signMessageAndVerifySignature = new SignMessageAndVerifySignature();

        final byte[] dtbs = "Hello World".getBytes(StandardCharsets.UTF_8);
        final byte[] cmsBytes = signMessageAndVerifySignature.signMessageAndCreateDetachedCMSWithoutOCSPResponse(dtbs, messageSignerPath.getCertificates(), messageSignerCertificate, (PrivateKey) signerKey);


        System.out.println("bytes = \n" + new String(cmsBytes));
        ByteArrayInputStream bankIDRootStream = new ByteArrayInputStream(SomeUtils.BANKID_ROOT_CERTIFICATE_PREPROD.getBytes());
        X509Certificate bankIDRootCert = (X509Certificate) SomeUtils.CERTIFICATE_FACTORY.generateCertificate(bankIDRootStream);
        boolean result = signMessageAndVerifySignature.verifySignedMessageCMS(bankIDRootCert, dtbs, cmsBytes);
        System.out.println("result = " + result);

    }

    static byte[] doDigest(byte[] tbs) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA256.name());
            md.update(tbs);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static ASN1EncodableVector toASN1EncodableVector(ASN1Encodable... elements) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (ASN1Encodable x : elements) {
            vector.add(x);
        }
        return vector;

    }
}
