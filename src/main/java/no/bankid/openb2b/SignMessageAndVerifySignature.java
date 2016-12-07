package no.bankid.openb2b;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.OtherSigningCertificate;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static no.bankid.openb2b.SomeUtils.*;

public class SignMessageAndVerifySignature {
    /**
     * @param dataToBeSigned
     * @param jCertificateChain
     * @param jSignerCertificate
     * @param privateKey
     * @return a base64 mime encode CMS containing the contentinfo (i.e. data is skipped)
     * @throws InvalidKeyException
     */
    public byte[] signMessageAndCreateCMSWithoutOCSP(byte[] dataToBeSigned, List<? extends Certificate> jCertificateChain, X509Certificate jSignerCertificate, PrivateKey privateKey) throws InvalidKeyException {
        try {
            AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
            X509CertificateHolder signerCertificate = toCertificateHolder(jSignerCertificate);

            MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
            md.update(dataToBeSigned);
            DEROctetString digest = new DEROctetString(md.digest());

            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);
            SignerInfo signerInfo = this.createSignerInfo(signerCertificate, digestAlgorithm, digest, privateKey);
            ASN1EncodableVector digestAlgorithmsVector = new ASN1EncodableVector();
            digestAlgorithmsVector.add(digestAlgorithm);
            DERSet digestAlgorithms = new DERSet(digestAlgorithmsVector);
            ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : toCertificateHolder(jCertificateChain)) {
                certificatesVector.add(c.toASN1Structure());
            }

            ASN1EncodableVector signerInfosVector = new ASN1EncodableVector();
            signerInfosVector.add(signerInfo);
            SignedData signedData = new SignedData(digestAlgorithms, contentInfo, new DERSet(certificatesVector), null, new DERSet(signerInfosVector));
            ContentInfo signedDataContentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);
            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, signedDataContentInfo);
            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException | SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }

    private SignerInfo createSignerInfo(X509CertificateHolder signerCertificate, AlgorithmIdentifier digestAlgorithm, ASN1OctetString digest, PrivateKey privateKey) throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchProviderException {
        SignerIdentifier signerIdentifier = new SignerIdentifier(new IssuerAndSerialNumber(signerCertificate.getIssuer(), signerCertificate.getSerialNumber()));
        ASN1EncodableVector authAttribVector = new ASN1EncodableVector();
        authAttribVector.add(new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)));
        authAttribVector.add(new Attribute(CMSAttributes.messageDigest, new DERSet(digest)));
        authAttribVector.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))));
        MessageDigest md = MessageDigest.getInstance("SHA256", "BC");
        md.update(signerCertificate.getEncoded());
        byte[] digestBytes = md.digest();
        authAttribVector.add(new Attribute(PKCSObjectIdentifiers.id_aa_ets_otherSigCert, new DERSet(new OtherSigningCertificate(new OtherCertID(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), digestBytes)))));


        DERSet authenticatedAttributes1 = new DERSet(authAttribVector);
        AlgorithmIdentifier digestEncryptionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
        byte[] pkcs1Bytes1 = signData(privateKey, authenticatedAttributes1.getEncoded());
        DEROctetString encryptedDigest1 = new DEROctetString(pkcs1Bytes1);
        return new SignerInfo(signerIdentifier, digestAlgorithm, authenticatedAttributes1, digestEncryptionAlgorithm, encryptedDigest1, null);
    }

    private byte[] signData(PrivateKey privateKey, byte[] toBeSigned) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");

        signature.initSign(privateKey);
        signature.update(toBeSigned);
        return signature.sign();
    }

    public boolean verifySignedMessageCMS(X509Certificate rootCert, byte dtbs[], byte[] base64EncodedCMS) throws Exception {
        final byte[] cmsBytes = Base64.getDecoder().decode(base64EncodedCMS);

        final CMSSignedData signedData = new CMSSignedData(cmsBytes);

// må vi legge dtbs inn i cms-en ??
        CertStore certsAndCRLs = new JcaCertStoreBuilder().setProvider("BC").addCertificates(signedData.getCertificates()).build();

        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();
        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = new
                    JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
           // signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.digitalSignature)); // TODO: BankID sign certs er markert med non_repudiation
            PKIXCertPathBuilderResult result = buildPath(rootCert,
                    signerConstraints, certsAndCRLs);
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build((X509Certificate) result.getCertPath().getCertificates().get(0)));
        }
        return false;

//        Store certs = signedData.getCertificates();
//        SignerInformationStore signers = signedData.getSignerInfos();
//        Iterator it = signers.getSigners().iterator();
//        if (it.hasNext())
//        {
//            SignerInformation signer = (SignerInformation)it.next();
//            X509CertificateHolder cert =
//                    (X509CertificateHolder)certs.getMatches(signer.getSID()).iterator().next();
//            SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
//                    new DefaultCMSSignatureAlgorithmNameGenerator(),
//                    new DefaultSignatureAlgorithmIdentifierFinder(),
//                    new DefaultDigestAlgorithmIdentifierFinder(),
//                    new BcDigestCalculatorProvider()).build(cert);
//            return signer.verify(verifier);
//        }
//        return false;
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
        final byte[] cmsBytes = signMessageAndVerifySignature.signMessageAndCreateCMSWithoutOCSP(dtbs, messageSignerPath.getCertificates(), messageSignerCertificate, (PrivateKey) signerKey);


        System.out.println("bytes = \n" + new String(cmsBytes));
        ByteArrayInputStream bankIDRootStream = new ByteArrayInputStream(SomeUtils.BANKID_ROOT_CERTIFICATE_PREPROD.getBytes());
        X509Certificate bankIDRootCert = (X509Certificate) SomeUtils.CERTIFICATE_FACTORY.generateCertificate(bankIDRootStream);
        signMessageAndVerifySignature.verifySignedMessageCMS(bankIDRootCert, dtbs, cmsBytes);

    }
}
