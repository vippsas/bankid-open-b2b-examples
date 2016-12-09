package no.bankid.openb2b;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ess.OtherSigningCertificate;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static no.bankid.openb2b.Algos.*;
import static no.bankid.openb2b.SomeUtils.*;

public class SignMessageAndVerifySignature {

    /**
     * See rfc5652 for details about cms content. See BankID (TODO finn doc) for hva som må være med.
     *
     * @param dataToBeSigned
     * @param messageSignerPath
     * @param messageSignerKey
     * @return
     * @throws InvalidKeyException
     */

    public byte[] signMessageAndCreateDetachedCMSWithoutOCSPResponse(byte[] dataToBeSigned,
                                                                     CertPath messageSignerPath,
                                                                     PrivateKey messageSignerKey
    ) {
        try {
            System.out.println("\n\nSigns a message, NO OCSP Response in the result");
            X509CertificateHolder signerCertificate = toCertificateHolder(messageSignerPath.getCertificates().get(0));

            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);

            SignerInfo signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)), messageSignerKey);

            ContentInfo detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : toCertificateHolder(messageSignerPath.getCertificates())) {
                certificatesVector.add(c.toASN1Structure());
            }

            SignedData signedData = new SignedData(  // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA256.asId())),
                    detachedContentInfo,
                    new BERSet(certificatesVector),
                    null,
                    new DERSet(toASN1EncodableVector(signerInfo)));

            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, new ContentInfo(PKCSObjectIdentifiers.signedData, signedData));
            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | IOException | SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] signMessageAndCreateDetachedCMSWithValidatedOCSPResponse(byte[] dataToBeSigned,
                                                                           CertPath messageSignerPath,
                                                                           PrivateKey messageSignerKey,
                                                                           OcspChecker ocspChecker
    ) {
        try {
            System.out.println("\n\nSigns a message, EMBEDS an OCSP Response in the result");

            X509CertificateHolder signerCertificate = toCertificateHolder(messageSignerPath.getCertificates().get(0));


            CMSProcessableByteArray signedContent = new CMSProcessableByteArray(dataToBeSigned);
            SignerInfo signerInfo = createSignerInfo(signerCertificate, new DEROctetString(doDigest(dataToBeSigned)), messageSignerKey);

            ContentInfo detachedContentInfo = new ContentInfo(PKCSObjectIdentifiers.data, null);
            ASN1EncodableVector certificatesVector = new ASN1EncodableVector();

            for (X509CertificateHolder c : toCertificateHolder(messageSignerPath.getCertificates())) {
                certificatesVector.add(c.toASN1Structure());
            }

            // Check revocation state for our own signing certificate and add the signed response to the CMS
            byte[] ocspResponseBytes = ocspChecker.getOcspResponseFromVa(messageSignerPath);
            ocspChecker.validateOcspResponse(messageSignerPath, ocspResponseBytes); // Still only throws if not ok, TODO: make it return a usable value ?

            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponseBytes);
            SignedData signedData = new SignedData( // TODO: vurder å bruke CMSSignedDataGenerator, da slipper vi å tenke på BER/DER etc.
                    new DERSet(toASN1EncodableVector(SHA256.asId())),
                    detachedContentInfo,
                    new BERSet(certificatesVector),
                    new BERSet(toASN1EncodableVector(new DERTaggedObject(false, 1, new OtherRevocationInfoFormat(OCSPObjectIdentifiers.id_pkix_ocsp_response, ocspResponse)))),
                    new DERSet(toASN1EncodableVector(signerInfo)));

            CMSSignedData cmsSignedData = new CMSSignedData(signedContent, new ContentInfo(PKCSObjectIdentifiers.signedData, signedData));

            return Base64.getEncoder().encode(cmsSignedData.getEncoded());
        } catch (InvalidAlgorithmParameterException | CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | IOException | SignatureException | CMSException e) {
            throw new RuntimeException(e);
        }
    }


    private SignerInfo createSignerInfo(X509CertificateHolder signerCertificate, ASN1OctetString dtbsDigest, PrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchProviderException {
        ASN1EncodableVector authAttribVector = toASN1EncodableVector( // This is the same attributes as BIDJServer adds to the CMS
                new Attribute(CMSAttributes.contentType, new DERSet(PKCSObjectIdentifiers.data)),
                new Attribute(CMSAttributes.messageDigest, new DERSet(dtbsDigest)),
                new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date()))),
                new Attribute(PKCSObjectIdentifiers.id_aa_ets_otherSigCert,
                        new DERSet(new OtherSigningCertificate(new OtherCertID(SHA256.asId(), doDigest(signerCertificate.getEncoded()))))));

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

    @SuppressWarnings("unchecked")
    /**
     * Handles verification of a signed message.
     */
    public boolean verifySignedMessageAndDetachedCMS(X509Certificate rootCert, byte dtbs[], byte[] base64EncodedCMS, OcspChecker ocspChecker) throws Exception {

        System.out.println("\nVerifies a signed message");
        final byte[] cmsBytesBlock = Base64.getDecoder().decode(base64EncodedCMS);

        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(dtbs), cmsBytesBlock);

        CertStore certsAndCRLs = new JcaCertStoreBuilder().addCertificates(signedData.getCertificates()).build();

        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator it = signers.getSigners().iterator();
        if (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = new JcaX509CertSelectorConverter().getCertSelector(signer.getSID());
            signerConstraints.setKeyUsage(getKeyUsage(KeyUsage.nonRepudiation)); // TODO: BankID sign certs er markert med non_repudiation ikke digitalSignature
            CertPath certPath = buildPath(rootCert, signerConstraints, certsAndCRLs);
            List<? extends Certificate> certificates = certPath.getCertificates();

            System.out.println("Message was signed by " + ((X509Certificate) certificates.get(0)).getSubjectX500Principal().getName("RFC1779"));

            Store<DERSequence> otherRevocationInfoStore = signedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            Collection<DERSequence> allOtherRevocationInfos = otherRevocationInfoStore.getMatches(null);

            byte [] ocspResponse;
            if (allOtherRevocationInfos.isEmpty()) {
                System.out.println("Checking revocation state by asking VA");
                // We have to check the signing certificate ourselves by sending an OCSP request
                ocspResponse = ocspChecker.getOcspResponseFromVa(certPath);
            } else {
                // Sender has inserted ocsp response
                System.out.println("Checking embedded OCSP response ");
                // We handle only the first, in case of more than one, these should be handled
                 ocspResponse = OCSPResponse.getInstance(allOtherRevocationInfos.iterator().next()).getEncoded();
            }
            ocspChecker.validateOcspResponse(certPath, ocspResponse);

            X509Certificate signerCertificate = (X509Certificate) certificates.get(0);

            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate));
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore messageSignerKeystore = KeyStore.getInstance("JKS");
        String messageSignerTrustKeystore = "www.kantega.no-sign.jks";
        messageSignerKeystore.load(Files.newInputStream(SomeUtils.RESOURCES_PATH.resolve(messageSignerTrustKeystore).toAbsolutePath()), "changeit".toCharArray());
        PrivateKey signerKey = (PrivateKey) messageSignerKeystore.getKey("sign", "changeit".toCharArray());
        List<Certificate> messageSignerCertificateChain = Arrays.asList(messageSignerKeystore.getCertificateChain("sign"));

        // extract the certification path from the list of Certificates
        CertPath messageSignerPath = SomeUtils.CERTIFICATE_FACTORY.generateCertPath(messageSignerCertificateChain);

        SignMessageAndVerifySignature signMessageAndVerifySignature = new SignMessageAndVerifySignature();

        final byte[] dtbs = "Hello World".getBytes(StandardCharsets.UTF_8);


        ByteArrayInputStream bankIDRootStream = new ByteArrayInputStream(SomeUtils.BANKID_ROOT_CERTIFICATE_PREPROD.getBytes());
        X509Certificate bankIDRootCert = (X509Certificate) SomeUtils.CERTIFICATE_FACTORY.generateCertificate(bankIDRootStream);

        final OcspChecker ocspChecker = new OcspChecker();

        final byte[] cmsBytesNoEmbeddedOcspResponse = signMessageAndVerifySignature.signMessageAndCreateDetachedCMSWithoutOCSPResponse(dtbs, messageSignerPath, signerKey);
        boolean resultNoEmbeddedOcspResponse = signMessageAndVerifySignature.verifySignedMessageAndDetachedCMS(bankIDRootCert, dtbs, cmsBytesNoEmbeddedOcspResponse, ocspChecker);
        System.out.println("resultNoEmbeddedOcspResponse = " + resultNoEmbeddedOcspResponse);

        final byte[] cmsBytesEmbeddedOcspResponse = signMessageAndVerifySignature.signMessageAndCreateDetachedCMSWithValidatedOCSPResponse(dtbs, messageSignerPath, signerKey, ocspChecker);

        boolean resultEmbeddedOcspResponse = signMessageAndVerifySignature.verifySignedMessageAndDetachedCMS(bankIDRootCert, dtbs, cmsBytesEmbeddedOcspResponse, ocspChecker);
        System.out.println("resultEmbeddedOcspResponse = " + resultEmbeddedOcspResponse);
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
