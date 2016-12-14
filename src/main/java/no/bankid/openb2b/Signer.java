package no.bankid.openb2b;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * See rfc5652 (https://tools.ietf.org/html/rfc5652) for details about cms content.
 */
public class Signer {

    private static final Logger LOGGER = LoggerFactory.getLogger(Signer.class);

    private static final JcaContentSignerBuilder SHA_512_WITH_RSA_SIGNER_BUILDER =
            new JcaContentSignerBuilder("SHA512withRSA");


    public static byte[] signWithoutOCSPResponse(byte[] dataToBeSigned,
                                                 CertPath signerCertPath,
                                                 PrivateKey signerKey) {
        try {
            LOGGER.info("Signs a message, NO OCSP Response in the result");

            ContentSigner sha512Signer = SHA_512_WITH_RSA_SIGNER_BUILDER.build(signerKey);
            JcaX509CertificateHolder signerCert =
                    new JcaX509CertificateHolder((X509Certificate) signerCertPath.getCertificates().get(0));
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
            JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider);
            generator.addSignerInfoGenerator(infoGeneratorBuilder.build(sha512Signer, signerCert));
            generator.addCertificates(new JcaCertStore(signerCertPath.getCertificates()));
            CMSSignedData cmsSignedData = generator.generate(new CMSProcessableByteArray(dataToBeSigned), false);

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

            // TODO: Consider extracting these two lines outside of this class and providing an optional OCSPResponse
            // instead.
            // Check revocation state for our own signing certificate and add the signed response to the CMS
            byte[] ocspResponseBytes = bankIDStatusChecker.validateCertPathAndOcspResponseOnline(signerCertPath);
            OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponseBytes);

            ContentSigner sha512Signer = SHA_512_WITH_RSA_SIGNER_BUILDER.build(signerKey);
            JcaX509CertificateHolder signerCert =
                    new JcaX509CertificateHolder((X509Certificate) signerCertPath.getCertificates().get(0));
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
            JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestProvider);
            generator.addSignerInfoGenerator(infoGeneratorBuilder.build(sha512Signer, signerCert));
            generator.addCertificates(new JcaCertStore(signerCertPath.getCertificates()));
            generator.addOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_response, ocspResponse);
            CMSSignedData cmsSignedData = generator.generate(new CMSProcessableByteArray(dataToBeSigned), false);

            return Base64.getEncoder().encode(cmsSignedData.getEncoded());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
