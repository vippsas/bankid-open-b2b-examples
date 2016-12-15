package no.bankid.openb2b;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import static no.bankid.openb2b.SecurityProvider.SHA_512_WITH_RSA_SIGNER_BUILDER;
import static no.bankid.openb2b.SecurityProvider.toCertificateHolders;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce;

/**
 * See RFC6960 for details.
 */
public class OcspRequester {

    private static final Logger LOGGER = LoggerFactory.getLogger(OcspRequester.class);

    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final String CONTENT_TYPE = "application/ocsp-request";

    public byte[] post(X509Certificate certToBeValidated,
                       X509Certificate issuerCert,
                       List<? extends Certificate> signerChain,
                       PrivateKey signerKey) {

        if (signerChain == null || signerChain.isEmpty()) {
            throw new IllegalArgumentException("Parameter signerChain is required to sign OCSP request");
        }

        OCSPReq ocspReq;
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        try {

            OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();

            // A certificate is identified using it's issuer and it's serialnumber.
            DigestCalculator digestCalc = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
            JcaX509CertificateHolder issuerCertHolder = new JcaX509CertificateHolder(issuerCert);
            BigInteger serialNumber = certToBeValidated.getSerialNumber();
            CertificateID id = new CertificateID(digestCalc, issuerCertHolder, serialNumber);
            ocspReqBuilder.addRequest(id);

            // Place a nonce in the request, to prevent replay attack
            Extension ocspNonce = new Extension(id_pkix_ocsp_nonce, false, nonce.toByteArray());
            ocspReqBuilder.setRequestExtensions(new Extensions(ocspNonce));

            // Mandatory to set the requestorname
            List<X509CertificateHolder> certificateHolders = toCertificateHolders(signerChain);
            X500Name requestorName = certificateHolders.get(0).getSubject();
            LOGGER.info("Using '{}' as requestor name", requestorName);
            ocspReqBuilder.setRequestorName(requestorName);

            // Sign request, all BankID VA's demands signed ocsp requests.
            ContentSigner signer = SHA_512_WITH_RSA_SIGNER_BUILDER.build(signerKey);
            X509CertificateHolder[] chain = certificateHolders.toArray(new X509CertificateHolder[signerChain.size()]);

            ocspReq = ocspReqBuilder.build(signer, chain);

        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            throw new IllegalArgumentException(e);
        }

        URL ocspUrlFromCertificate = getOcspUrlFromCertificate(certToBeValidated);
        LOGGER.info("Connecting to VA: {}", ocspUrlFromCertificate);
        byte ocspResponseBytes[] = sendRequest(ocspUrlFromCertificate, ocspReq);

        OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponseBytes));
        if (ocspResp.getStatus() != 0) {
            throw new IllegalStateException("Invalid OCSP status " + ocspResp.getStatus());
        }

        BasicOCSPResp basicOCSPResp = checkNonce(ocspResp, nonce);
        debugLog(basicOCSPResp);

        return ocspResponseBytes;
    }

    private byte[] sendRequest(URL ocspUrlFromCertificate, OCSPReq ocspReq) {

        try {

            byte[] ocspReqBytes = ocspReq.getEncoded();
            LOGGER.debug("Sending OcspReq:\n{}", new String(Base64.getMimeEncoder().encode(ocspReqBytes)));
            HttpURLConnection vaConnection = (HttpURLConnection) ocspUrlFromCertificate.openConnection();
            vaConnection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            vaConnection.setReadTimeout(CONNECT_TIMEOUT_MS);
            vaConnection.setDoOutput(true);
            vaConnection.setDoInput(true);
            vaConnection.setRequestMethod("POST");
            vaConnection.setRequestProperty("Content-type", CONTENT_TYPE);
            vaConnection.setRequestProperty("Content-length", String.valueOf(ocspReqBytes.length));

            try (OutputStream vaConnectionOutputStream = vaConnection.getOutputStream()) {
                vaConnectionOutputStream.write(ocspReqBytes);
                vaConnectionOutputStream.flush();
                if (vaConnection.getResponseCode() != 200) {
                    LOGGER.debug("OCSP Received HTTP error: {} - {}",
                            vaConnection.getResponseCode(), vaConnection.getResponseMessage());
                }
            }

            try (InputStream inputStream = vaConnection.getInputStream()) {
                ByteArrayOutputStream ocspResponseBuffer = new ByteArrayOutputStream();
                int bytesRead;
                byte[] data = new byte[16384];
                while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
                    ocspResponseBuffer.write(data, 0, bytesRead);
                }

                LOGGER.debug("Received OcspResp:\n{}",
                        new String(Base64.getMimeEncoder().encode(ocspResponseBuffer.toByteArray())));

                return ocspResponseBuffer.toByteArray();
            }

        } catch (IOException e) {
            throw new IllegalStateException("Could not determine revocation status due to IO error ", e);
        }
    }

    private BasicOCSPResp checkNonce(OCSPResp ocspResponse, BigInteger expectedNonceValue) {

        try {

            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResponse.getResponseObject();
            Optional<Extension> nonceExtension = Optional.ofNullable(basicOCSPResp.getExtension(id_pkix_ocsp_nonce));
            BigInteger foundNonce = nonceExtension
                    .map(nonceReceived -> new BigInteger(nonceReceived.getExtnValue().getOctets()))
                    .orElse(null);

            if (!Objects.equals(foundNonce, expectedNonceValue)) {
                throw new IllegalStateException(
                        String.format("Invalid nonce value in OCSP response expected: %s,  received: %s",
                                expectedNonceValue, foundNonce));
            }

            return basicOCSPResp;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void debugLog(BasicOCSPResp basicOCSPResp) {
        if (LOGGER.isDebugEnabled()) {

            try {
                LOGGER.debug("OCSP Responder's name is " + basicOCSPResp.getResponderId().toASN1Primitive().getName());
                X509CertificateHolder[] certs = basicOCSPResp.getCerts();
                BcRSAContentVerifierProviderBuilder verifierBuilder =
                        new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder());
                ContentVerifierProvider verifier = verifierBuilder.build(certs[0]);
                LOGGER.debug("OCSP Responder's signature is valid: {}", basicOCSPResp.isSignatureValid(verifier));
                LOGGER.debug("OCSP Responder's certificate used for signing OCSP response is:\n {}\n{}\n{}",
                        "-----BEGIN CERTIFICATE-----",
                        new String(Base64.getMimeEncoder().encode(certs[0].getEncoded())),
                        "-----END CERTIFICATE-----\n");

                SingleResp singleResp = basicOCSPResp.getResponses()[0];

                CertificateStatus certStatus = singleResp.getCertStatus();
                if (certStatus instanceof RevokedStatus) {
                    LOGGER.debug("Certificate status is REVOKED");
                } else if (certStatus == CertificateStatus.GOOD) {
                    LOGGER.debug("Certificate status is GOOD");
                } else {
                    LOGGER.debug("Certificate status is UNKNOWN");
                }
            } catch (OCSPException | OperatorCreationException | IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private URL getOcspUrlFromCertificate(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());

        try {
            ASN1Sequence authorityInfoAccess = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(extensionValue);
            Enumeration<?> objects = authorityInfoAccess.getObjects();

            while (objects.hasMoreElements()) {
                ASN1Sequence accessDescription = (ASN1Sequence) objects.nextElement();
                ASN1ObjectIdentifier accessMethod = (ASN1ObjectIdentifier) accessDescription.getObjectAt(0);
                DERTaggedObject accessLocation = (DERTaggedObject) accessDescription.getObjectAt(1);

                if (accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DEROctetString uri = (DEROctetString) accessLocation.getObject();
                    String str = new String(uri.getOctets());
                    if (accessMethod.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                        return new URL(str);
                    }
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

        throw new IllegalArgumentException("Could not find OCSP URL in certificate");
    }
}
