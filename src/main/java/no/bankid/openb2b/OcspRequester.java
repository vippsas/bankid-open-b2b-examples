package no.bankid.openb2b;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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

import static no.bankid.openb2b.Algorithms.SHA512withRSA;
import static no.bankid.openb2b.SecurityProvider.toCertificateHolders;

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

        URL ocspUrlFromCertificate = getOcspUrlFromCertificate(certToBeValidated);
        LOGGER.info("Connecting to VA: {}", ocspUrlFromCertificate);

        OCSPReq ocspReq;
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        try {
            CertificateID id =
                    new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                            new JcaX509CertificateHolder(issuerCert), certToBeValidated.getSerialNumber());

            OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
            ocspReqBuilder.addRequest(id); // a certificate is identified using it's issuer and it's serialnumber.

            // Place a nonce in the request, to prevent attack
            Extension ocspNonce = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce.toByteArray());
            ocspReqBuilder.setRequestExtensions(new Extensions(ocspNonce));

            // Sign request if signerchain is given, all BankID VA's demands signed ocsp requests.
            if (signerChain != null && !signerChain.isEmpty()) {
                List<X509CertificateHolder> x509CertificateHolders = toCertificateHolders(signerChain);
                X500Name requestorName = x509CertificateHolders.get(0).getSubject();
                LOGGER.info("Using '{}' as requestor name", requestorName);
                // Mandatory to set the requestorname
                ocspReqBuilder.setRequestorName(requestorName);
                ocspReq = ocspReqBuilder.build(new JcaContentSignerBuilder(SHA512withRSA.name()).build(signerKey),
                        x509CertificateHolders.toArray(new X509CertificateHolder[signerChain.size()]));
            } else {
                ocspReq = ocspReqBuilder.build();
            }

        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            throw new IllegalArgumentException(e);
        }

        byte ocspResponseBytes[] = sendRequest(ocspUrlFromCertificate, ocspReq);

        checkResult(ocspResponseBytes, nonce);

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

    private void checkResult(byte[] ocspResponseBytes, BigInteger expectedNonceValue) {
        try {

            OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponseBytes));
            if (ocspResp.getStatus() != 0) {
                throw new IllegalStateException("Invalid OCSP status " + ocspResp.getStatus());
            }
            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
            Optional<Extension> nonceExtension = Optional.ofNullable(basicOCSPResp.getExtension(OCSPObjectIdentifiers
                    .id_pkix_ocsp_nonce));
            BigInteger foundNonce = nonceExtension.map(nonceReceived -> new BigInteger(nonceReceived.getExtnValue()
                    .getOctets())).orElse(null);

            if (!Objects.equals(foundNonce, expectedNonceValue)) {
                throw new IllegalStateException("Invalid nonce value in OCSP response expected: " + expectedNonceValue
                        + " received:" + foundNonce);
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("OCSP Responder's name is " + basicOCSPResp.getResponderId().toASN1Primitive().getName());
                X509CertificateHolder[] certs = basicOCSPResp.getCerts();
                boolean signatureValid = basicOCSPResp.isSignatureValid(new BcRSAContentVerifierProviderBuilder(new
                        DefaultDigestAlgorithmIdentifierFinder()).build(certs[0]));
                LOGGER.debug("OCSP Responder's signature is valid: " + signatureValid);
                LOGGER.debug("OCSP Responder's certificate used for signing OCSP response is:\n " + "-----BEGIN " +
                        "CERTIFICATE-----\n" + new String(Base64.getMimeEncoder().encode(certs[0].getEncoded())) +
                        "\n" + "-----END CERTIFICATE-----\n");

                SingleResp singleResp = basicOCSPResp.getResponses()[0];

                CertificateStatus certStatus = singleResp.getCertStatus();
                if (certStatus instanceof RevokedStatus) {
                    LOGGER.debug("Certificate status is REVOKED");
                } else if (certStatus == CertificateStatus.GOOD) {
                    LOGGER.debug("Certificate status is GOOD");
                } else {
                    LOGGER.debug("Certificate status is UNKNOWN");
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
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
