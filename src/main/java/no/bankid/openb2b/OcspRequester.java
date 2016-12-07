package no.bankid.openb2b;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import static no.bankid.openb2b.SomeUtils.Algos.SHA256withRSA;
import static no.bankid.openb2b.SomeUtils.*;

public class OcspRequester {
    private final static Logger LOGGER = LoggerFactory.getLogger(OcspRequester.class);
    private static final int CONNECT_TIMEOUT_MS = 15000;

    /**
     * See RFC6960 for details.
     *
     * @param certToBeValidated must contain the authorityInfoAccessExtension holding the url for the va service and the certificate serialnumber
     * @param issuerCert        issuer of certToBeValidated, used together with certToBeValidated's serialnumber
     * @param signerChain       used for signing the ocsp request to the va service, used if nonempty
     * @param signerKey         used together with the signerchain to sign the ocsp request, required if signerchain is nonempty
     * @return DEREncoded bytes
     */
    public byte[] sendOcspRequestGetResponse(X509Certificate certToBeValidated, X509Certificate issuerCert,
                                             List<? extends java.security.cert.Certificate> signerChain, PrivateKey signerKey) {

        final URL ocspUrlFromCertificate = getOcspUrlFromCertificate(certToBeValidated);
        LOGGER.debug("Connecting to instance.toString() = " + ocspUrlFromCertificate);

        final OCSPReq ocspReq;
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
                final List<X509CertificateHolder> x509CertificateHolders = toCertificateHolder(signerChain);
                ocspReqBuilder.setRequestorName(x509CertificateHolders.get(0).getSubject()); // Mandatory to set the requestorname
                ocspReq = ocspReqBuilder.build(new JcaContentSignerBuilder(SHA256withRSA.name()).build(signerKey),
                        x509CertificateHolders.toArray(new X509CertificateHolder[signerChain.size()]));
            } else {
                ocspReq = ocspReqBuilder.build();
            }

        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            throw new IllegalArgumentException(e);
        } // TODO: se http://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.ocsp.OCSPResp for enklere kode, og husk å legge inn sjekk på nonceverdien sent over.
        byte ocspResponseBytes[] = sendRequest(ocspUrlFromCertificate, ocspReq);

        checkResult(ocspResponseBytes, nonce);

        return ocspResponseBytes;
    }

    private byte[] sendRequest(URL ocspUrlFromCertificate, OCSPReq ocspReq) {
        try {
            byte[] ocspReqBytes = ocspReq.getEncoded();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Sending OcspReq:\n" + new String(Base64.getMimeEncoder().encode(ocspReqBytes)));
            }
            HttpURLConnection vaConnection = (HttpURLConnection) ocspUrlFromCertificate.openConnection();
            vaConnection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            vaConnection.setReadTimeout(CONNECT_TIMEOUT_MS);
            vaConnection.setDoOutput(true);
            vaConnection.setDoInput(true);
            vaConnection.setRequestMethod("POST");
            vaConnection.setRequestProperty("Content-type", "application/ocsp-request");
            vaConnection.setRequestProperty("Content-length", String.valueOf(ocspReqBytes.length));
            try (OutputStream vaConnectionOutputStream = vaConnection.getOutputStream()) {
                vaConnectionOutputStream.write(ocspReqBytes);
                vaConnectionOutputStream.flush();
                if (vaConnection.getResponseCode() != 200) {
                    LOGGER.debug("OCSP Received HTTP error: " + vaConnection.getResponseCode() + " - " + vaConnection.getResponseMessage());
                }
                try (final InputStream vaConnectionInputStream = vaConnection.getInputStream()) {
                    int responseLength = vaConnection.getContentLength();
                    if (responseLength == -1) {
                        responseLength = 2147483647;
                    }
                    byte[] ocspResponseBytes = new byte[responseLength > 2048 ? 2048 : responseLength];
                    int nReadSoFar = 0;

                    while (true) {
                        if (nReadSoFar < responseLength) {
                            int nRead = vaConnectionInputStream.read(ocspResponseBytes, nReadSoFar, ocspResponseBytes.length - nReadSoFar);
                            if (nRead >= 0) {
                                nReadSoFar += nRead;
                                if (nReadSoFar >= ocspResponseBytes.length && nReadSoFar < responseLength) {
                                    ocspResponseBytes = Arrays.copyOf(ocspResponseBytes, nReadSoFar * 2);
                                }
                                continue;
                            }
                        }

                        ocspResponseBytes = Arrays.copyOf(ocspResponseBytes, nReadSoFar);
                        if (LOGGER.isDebugEnabled()) {
                            LOGGER.debug("Received OcspResp:\n" + new String(Base64.getMimeEncoder().encode(ocspResponseBytes)));
                        }
                        break;
                    }

                    return ocspResponseBytes;
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not determine revooation status due to io error ", e);
        }
    }

    private void checkResult(byte[] ocspResponseBytes, BigInteger expectedNonceValue) {
        try {

            final OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponseBytes));
            if (ocspResp.getStatus() != 0) {
                throw new IllegalStateException("Invalid OCSP status " + ocspResp.getStatus());
            }
            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
            final Optional<Extension> nonceExtension = Optional.ofNullable(basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce));
            final BigInteger foundNonce = nonceExtension.map(nonceReceived -> new BigInteger(nonceReceived.getExtnValue().getOctets())).orElse(null);

            if (!Objects.equals(foundNonce, expectedNonceValue)) {
                throw new IllegalStateException("Invalid nonce value in OCSP response expected: " + expectedNonceValue + " received:" + foundNonce);
            }
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("OCSP Responder's name is " + basicOCSPResp.getResponderId().toASN1Primitive().getName());
                final X509CertificateHolder[] certs = basicOCSPResp.getCerts();
                final boolean signatureValid = basicOCSPResp.isSignatureValid(new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(certs[0]));
                LOGGER.debug("OCSP Responder's signature is valid: " + signatureValid);
                LOGGER.debug("OCSP Responder's certificate used for signing OCSP response is:\n " + BEGIN_CERTIFICATE + new String(Base64.getMimeEncoder().encode(certs[0].getEncoded())) + "\n" + END_CERTIFICATE);

                SingleResp singleResp = basicOCSPResp.getResponses()[0];

                final CertificateStatus certStatus = singleResp.getCertStatus();
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
            ASN1Sequence asn1Seq = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(extensionValue); // AuthorityInfoAccessSyntax
            Enumeration<?> objects = asn1Seq.getObjects();

            while (objects.hasMoreElements()) {
                ASN1Sequence obj = (ASN1Sequence) objects.nextElement(); // AccessDescription
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) obj.getObjectAt(0); // accessMethod
                DERTaggedObject location = (DERTaggedObject) obj.getObjectAt(1); // accessLocation

                if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    DEROctetString uri = (DEROctetString) location.getObject();
                    String str = new String(uri.getOctets());
                    if (oid.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
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
