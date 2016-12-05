package no.bankid.openb2b;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static no.bankid.openb2b.OcspChecker.BEGIN_CERTIFICATE;
import static no.bankid.openb2b.OcspChecker.END_CERTIFICATE;

public class OcspRequester {
    private final static Logger LOGGER = LoggerFactory.getLogger(OcspRequester.class);
    private static final int CONNECT_TIMEOUT_MS = 15000;


    public static class OCSPResponseHolder {
        final String signerCert;
        final String signerName;
        final byte[] rawOcspResponse;

        public OCSPResponseHolder(String signerCert, String signerName, byte[] rawOcspResponse) {
            this.signerCert = signerCert;
            this.signerName = signerName;
            this.rawOcspResponse = rawOcspResponse;
        }
    }

    /**
     * @param certToBeValidated must contain the authorityInfoAccessExtension holding the url for the va service
     * @param issuerCert        issuer of certToBeValidated, used together with certToBeValidated's serialnumber
     * @param signerChain       used for signing the ocsp request to the va service, used if nonempty
     * @return DEREncoded bytes
     * @optional key used together with the signerchain to sign the ocsp request, used if signerchain is nonempty
     */
    OCSPResponseHolder sendOcspRequestGetResponse(X509Certificate certToBeValidated, X509Certificate issuerCert,
                                                  List<? extends java.security.cert.Certificate> signerChain, Optional<PrivateKey> signerKey) {

        final URL ocspUrlFromCertificate = getOcspUrlFromCertificate(certToBeValidated);
        final OCSPReq ocspReq;
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        try {
            CertificateID id = new CertificateID(new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert), certToBeValidated.getSerialNumber());

            LOGGER.debug("Connecting to instance.toString() = " + ocspUrlFromCertificate);

            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(id);

            // create details for nonce extension
            Extension ocspNonce = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce.toByteArray());
            gen.setRequestExtensions(new Extensions(ocspNonce));

            if (signerChain != null && !signerChain.isEmpty()) {
                final List<X509CertificateHolder> x509CertificateHolders = toHolder(signerChain);
                gen.setRequestorName(x509CertificateHolders.get(0).getSubject());
                ocspReq = gen.build(new JcaContentSignerBuilder("SHA256WithRSA").build(signerKey.get()), x509CertificateHolders.toArray(new X509CertificateHolder[signerChain.size()]));
            } else {
                ocspReq = gen.build();
            }

        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            throw new IllegalArgumentException(e);
        } // TODO: se http://www.programcreek.com/java-api-examples/index.php?api=org.bouncycastle.ocsp.OCSPResp for enklere kode, og husk å legge inn sjekk på nonceverdien sent over.
        final byte[] ocspReqBytes;
        try {
            ocspReqBytes = ocspReq.getEncoded();
            System.out.println("OcspReq:\n" + new String(Base64.getMimeEncoder().encode(ocspReqBytes)));
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
                        LOGGER.debug("OcspResp:\n" + new String(Base64.getMimeEncoder().encode(ocspResponseBytes)));
                        break;
                    }
                    final ResponseSignerCertAndName responseSignerCertAndName = showResponse(ocspResponseBytes, nonce);
                    return new OCSPResponseHolder(responseSignerCertAndName.responseSignerCert, responseSignerCertAndName.responseSignerName, ocspResponseBytes);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not determine revooation status due to io error ", e);
        }
    }

    private List<X509CertificateHolder> toHolder(List<? extends Certificate> signerChain) {
        List<X509CertificateHolder> ret = new ArrayList<>();
        for (Certificate c : signerChain) {
            try {
                ret.add(new JcaX509CertificateHolder((X509Certificate) c));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }
        return ret;
    }

    private static class ResponseSignerCertAndName {
        final String responseSignerCert;
        final String responseSignerName;

        ResponseSignerCertAndName(String responseSignerCert, String responseSignerName) {
            this.responseSignerCert = responseSignerCert;
            this.responseSignerName = responseSignerName;
        }
    }

    private ResponseSignerCertAndName showResponse(byte[] ocspResponseBytes, BigInteger expectedNonceValue) {
        try {

            final OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(ocspResponseBytes));
            if (ocspResp.getStatus() != 0) {
                throw new IOException("Invalid OCSP status " + ocspResp.getStatus());
            }
            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();

            final BigInteger foundNonce = new BigInteger(basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getOctets()); // TODO: nullchecks
            if (Objects.equals(foundNonce, expectedNonceValue)) {
                System.out.println("Nonce as expected.");
            }
            final X500Name responseSignerName = basicOCSPResp.getResponderId().toASN1Primitive().getName();
            System.out.println("Responder name is " + responseSignerName);
            final X509CertificateHolder[] certs = basicOCSPResp.getCerts();
            final boolean signatureValid = basicOCSPResp.isSignatureValid(
                    new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(certs[0]));
            System.out.println("Response signature is valid: " + signatureValid);
            //X509Certificate signerCert = new JcaX509CertificateConverter().getCertificate(certs[0]);
            System.out.println("certificate used for signing OCSP response is: ");
            final String responseSignerCertMimeEncoded = BEGIN_CERTIFICATE + new String(Base64.getMimeEncoder().encode(certs[0].getEncoded())) + "\n" + END_CERTIFICATE;
            System.out.println(responseSignerCertMimeEncoded);

            SingleResp singleResp = basicOCSPResp.getResponses()[0];

            final CertificateStatus certStatus = singleResp.getCertStatus();
            if (certStatus instanceof RevokedStatus) {
                System.out.println("Cert revoked");
            } else if (certStatus == CertificateStatus.GOOD) {
                System.out.println("Certstatus is good");
            } else {
                System.out.println("Certstatus is unknown");
            }
            return new ResponseSignerCertAndName(responseSignerCertMimeEncoded, responseSignerName.toString());
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
