package no.bankid.openb2b;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;


public class OcspChecker {

    private final X509Certificate netsVAOCSPResponderCert;
    private final X509Certificate bankIDRootCert;
    private List<? extends Certificate> ocspRequestSignerCertificateChain;
    private PrivateKey ocspSignerKey;

    public OcspChecker() {
        try {
            ByteArrayInputStream bankIDRootStream = new ByteArrayInputStream(SomeUtils.BANKID_ROOT_CERTIFICATE_PREPROD.getBytes());
            bankIDRootCert = (X509Certificate) SomeUtils.CERTIFICATE_FACTORY.generateCertificate(bankIDRootStream);

            ByteArrayInputStream netsVAStream = new ByteArrayInputStream(SomeUtils.NETS_VA_OCSP_RESPONDER_CERTIFICATE_PREPROD.getBytes());
            netsVAOCSPResponderCert = (X509Certificate) SomeUtils.CERTIFICATE_FACTORY.generateCertificate(netsVAStream);
            initOcspSigner(SomeUtils.RESOURCES_PATH.resolve("www.kantega.no-sign.jks").toAbsolutePath(), "changeit".toCharArray(), "sign", "changeit".toCharArray());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void initOcspSigner(Path keystorePath, char[] keystorePassword, String keyAlias, char[] keyPassword)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchProviderException {
        // Load certificates for an OCSP request signer from a java keystore
        KeyStore ocspSignerKeyStore = KeyStore.getInstance("JKS");
        ocspSignerKeyStore.load(Files.newInputStream(keystorePath), keystorePassword);
        // Fetch private key for signing OCSP request
        ocspSignerKey = (PrivateKey) ocspSignerKeyStore.getKey(keyAlias, keyPassword);
        // fetch certificate chain for signing OCSP request
        List<? extends Certificate> ocspSignerCertificateChain = Arrays.asList(ocspSignerKeyStore.getCertificateChain(keyAlias));
        // extract the certification path from the list of Certificates
        CertPath ocspSignerCertPath = SomeUtils.CERTIFICATE_FACTORY.generateCertPath(ocspSignerCertificateChain);
        ocspRequestSignerCertificateChain = ocspSignerCertPath.getCertificates();
    }

    /**
     * Run with -Djava.security.debug="certpath ocsp" to debug.
     * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html for all options.
     *
     * @param args unused
     * @throws Exception when fail
     */
    public static void main(String args[]) throws Exception {
        OcspChecker ocspChecker = new OcspChecker();

        KeyStore messageSignerKeystore = KeyStore.getInstance("JKS");
        final String messageSignerTrustKeystore = "www.kantega.no-auth.jks";
        messageSignerKeystore.load(Files.newInputStream(SomeUtils.RESOURCES_PATH.resolve(messageSignerTrustKeystore).toAbsolutePath()), "changeit".toCharArray());
        List<Certificate> messageSignerCertificateChain = Arrays.asList(messageSignerKeystore.getCertificateChain("auth"));

        // extract the certification path from the list of Certificates
        CertPath messageSignerPath = SomeUtils.CERTIFICATE_FACTORY.generateCertPath(messageSignerCertificateChain);

        byte[] rawOcspResponse = ocspChecker.getOcspResponseFromVa(messageSignerPath);

        ocspChecker.validateOcspResponse(messageSignerPath, rawOcspResponse);
    }

    public void validateOcspResponse(CertPath messageSignerPath, byte[] rawOcspResponse)
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Map<X509Certificate, byte[]> prCertificateOcspResponses = new HashMap<>();
        X509Certificate messageSignerCertificate = (X509Certificate) messageSignerPath.getCertificates().get(0);
        prCertificateOcspResponses.put(messageSignerCertificate, rawOcspResponse);

        // Build an ocsp revocation checker
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
        // Tell the ocsp revocation checker who is signing the ocsp response, the actual value used may be found in the debug log for OcspRequester
        revocationChecker.setOcspResponderCert(netsVAOCSPResponderCert);
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY));
        revocationChecker.setOcspResponses(prCertificateOcspResponses);

        Set<TrustAnchor> anchors = generateTrustAnchors();
        PKIXParameters params = new PKIXParameters(anchors);

        // Activate certificate revocation checking, otherwise no check for ocsp is done
        params.setRevocationEnabled(true);
        params.addCertPathChecker(revocationChecker);
        try {
            System.out.println("Validates OCSP response for certificate " + messageSignerCertificate.getSubjectX500Principal().getName("RFC1779"));
            CertPathValidator.getInstance("PKIX").validate(messageSignerPath, params);
            System.out.println("Status is OK");

        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            X509Certificate certificate = (X509Certificate) e.getCertPath().getCertificates().get(e.getIndex());
            System.out.println(certificate.getSubjectX500Principal().getName("RFC1779") + ": " + e.getReason());
            throw new IllegalStateException(e);
        }

    }

    /**
     * Sends a signed request to the BankID Va based and return its response unvalidated.
     * This is the call which generates a billing to the owner of the OCSP signer certificate owner.
     * @param messageSignerPath the signerpath
     * @return the response received
     */
    public byte[] getOcspResponseFromVa(CertPath messageSignerPath) {


        X509Certificate messageSignerCertificateIssuer = (X509Certificate) messageSignerPath.getCertificates().get(1);
        X509Certificate messageSignerCertificate = (X509Certificate) messageSignerPath.getCertificates().get(0);
        System.out.println("Sending OCSP request for certificate " + messageSignerCertificate.getSubjectX500Principal().getName("RFC1779"));

        return new OcspRequester().sendOcspRequestGetResponse(messageSignerCertificate, messageSignerCertificateIssuer, ocspRequestSignerCertificateChain, ocspSignerKey);
    }

    private Set<TrustAnchor> generateTrustAnchors() throws CertificateException {

        TrustAnchor bankIDRootAnchor = new TrustAnchor(bankIDRootCert, null);

        Set<TrustAnchor> list = new HashSet<>();
        list.add(bankIDRootAnchor);

        return list;
    }
}
