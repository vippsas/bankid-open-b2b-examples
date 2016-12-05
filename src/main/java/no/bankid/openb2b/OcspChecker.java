package no.bankid.openb2b;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class OcspChecker {

    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----\n";
    private static final String NETS_VA_CERTIFICATE_PREPROD = BEGIN_CERTIFICATE  +
            "MIIExzCCAq+gAwIBAgICA+swDQYJKoZIhvcNAQELBQAwcTELMAkGA1UEBhMCTk8x\n" +
            "KjAoBgNVBAoMIVRFU1QgLSBGTkggb2cgU3BhcmViYW5rZm9yZW5pbmdlbjEWMBQG\n" +
            "A1UECwwNVEVTVCAtIEJhbmtJRDEeMBwGA1UEAwwVVEVTVCAtIEJhbmtJRCBSb290\n" +
            "IENBMB4XDTE1MDEyOTE0MDEyNFoXDTE5MDEyOTE0MDEyNFowXDELMAkGA1UEBhMC\n" +
            "Tk8xFTATBgNVBAoMDFRFU1QgTmV0cyBBUzEXMBUGA1UECwwOVEVTVCBlU2VjdXJp\n" +
            "dHkxHTAbBgNVBAMMFFRFU1QgQmFua0lEIE5ldHMgVkExMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEAwOG46CxGgisj6Nvr1T2SBG9W37eDXeM6Aha+f3Y9\n" +
            "2IDXL2ygyTaIFHnv/Es4qTd80j5CcVP24H3o5llx9maCcpEyrb396eR0FkI+O1Jb\n" +
            "z4mpnPHfhn3KlE7lPMADUGKGz9YoC3B67++y6O8+25w9KHip/AmHjnn1upKdMCTA\n" +
            "cp520+ekDuZFWnHTnuR8xtHJwo76MFWJbmCRMB6rRnfdfuPikrjwtl2YmRZU2qt2\n" +
            "vRuC4D9Jcf4Iav4jEPr9vUFxu/RFHR8Dj2+lGtw6x8u3A1ghA8ScMMXb6cE/eVZM\n" +
            "EfKIZ0oRKRY3BRE2NCkGQGKDkbZNEIFvTZUEHlIAqFA/wwIDAQABo34wfDAVBgNV\n" +
            "HSAEDjAMMAoGCGCEQgEQAQUBMA4GA1UdDwEB/wQEAwIGwDATBgNVHSUEDDAKBggr\n" +
            "BgEFBQcDCTAfBgNVHSMEGDAWgBTTRlcrd9Ji72vMM8ccXH4zlSqiHjAdBgNVHQ4E\n" +
            "FgQUY3UiXf2widDtqXsXYHHgDQgOWKswDQYJKoZIhvcNAQELBQADggIBADMKCakb\n" +
            "1HyphTS/UzZcOoo116pdnfT2FfiJUefEMJ5+GEHp0NyRcSJK+YJf5PhaRNbVXL2j\n" +
            "q9IBOI+gC8zehwP4v2//flWFcqDlf5w7wl5SAEroFUZBpMPtZmUoNIt9mwZTYjwq\n" +
            "RSfK9+K1P1KhQqTlIzcLGwABxGHMx1UsadYtDniLthf3TbQ2pYKqfTlukLOWT7w9\n" +
            "n+cSPF3HURZj8dsggxRykrCLietyxLHAAlns/LJKpNKQPs4oZfJxfx5b50bNNwJM\n" +
            "MgHck18JlB/U29agxqYQZxJXcR6DZ4BG1zh08dOJh01//DWXg7iYKFiI1XyfD2rg\n" +
            "cxcaY/J92s7FyN0SsArsG2hPQSPIncA60Hl0pYICDMSxSsyQzapgSMKVfdFsB+nt\n" +
            "WHhzAHt+ZYuJnASTPwF/8wnR4UPz6azCNIcyxBROLJimNKWXSk4FL2TDGxMrSa8U\n" +
            "GDSvJHTevpn+47J9EX+eUIyO03PJz6ibsa0jgmW3PAUkLh3Q4vrvWbHW9Cdl4TiA\n" +
            "KEYd1OM4etUgUpf+1fNwukUhU5wbGKtTOa8CjtStbH52JkjI8/ci8wtBCUJ8M+Lv\n" +
            "azvX2YkNoq0tyzkrd94xUiSLjgXeRWVHieeD963jBbUQI5o4bxfWwqec3VBep+oS\n" +
            "1VGZY00GXWHKSCU9weyzWVqrl0S5Kc8wqmhg\n" +
            END_CERTIFICATE;

    private static final String BANKID_ROOT_CERTIFICATE_PREPROD = BEGIN_CERTIFICATE
                    + "MIIF2jCCA8KgAwIBAgIBZDANBgkqhkiG9w0BAQsFADBxMQswCQYDVQQGEwJOTzEq\n"
                    + "MCgGA1UECgwhVEVTVCAtIEZOSCBvZyBTcGFyZWJhbmtmb3JlbmluZ2VuMRYwFAYD\n"
                    + "VQQLDA1URVNUIC0gQmFua0lEMR4wHAYDVQQDDBVURVNUIC0gQmFua0lEIFJvb3Qg\n"
                    + "Q0EwHhcNMDkwMzA2MDkyNDMyWhcNMzUwMzA2MDkyNDMyWjBxMQswCQYDVQQGEwJO\n"
                    + "TzEqMCgGA1UECgwhVEVTVCAtIEZOSCBvZyBTcGFyZWJhbmtmb3JlbmluZ2VuMRYw\n"
                    + "FAYDVQQLDA1URVNUIC0gQmFua0lEMR4wHAYDVQQDDBVURVNUIC0gQmFua0lEIFJv\n"
                    + "b3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDCUuJ/b5kyoxlm\n"
                    + "El5auQFvHgwWHq4fqmIde2pslLvHfUFHCptXK/DS0zCVfjZfmIipX7x2dmy1zgbe\n"
                    + "Agp23lWK6LjUuIXC7zAduY9KRCBot8qfUGgPvTh79KC20lMxNEcejiwZQcjgZVxa\n"
                    + "2qLnDD0O9tiNqs6+jTOHViSNu0JsIAmDmJuLBaGK/JrvxzlFLQA+Y4hKFiH8X3al\n"
                    + "f/Rtt23fEVg6VqDJII9+djYfAs4kb8T5ClaDYG7cq0ikCEV8lxGyVs5bM4gUSPtN\n"
                    + "fawMX7GXt6mcyEG+JETP599N+G+3mvfV3zRnpuewvYkJXiGpqnhW0qKoipymEXZa\n"
                    + "STtyLu7FA//wQBMYPJL0uOcBEacmMAqzABEmRz7fQDsiegiHbgQrtMci7XQEwJqJ\n"
                    + "B9HqbWD56p6fnfNpFnp93jFJaF+WP8yhKGoi43ESLuZzmjx7+N2f41YIypneW5wR\n"
                    + "qE7zA4W+r94IensmsOXs1t970AJPs0EtYNCBpJGepyW30HieGt744/3+CFy4ZIEB\n"
                    + "UeBJDcRP+rI5r02SpCAsFjs159oWJsHmpGJJL42/VlMvVlOTIzvJHsO0wvSVn79n\n"
                    + "6bbDvUNZKQ2wZTI2Rdzb1/5QL9ETvOGaMjTqg+PGPZDCflXfhat2wlxEysBmBcNU\n"
                    + "Lo0cjUoayf3SUlt1G1vRHo4XdwqzUQIDAQABo30wezASBgNVHRMBAf8ECDAGAQH/\n"
                    + "AgEBMBUGA1UdIAQOMAwwCgYIYIRCARABBAEwDgYDVR0PAQH/BAQDAgEGMB8GA1Ud\n"
                    + "IwQYMBaAFNNGVyt30mLva8wzxxxcfjOVKqIeMB0GA1UdDgQWBBTTRlcrd9Ji72vM\n"
                    + "M8ccXH4zlSqiHjANBgkqhkiG9w0BAQsFAAOCAgEAeaNiZw3Hsb8sGWGh+q2vFQ4J\n"
                    + "rTu+ITmKMNgwb51DgbUAblypmJguTrcoGxQtuyr/GEiGxLhygXJhKqxufTpKJN2q\n"
                    + "OPdTklquw/adwRSfV7qpEY9C1w0vXl9NaKEbhRhivW3Wcd8VRWO6hjWA9oiReQnO\n"
                    + "DuL5n964VCbsRbn/4NwwsQKYIjGvP5aOdX+9yL6SNAbUOL6UCo81xs0zFEr0RwZ0\n"
                    + "Z1syNVMVNuAzQ0va2SR+H3dCpbgvRyIYLvyooM+f8cPM+rtgFGwAV2paYbXXUAV1\n"
                    + "QCa7oDXkvFYGc4L2BH97+TVx80/RHgrkWoh4neFKg+1qQhDrlfSGcrkNMvmCQr4Z\n"
                    + "G1qATYNEEpQKyL1YhZaF1V6lHOu/VvmUU+hi0PZ0BOqm0m9j40h97PDfkOWJOsBp\n"
                    + "j81++wIh5UWVPjOgzKW1K2r0uyL0YVQOa0eHSM+bgh8JgFOxiz52c1Qg2KXB0fMT\n"
                    + "/BuMf8KgFA+xZloFn2lZzAJZe1DuvdocpC0dnzsJvxUzba1jnihsoPfJWgVy3YCh\n"
                    + "ElH1147yPdu++SF5wrhMqBRZFcEw3iK39db5ZsFnttVmJUPXSekG+FarEbW18/4j\n"
                    + "Aq6SfMgz6vjL3NKuij+7FrdMR83fo21NaEbf4DS8zRNny6Miad9ZkpepOvglrLDk\n"
                    + "aMOySxzSiW4ogm4PkwE=\n"
                    + END_CERTIFICATE;

    private static final CertificateFactory CERTIFICATE_FACTORY;

    private static final Path RESOURCES_PATH;

    static {

        try {
            RESOURCES_PATH = Paths.get(OcspChecker.class.getResource("/").toURI());
        } catch (URISyntaxException e) {
            throw new RuntimeException("Failed to resolve resources path", e);
        }

        // Use BouncyCastle as crypto provider.
        Security.addProvider(new BouncyCastleProvider());

        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to initialize certificate factory", e);
        }

        // Activate OCSP.
        Security.setProperty("ocsp.enable", "true");
        Security.setProperty("ocsp.responderCertSubjectName", // TODO: kan hentes fra OcspChecker, merk at dette er en global setting.
                "CN=TEST BankID Nets VA1, OU=TEST eSecurity, O=TEST Nets AS, C=NO");

        // Activate CRL Distribution Points Extension.
        System.setProperty("com.sun.security.enableCRLDP", "true");

        // Set SSL trust store.
        String trustStorePath = RESOURCES_PATH.resolve("trust-va-preprod1.no.jks").toString();
        if (!Files.exists(Paths.get(trustStorePath))) {
            throw new RuntimeException("Failed to find trust store");
        }
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }


    /**
     * Run with -Djava.security.debug="certpath ocsp" to debug.
     * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html for all options.
     *
     * @param args unused
     * @throws Exception when fail
     */
    public static void main(String args[]) throws Exception {
//        CertPath certificatePath;
//        String keyStoreOrP7Filename = RESOURCES_PATH.resolve("www.kantega.no-BINAS-auth.p7").toString();
//        try (InputStream p7FileInputStream = Files.newInputStream(Paths.get(keyStoreOrP7Filename))) {
//            certificatePath = CERTIFICATE_FACTORY.generateCertPath(p7FileInputStream, "PKCS7");
//        }


        // instantiate a KeyStore with type JKS
        KeyStore ks = KeyStore.getInstance("JKS");
        // load the contents of the KeyStore
        final String keyStoreOrP7Filename = RESOURCES_PATH.resolve("www.kantega.no-auth.jks").toString();
        final char[] password = "changeit".toCharArray();
        ks.load(Files.newInputStream(Paths.get(keyStoreOrP7Filename)), password);
        // fetch certificate chain stored with alias "auth"
        Certificate[] certArray = ks.getCertificateChain("auth");
        // convert chain to a List
        List certList = Arrays.asList(certArray);
        // extract the certification path from
        // the List of Certificates
        CertPath certificatePath = CERTIFICATE_FACTORY.generateCertPath(certList);
        PrivateKey authKey = (PrivateKey) ks.getKey("auth", password);

        Set<TrustAnchor> anchors = generateTrustAnchors();
        PKIXParameters params = new PKIXParameters(anchors);

        // Activate certificate revocation checking
        params.setRevocationEnabled(true);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) validator.getRevocationChecker();
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

        final OcspRequester ocspRequester = new OcspRequester();
        final X509Certificate issuer = (X509Certificate) certificatePath.getCertificates().get(1);
        final X509Certificate certTBV = (X509Certificate) certificatePath.getCertificates().get(0);
        final OcspRequester.OCSPResponseHolder ocspResponseHolder = ocspRequester.sendOcspRequestGetResponse(certTBV, issuer, certificatePath.getCertificates(), Optional.of(authKey) ); // TODO: NETS VA anchor kan lages herfra (unsafe !!)
        final Map<X509Certificate, byte[]> responses = new HashMap<>();
        responses.put(certTBV, ocspResponseHolder.rawOcspResponse);
        revocationChecker.setOcspResponses(responses);

        params.addCertPathChecker(revocationChecker); // TODO: her maa vi inn med en annen revocationChecker
        try {
            System.out.println("Checking status for certificates in " + keyStoreOrP7Filename);
            validator.validate(certificatePath, params);
            System.out.print("OK");

        } catch (CertPathValidatorException e) {
            e.printStackTrace();
            X509Certificate certificate = (X509Certificate) e.getCertPath().getCertificates().get(e.getIndex());
            String commonName = getSubjectDNElement(certificate, "CN");
            System.out.println(commonName + ": " + e.getReason());
        }
    }

    private static String getSubjectDNElement(X509Certificate x509Certificate, String elementName) {
        String rfc1779SubjectName = x509Certificate.getSubjectX500Principal().getName("RFC1779");
        for (String namesAndValues : rfc1779SubjectName.split(",")) {
            String[] nameAndValue = namesAndValues.split("=");
            if (nameAndValue[0].trim().equals(elementName)) {
                return nameAndValue[1];
            }
        }
        return "<not found>";
    }

    private static Set<TrustAnchor> generateTrustAnchors() throws CertificateException {

        ByteArrayInputStream bankIDRootStream = new ByteArrayInputStream(BANKID_ROOT_CERTIFICATE_PREPROD.getBytes());
        Certificate bankIDRootCert = CERTIFICATE_FACTORY.generateCertificate(bankIDRootStream);
        TrustAnchor bankIDRootAnchor = new TrustAnchor((X509Certificate) bankIDRootCert, null);

        ByteArrayInputStream netVAStream = new ByteArrayInputStream(NETS_VA_CERTIFICATE_PREPROD.getBytes());
        Certificate netsVACert = CERTIFICATE_FACTORY.generateCertificate(netVAStream);
        TrustAnchor netsVAAnchor = new TrustAnchor((X509Certificate) netsVACert, null);

        Set<TrustAnchor> list = new HashSet<>();
        list.add(bankIDRootAnchor);
        list.add(netsVAAnchor);

        return list;
    }
}
