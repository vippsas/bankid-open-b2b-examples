package no.bankid.openb2b;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SomeUtils {
    static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
    static final String END_CERTIFICATE = "-----END CERTIFICATE-----\n";
    static final String BANKID_ROOT_CERTIFICATE_PREPROD = BEGIN_CERTIFICATE
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
    static final String NETS_VA_OCSP_RESPONDER_CERTIFICATE_PREPROD = BEGIN_CERTIFICATE +
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

    static final CertificateFactory CERTIFICATE_FACTORY;
    static final Path RESOURCES_PATH;

    static {
        // Use BouncyCastle as an additional crypto provider.
        Security.addProvider(new BouncyCastleProvider());
        try {
            RESOURCES_PATH = Paths.get(OcspChecker.class.getResource("/").toURI());
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509", "BC");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        // Set SSL trust store used for SSL communication with the preprod VA, // TODO: lag tilsvarenende fil for va1.bankid.no eller kombiner begge i en
        String trustStorePath = SomeUtils.RESOURCES_PATH.resolve("trust-va-preprod1.no.jks").toString();
        if (!Files.exists(Paths.get(trustStorePath))) {
            throw new RuntimeException("Failed to find trust store");
        }
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }


    public static List<X509CertificateHolder> toCertificateHolder(List<? extends Certificate> signerChain) {
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

    public static X509CertificateHolder toCertificateHolder(Certificate c) {
        try {
            return new JcaX509CertificateHolder((X509Certificate) c);
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static String getSubjectDNElement(X509Certificate x509Certificate, String elementName) {
        String rfc1779SubjectName = x509Certificate.getSubjectX500Principal().getName("RFC1779");
        for (String namesAndValues : rfc1779SubjectName.split(",")) {
            String[] nameAndValue = namesAndValues.split("=");
            if (nameAndValue[0].trim().equals(elementName)) {
                return nameAndValue[1];
            }
        }
        return "<not found>";
    }
    /**
     * Return a boolean array representing passed in keyUsage mask.
     *
     * @param mask keyUsage mask.
     */
    public static boolean[] getKeyUsage(int mask)
    {
        byte[] bytes = new byte[] { (byte)(mask & 0xff), (byte)((mask & 0xff00) >> 8) };
        boolean[] keyUsage = new boolean[9];

        for (int i = 0; i != 9; i++)
        {
            keyUsage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
        }

        return keyUsage;
    }
    /**
     * Build a path using the given root as the trust anchor, and the passed
     * in end constraints and certificate store.
     * <p>
     * Note: the path is built with revocation checking turned off.
     */
    public static PKIXCertPathBuilderResult buildPath(
            X509Certificate  rootCert,
            X509CertSelector endConstraints,
            CertStore certsAndCRLs)
            throws Exception
    {
        CertPathBuilder       builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);

        buildParams.addCertStore(certsAndCRLs);
        buildParams.setRevocationEnabled(false);

        return (PKIXCertPathBuilderResult)builder.build(buildParams);
    }
}
