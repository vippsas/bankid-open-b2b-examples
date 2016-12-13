package no.bankid.openb2b;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class OcspResponderCertPreprod {

    static final String OCSP_RESPONDER_CERTIFICATE_PREPROD =
            "-----BEGIN CERTIFICATE-----\n" +
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
                    "-----END CERTIFICATE-----\n";

    static InputStream getInputStream() {
        return new ByteArrayInputStream(OCSP_RESPONDER_CERTIFICATE_PREPROD.getBytes());
    }
}
