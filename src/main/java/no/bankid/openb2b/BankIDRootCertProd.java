package no.bankid.openb2b;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

class BankIDRootCertProd {

    private static final String BANKID_ROOT_CERTIFICATE_PROD =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFsDCCA5igAwIBAgIBZDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJOTzEj\n" +
                    "MCEGA1UECgwaRk5IIG9nIFNwYXJlYmFua2ZvcmVuaW5nZW4xDzANBgNVBAsMBkJh\n" +
                    "bmtJRDEXMBUGA1UEAwwOQmFua0lEIFJvb3QgQ0EwHhcNMDkwNDI4MTY0NTQ5WhcN\n" +
                    "MzUwNDI4MTY0NTQ5WjBcMQswCQYDVQQGEwJOTzEjMCEGA1UECgwaRk5IIG9nIFNw\n" +
                    "YXJlYmFua2ZvcmVuaW5nZW4xDzANBgNVBAsMBkJhbmtJRDEXMBUGA1UEAwwOQmFu\n" +
                    "a0lEIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCHrO2o\n" +
                    "OJgH1XL6AF5BSTUwgZcMLaqsRzhWqWAFXgQZJliauDaGER4COVpEpk11mQBlk6AU\n" +
                    "EbTyeCJ9yl+Qfhw8zTv00/ZN6420y+e0Id3yX+kROIXj0f7+PQaOAv1d7GEYAPe3\n" +
                    "UaSk/unwyz2XWnPSHl4PUoxa3nqrJlhhhcVX5hJMxM9b8D3RsVhbY/XGPXe/wM2A\n" +
                    "bM3DRZjEkY/Bj1uAsphIzy8GroqDnsJ2OfhpiOvPSgR7Rv4ULf8YdzqRvn+j3awi\n" +
                    "fDVru1oMq5sVT2pO2iG9+vcuAEt6I6rdcGVNRSQc72o+Sj1MtnNI44CFSGVoluyu\n" +
                    "CvlNorHY4I0UuW+lndGy5t/icMeG2K4Wx5qfTLCIBqNMe3zQwtGuXa2hlRjFCuR/\n" +
                    "UwOQV9a6NPKV7tnYXAV28FDqCLrfFzsHIdNtvoIUPYNQCUOukMEZlhO7B84vycI3\n" +
                    "DWBeiz7Ri/+R3fj4iD7/ySPqHqhAyyL4QfBc/OiP/lGWMBUPx7FK52k1PID3yhb7\n" +
                    "ZZAKLcnKn2Ok755fCMw3/SAlBAJwfuii8nwCOazYpJeIEuWVyZVttZpfDnw5IgoL\n" +
                    "DOGkopJfRAWaUdtlsuysGAOl/rZn02DnIcsIBwbC/Z+zpRr/c+Wa0h7PF1oTFpJ2\n" +
                    "uqDNv4zHXmGLcf6RTBJAmxMG/hH2n0cm0CJEvQIDAQABo30wezASBgNVHRMBAf8E\n" +
                    "CDAGAQH/AgEBMBUGA1UdIAQOMAwwCgYIYIRCARABBAEwDgYDVR0PAQH/BAQDAgEG\n" +
                    "MB8GA1UdIwQYMBaAFKBudPUx8LAUfeJ/P6bEfG/ZhGlcMB0GA1UdDgQWBBSgbnT1\n" +
                    "MfCwFH3ifz+mxHxv2YRpXDANBgkqhkiG9w0BAQsFAAOCAgEAZWrD+ZSuHskrIFCV\n" +
                    "T30RJwl73L38VF5RB++h4fBbujCswtEUM51VEK16/8tjZgp6dKpOp2MqIDGg2W87\n" +
                    "fBOI/7xR39RE+v92K5i6PRXhmnz97iPQUGqF6POyhDyuSIimrJnjw1WMd7LI1+FT\n" +
                    "3e/wdHV/WDTM5g0DV07McMGt29Ls4q/BDZtaXVUVI+SnpWtbBMHvCOt0JWjIcm4T\n" +
                    "6UG1WB9jeTYq5k4ikrwNUIbEwP2mtmPE30qYL/6DNFNMDLVziJhX5gjn+nMHwPBl\n" +
                    "biYbgMp47X5A79mfPLoQB0dZ82qAM8QqorVn88Y7IINOjR1Qvd0IWIiswEj2aVWf\n" +
                    "VSRZ20Zu/QTew4+sr1uIRqt2hs0+HIYr8ozNDbYh4Y/bu6BV6XYg1MTtto8lANPc\n" +
                    "mM9IXaDaDSZ79WPKxm4ltJC6bSYYRqbg8arVSQR4XwSt2bWyKJuiLg6i6wj4Msin\n" +
                    "l+toLDBezQWH9UcG3fB/rut5YTy10n03+m4l7nT/jDeLIZzRPdjnklUX/741FWK9\n" +
                    "27cra/wwZdgxRKA6oxHh2SpplgAtkeVZVe9bxKak1UGokOoPSOtaRzAf0UIpDQoh\n" +
                    "Euqk6ZRC2kMBrucGigaxJwLtbmlJeh9VG6eI/Ekzkhg/wu2+SNmdRF1dGZf1GA+x\n" +
                    "SEZSLzDXpRxX/9RbZ5VsPM3QF00=\n"
                    + "-----END CERTIFICATE-----\n";

    static InputStream getInputStream() {
        return new ByteArrayInputStream(BANKID_ROOT_CERTIFICATE_PROD.getBytes());
    }
}
