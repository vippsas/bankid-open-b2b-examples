package no.bankid.openb2b;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class SecurityProvider {

    static final CertificateFactory CERTIFICATE_FACTORY;

    static {

        Security.addProvider(new BouncyCastleProvider());

        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static List<X509CertificateHolder> toCertificateHolders(List<? extends Certificate> signerChain) {
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

    static ASN1EncodableVector toASN1EncodableVector(ASN1Encodable... elements) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (ASN1Encodable x : elements) {
            vector.add(x);
        }
        return vector;
    }
}
