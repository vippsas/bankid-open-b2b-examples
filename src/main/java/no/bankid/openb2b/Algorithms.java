package no.bankid.openb2b;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public enum Algorithms { // Name of this enum may be used as is.

    SHA512(new DefaultDigestAlgorithmIdentifierFinder().find("SHA512")),
    SHA512withRSA(new DefaultSignatureAlgorithmIdentifierFinder().find("SHA512withRSA")),
    RSA(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption));

    private final AlgorithmIdentifier algorithmIdentifier;

    Algorithms(AlgorithmIdentifier algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public AlgorithmIdentifier asId() {
        return algorithmIdentifier;
    }
}
