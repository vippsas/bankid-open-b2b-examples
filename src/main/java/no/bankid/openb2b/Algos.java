package no.bankid.openb2b;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

public enum Algos { // Name of this enum may be used as is.

    SHA256(new DefaultDigestAlgorithmIdentifierFinder().find("SHA256")),
    SHA256withRSA(new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")),
    RSA(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption));

    private final AlgorithmIdentifier algorithmIdentifier;

    Algos(AlgorithmIdentifier algorithmIdentifier) {

        this.algorithmIdentifier = algorithmIdentifier;
    }

    public AlgorithmIdentifier asId() {
        return algorithmIdentifier;
    }
}
