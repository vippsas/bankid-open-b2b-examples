package no.bankid.openb2b;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;

import static no.bankid.openb2b.SecurityProvider.CERTIFICATE_FACTORY;

/**
 * Run with -Djava.security.debug="certpath ocsp" to debug.
 * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html for all options.
 */
public class ReceiverVerifiesBankIDStatusIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReceiverVerifiesBankIDStatusIT.class);

    // Provided to toggle between PREPROD/PROD.
    private final BankIDEnvironment env = BankIDEnvironment.PREPROD;

    private final MerchantA merchantA = new MerchantA();
    private final MerchantB merchantB = new MerchantB();
    private static final byte[] DTBS = "Hello World".getBytes(StandardCharsets.UTF_8);


    @Test
    public void happyDayScenario() throws Exception {

        OcspResponderSslTrust.init(env);

        // Given: Merchant A signs data and creates a detached signature, without OCSP check.
        CertPath senderCertPath = CERTIFICATE_FACTORY.generateCertPath(merchantA.getCertList());
        OCSPResponse ocspResponse = null;
        byte[] detachedSignature = Signer.sign(DTBS, senderCertPath, merchantA.getPrivateKey(), ocspResponse);


        // When: Merchant A sends data and detached signature to Merchant B over the wire (not shown here).
        LOGGER.info("Merchant A sends data and detached signature (without OCSP check) to Merchant B.");


        // Then: Merchant B verifies received data with detached signature.
        BankIDStatusChecker bankIDStatusChecker =
                new BankIDStatusChecker(env, merchantB.getPrivateKey(), merchantB.getCertList());
        boolean signatureVerified =
                Verifier.verifyDetachedSignature(env.getBankIDRootCert(), DTBS, detachedSignature, bankIDStatusChecker);


        Assert.assertTrue(signatureVerified);
    }
}
