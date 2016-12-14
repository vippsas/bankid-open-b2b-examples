package no.bankid.openb2b;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.List;

import static no.bankid.openb2b.SecurityProvider.CERTIFICATE_FACTORY;

/**
 * Run with -Djava.security.debug="certpath ocsp" to debug.
 * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html for all options.
 */
public class SenderVerifiesBankIDStatusIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SenderVerifiesBankIDStatusIT.class);

    // Provided to toggle between PREPROD/PROD.
    private final BankIDEnvironment env = BankIDEnvironment.PREPROD;

    private final MerchantA merchantA = new MerchantA();
    private final MerchantB merchantB = new MerchantB();
    private static final byte[] DTBS = "Hello World".getBytes(StandardCharsets.UTF_8);


    @Test
    public void happyDayScenario() throws Exception {

        OcspResponderSslTrust.init(env);

        // Given: Merchant A signs data and creates a detached signature, with OCSP check embedded.
        List<Certificate> senderCertList = merchantA.getCertList();
        CertPath senderCertPath = CERTIFICATE_FACTORY.generateCertPath(senderCertList);
        PrivateKey senderSignKey = merchantA.getPrivateKey();
        BankIDStatusChecker senderBankIDStatusChecker = new BankIDStatusChecker(env, senderSignKey, senderCertList);
        byte[] ocspResponseBytes = senderBankIDStatusChecker.validateCertPathAndOcspResponseOnline(senderCertPath);
        OCSPResponse ocspResponse = OCSPResponse.getInstance(ocspResponseBytes);
        byte[] detachedSignature = Signer.sign(DTBS, senderCertPath, senderSignKey, ocspResponse);


        // When: Merchant A sends data and detached signature to Merchant B over the wire (not shown here).
        LOGGER.info("Merchant A sends data and detached signature (with embedded OCSP check) to Merchant B.");


        // Then: Merchant B verifies received data with detached signature.
        BankIDStatusChecker receiverBankIDStatusChecker =
                new BankIDStatusChecker(env, merchantB.getPrivateKey(), merchantB.getCertList());
        boolean signatureVerified =
                Verifier.verifyDetachedSignature(env.getBankIDRootCert(), DTBS, detachedSignature,
                        receiverBankIDStatusChecker);


        Assert.assertTrue(signatureVerified);
    }

}
