package no.bankid.openb2b;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Optional;

import static no.bankid.openb2b.BankIDStatus.NOT_VERIFIED;
import static no.bankid.openb2b.BankIDStatus.VERIFIED_OFFLINE;
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

    @Rule
    public final TestName testName = new TestName();

    @Before
    public void logNewline() {
        LOGGER.info("\n{}", testName.getMethodName());
    }

    @Test
    public void happyDayScenario() throws Exception {

        OcspResponderSslTrust.init(env);

        // Given: Merchant A signs data and creates a detached signature, with OCSP check embedded.
        List<Certificate> senderCertList = merchantA.getCertList();
        CertPath senderCertPath = CERTIFICATE_FACTORY.generateCertPath(senderCertList);
        PrivateKey senderSignKey = merchantA.getPrivateKey();
        BankIDStatusChecker statusCheckerA = new BankIDStatusChecker(env, senderSignKey, senderCertList);
        OcspResponse ocspResponse = statusCheckerA.fetchOcspResponse(senderCertPath);
        byte[] detachedSignature = Signer.sign(DTBS, senderCertPath, senderSignKey, ocspResponse);


        // When: Merchant A sends data and detached signature to Merchant B over the wire (not shown here).
        LOGGER.info("Merchant A sends data and detached signature (with embedded OCSP check) to Merchant B.");


        // Then: Merchant B verifies received data with detached signature.
        Optional<VerifiedSignature> verifiedSignature =
                Verifier.verifyDetachedSignature(env.getBankIDRoot(), DTBS, detachedSignature);
        Assert.assertTrue(verifiedSignature.isPresent());
        BankIDStatusChecker statusCheckerB =
                new BankIDStatusChecker(env, merchantB.getPrivateKey(), merchantB.getCertList());
        BankIDStatus bankIdStatusOk = statusCheckerB.checkOffline(verifiedSignature.get());
        Assert.assertEquals(VERIFIED_OFFLINE, bankIdStatusOk);
    }

    @Test
    public void bankIDStatusCheckFailsIfSenderHasNotCheckedStatus() throws Exception {

        OcspResponderSslTrust.init(env);

        // Given: Merchant A signs data and creates a detached signature, without OCSP check.
        CertPath senderCertPath = CERTIFICATE_FACTORY.generateCertPath(merchantA.getCertList());
        byte[] detachedSignature = Signer.sign(DTBS, senderCertPath, merchantA.getPrivateKey(), OcspResponse.empty());


        // When: Merchant A sends data and detached signature to Merchant B over the wire (not shown here).
        LOGGER.info("Merchant A sends data and detached signature (without OCSP check) to Merchant B.");


        // Then: Merchant B verifies received data with detached signature.
        Optional<VerifiedSignature> verifiedSignature =
                Verifier.verifyDetachedSignature(env.getBankIDRoot(), DTBS, detachedSignature);
        Assert.assertTrue(verifiedSignature.isPresent());
        BankIDStatusChecker statusChecker =
                new BankIDStatusChecker(env, merchantB.getPrivateKey(), merchantB.getCertList());
        BankIDStatus bankIdStatus = statusChecker.checkOffline(verifiedSignature.get());
        Assert.assertEquals(NOT_VERIFIED, bankIdStatus);
    }

}
