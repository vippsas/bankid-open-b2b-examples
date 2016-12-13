package no.bankid.openb2b;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.util.List;

import static java.util.Arrays.asList;
import static no.bankid.openb2b.SecurityProvider.CERTIFICATE_FACTORY;

/**
 * Run with -Djava.security.debug="certpath ocsp" to debug.
 * See https://docs.oracle.com/javase/8/docs/technotes/guides/security/troubleshooting-security.html for all options.
 */
public class SenderVerifiesBankIDStatusIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(SenderVerifiesBankIDStatusIT.class);

    // Provided to toggle between PREPROD/PROD.
    private final BankIDEnvironment env = BankIDEnvironment.PREPROD;

    private static final byte[] DTBS = "Hello World".getBytes(StandardCharsets.UTF_8);


    @Test
    public void happyDayScenario() throws Exception {

        OcspResponderSslTrust.init(env);

        // Given: Merchant A signs data and creates a detached signature, with OCSP check embedded.
        KeyStore senderKeystore = KeyStore.getInstance("JKS");
        senderKeystore.load(MerchantA.KEYSTORE_URL.openStream(), MerchantA.KEYSTORE_PASSWORD);
        List<Certificate> senderCertList = asList(senderKeystore.getCertificateChain(MerchantA.KEY_ALIAS));
        CertPath senderCertPath = CERTIFICATE_FACTORY.generateCertPath(senderCertList);
        PrivateKey senderSignKey = (PrivateKey) senderKeystore.getKey(MerchantA.KEY_ALIAS, MerchantA.KEY_PASSWORD);
        BankIDStatusChecker senderBankIDStatusChecker = new BankIDStatusChecker(env, senderSignKey, senderCertList);

        byte[] detachedSignature =
                Signer.signWithValidatedOCSPResponse(DTBS, senderCertPath, senderSignKey, senderBankIDStatusChecker);


        // When: Merchant A sends data and detached signature to Merchant B over the wire (not shown here).
        LOGGER.info("Merchant A sends data and detached signature (with embedded OCSP check) to Merchant B.");


        // Then: Merchant B verifies received data with detached signature.
        KeyStore receiverKeystore = KeyStore.getInstance("JKS");
        receiverKeystore.load(MerchantB.KEYSTORE_URL.openStream(), MerchantB.KEYSTORE_PASSWORD);
        List<Certificate> receiverCertList = asList(receiverKeystore.getCertificateChain(MerchantB.KEY_ALIAS));
        PrivateKey receiverSignKey = (PrivateKey) receiverKeystore.getKey(MerchantB.KEY_ALIAS, MerchantB.KEY_PASSWORD);

        BankIDStatusChecker receiverBankIDStatusChecker = new BankIDStatusChecker(env, receiverSignKey, receiverCertList);
        boolean signatureVerified =
                Verifier.verifyDetachedSignature(env.getBankIDRootCert(), DTBS, detachedSignature, receiverBankIDStatusChecker);


        Assert.assertTrue(signatureVerified);
    }

}
