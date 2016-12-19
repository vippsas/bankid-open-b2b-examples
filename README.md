# BankID Open B2B Examples

This repository contains code examples for [BankID Open B2B](https://confluence.bankidnorge.no/confluence/display/DEVPUB/BankID+Open+B2B).

## Disclaimer
The code in this repository is provided as _examples_ for using BankID Open B2B. The code is not accurate or complete enough for banks, merchants, partners or vendors to rely on without further amendment. BankID Norge is not responsible for any errors or omissions.

## Requirement: Unlimited Strength Java Cryptography Extension Policy Files
Due to export control restrictions in the US, the version of JCE policy files that are bundled in the J2SDK environment allow "strong" but limited cryptography to be used.

The communication between a merchant and the BankID VA uses AES encryption with 256 bits keysize. Therefore the Unlimited Strength Java(TM) Cryptography Extension Policy Files need to be downloaded and installed to be able to run the Java example code. Download from: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html. You will find installation instructions in the downloaded .zip-file.

## Organization of example code
                                LOCATION                CONTENT DESCRIPTION

    Lifecycle tools:            src/main/keytool        Java keytool examples
     (i.e. how to create a      src/main/openssl        OpenSSL examples
      Java keystore for an
      Open B2B BankID)

    Usage examples:             src/main/java           Java code
     (i.e. how to sign and
      validate with an
      Open B2B BankID)

    Usage scenarios:            src/test/java           Java code
     (in the form of            src/test/resources      Java keystores for example merchants and VA trust.
      integration tests)                                Logback configuration.

Also see documentation for [Java keytool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html), [OpenSSL](https://www.openssl.org/) and [Java PKI Programmer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html).

**TIP!** A good starting point for getting familiar with the code is the integration tests, which implements the usage scenarios.