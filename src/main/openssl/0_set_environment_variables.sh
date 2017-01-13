#!/usr/bin/env bash

OPENSSL_HOME="/usr/bin"

# Change if the merchant's originator is not BINAS.
ORIGINATOR="BINAS"

# Change to actual common name.
COMMON_NAME="Merchant B"

AUTH_KEY="${COMMON_NAME}-auth.pem"
SIGN_KEY="${COMMON_NAME}-sign.pem"
AUTH_CSR="${COMMON_NAME}-auth.csr"
SIGN_CSR="${COMMON_NAME}-sign.csr"
AUTH_PKCS7="${COMMON_NAME}-${ORIGINATOR}-auth.p7"
SIGN_PKCS7="${COMMON_NAME}-${ORIGINATOR}-sign.p7"
AUTH_CER="${COMMON_NAME}-${ORIGINATOR}-auth.cer"
SIGN_CER="${COMMON_NAME}-${ORIGINATOR}-sign.cer"
AUTH_PKCS12="${COMMON_NAME}-${ORIGINATOR}-auth.p12"
SIGN_PKCS12="${COMMON_NAME}-${ORIGINATOR}-sign.p12"

# This password is used for authentication/signing with the BankID and must be protected!
KEY_PASSWORD="changeit"
