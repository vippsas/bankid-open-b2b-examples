#!/usr/bin/env bash

JAVA_HOME="set_path_to_your_java_bin_directory"

# Change if the merchant's originator is not BINAS.
ORIGINATOR="BINAS"

# Change to actual common name.
COMMON_NAME="Merchant A"

KEY_STORE="${COMMON_NAME}.jks"
AUTH_CSR="${COMMON_NAME}-auth.csr"
SIGN_CSR="${COMMON_NAME}-sign.csr"
AUTH_PKCS7="${COMMON_NAME}-${ORIGINATOR}-auth.p7"
SIGN_PKCS7="${COMMON_NAME}-${ORIGINATOR}-sign.p7"

# This password is used for authentication/signing with the BankID and must be protected!
STORE_PASSWORD="changeit"
