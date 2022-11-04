#!/usr/bin/env bash

source 0_set_environment_variables.sh

echo
echo "Activate merchant BankID by submitting the certificate signing requests (${AUTH_CSR} and ${SIGN_CSR}) to SkyMAT:"
echo
echo "    PREPROD: https://tools-preprod.bankid.no/skymat/b2b-activation-ui"
echo "    PROD:    https://tools.bankid.no/skymat/b2b-activation-ui"
echo
echo "Place the resulting .p7-files in this directory."
