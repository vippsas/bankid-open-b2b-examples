#!/usr/bin/env bash

source 0_set_environment_variables.sh

# Convert PKCS#7 to PEM encoded certificates.
${OPENSSL_HOME}/openssl pkcs7 \
                        -print_certs \
                        -in "${AUTH_PKCS7}" \
                        -out "${AUTH_CER}"

${OPENSSL_HOME}/openssl pkcs7 \
                        -print_certs \
                        -in "${SIGN_PKCS7}" \
                        -out "${SIGN_CER}"

# Convert PEM encoded Certificate and private key to PKCS#12.
${OPENSSL_HOME}/openssl pkcs12 \
                        -export \
                        -in "${AUTH_CER}" \
                        -inkey "${AUTH_KEY}" \
                        -passin "pass:${KEY_PASSWORD}" \
                        -out "${AUTH_PKCS12}" \
                        -passout "pass:${KEY_PASSWORD}"

${OPENSSL_HOME}/openssl pkcs12 \
                        -export \
                        -in "${SIGN_CER}" \
                        -inkey "${SIGN_KEY}" \
                        -passin "pass:${KEY_PASSWORD}" \
                        -out "${SIGN_PKCS12}" \
                        -passout "pass:${KEY_PASSWORD}"
