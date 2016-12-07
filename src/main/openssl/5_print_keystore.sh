#!/usr/bin/env bash

source 0_set_environment_variables.sh

${OPENSSL_HOME}/openssl pkcs12 \
                        -in "${AUTH_PKCS12}" \
                        -info \
                        -noout \
                        -passin "pass:${KEY_PASSWORD}"

${OPENSSL_HOME}/openssl pkcs12 \
                        -in "${SIGN_PKCS12}" \
                        -info \
                        -noout \
                        -passin "pass:${KEY_PASSWORD}"
