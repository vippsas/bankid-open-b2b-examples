#!/usr/bin/env bash

source 0_set_environment_variables.sh

${OPENSSL_HOME}/openssl genrsa \
                        -out "${AUTH_KEY}" \
                        -passout "pass:${KEY_PASSWORD}" \
                        -aes256 \
                        2048

${OPENSSL_HOME}/openssl genrsa \
                        -out "${SIGN_KEY}" \
                        -passout "pass:${KEY_PASSWORD}" \
                        -aes256 \
                        2048