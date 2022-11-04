#!/usr/bin/env bash

source 0_set_environment_variables.sh

${OPENSSL_HOME}/openssl req \
                        -new \
                        -SHA256 \
                        -key "${AUTH_KEY}" \
                        -out "${AUTH_CSR}" \
                        -subj "/CN=${COMMON_NAME}" \
                        -passin "pass:${KEY_PASSWORD}" \
                        -verify

${OPENSSL_HOME}/openssl req \
                        -new \
                        -SHA256 \
                        -key "${SIGN_KEY}" \
                        -out "${SIGN_CSR}" \
                        -subj "/CN=${COMMON_NAME}" \
                        -passin "pass:${KEY_PASSWORD}" \
                        -verify