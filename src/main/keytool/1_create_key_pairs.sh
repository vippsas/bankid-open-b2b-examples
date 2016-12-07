#!/usr/bin/env bash

source 0_set_environment_variables.sh

# This password is used for authentication/signing with the BankID and must be protected!
PRIVATE_KEY_PASSWORD="changeit"

${JAVA_HOME}/keytool -genkey \
                     -alias authkey \
                     -keyalg RSA \
                     -keysize 2048 \
                     -keystore "${KEY_STORE}" \
                     -dname "CN=${COMMON_NAME}" \
                     -storepass "${STORE_PASSWORD}" \
                     -keypass "${PRIVATE_KEY_PASSWORD}" \
                     -v

${JAVA_HOME}/keytool -genkey \
                     -alias signkey \
                     -keyalg RSA \
                     -keysize 2048 \
                     -keystore "${KEY_STORE}" \
                     -dname "CN=${COMMON_NAME}" \
                     -storepass "${STORE_PASSWORD}" \
                     -keypass "${PRIVATE_KEY_PASSWORD}" \
                     -v