#!/usr/bin/env bash

source 0_set_environment_variables.sh

echo
echo "Authentication certificate (chain):"
${JAVA_HOME}/keytool -list -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD} -alias authkey -v
echo
echo "Signing certificate (chain):"
${JAVA_HOME}/keytool -list -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD} -alias signkey -v
