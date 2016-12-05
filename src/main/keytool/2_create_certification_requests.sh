#!/usr/bin/env bash

source 0_set_environment_variables.sh

${JAVA_HOME}/keytool -certreq -alias authkey -file "${AUTH_CSR}" -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD}
${JAVA_HOME}/keytool -certreq -alias signkey -file "${SIGN_CSR}" -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD}