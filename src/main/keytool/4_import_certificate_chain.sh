#!/usr/bin/env bash

source 0_set_environment_variables.sh

${JAVA_HOME}/keytool -import -trustcacerts -file "${AUTH_PKCS7}" -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD} -alias authkey
${JAVA_HOME}/keytool -import -trustcacerts -file "${SIGN_PKCS7}" -keystore "${KEY_STORE}" -storepass ${STORE_PASSWORD} -alias signkey