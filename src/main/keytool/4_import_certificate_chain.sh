#!/usr/bin/env bash

source 0_set_environment_variables.sh

# NB! The top-level certificate in the PKCS7 files is likely not trusted (if not imported in cacerts)
# and must be confirmed, by typing 'y' on the command line, to be imported.

${JAVA_HOME}/keytool -import \
                     -trustcacerts \
                     -file "${AUTH_PKCS7}" \
                     -keystore "${KEY_STORE}" \
                     -storepass "${STORE_PASSWORD}" \
                     -alias authkey \
                     -v

${JAVA_HOME}/keytool -import \
                     -trustcacerts \
                     -file "${SIGN_PKCS7}" \
                     -keystore "${KEY_STORE}" \
                     -storepass "${STORE_PASSWORD}" \
                     -alias signkey \
                     -v