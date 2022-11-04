#!/usr/bin/env bash

source 0_set_environment_variables.sh

${JAVA_HOME}/keytool -list \
                     -keystore "${KEY_STORE}" \
                     -storepass "${STORE_PASSWORD}" \
                     -alias authkey \
                     -v

${JAVA_HOME}/keytool -list \
                     -keystore "${KEY_STORE}" \
                     -storepass "${STORE_PASSWORD}" \
                     -alias signkey \
                     -v
