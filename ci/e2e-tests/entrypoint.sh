#!/usr/bin/env bash

if [ -z "${E2E_PROFILE}" ]; then
    echo 'Must specify E2E_PROFILE (either "dam" or "ic")'
    exit 1
fi

set -ex

./mvnw -P${E2E_PROFILE} -o test "$@"