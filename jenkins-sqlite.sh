#!/bin/bash

set -eux

: ${WORKSPACE:="$(pwd)"}

export WORKSPACE
export PYTHONDONTWRITEBYTECODE=yep
export SYNAPSE_CACHE_FACTOR=1

./jenkins/prepare_synapse.sh
./jenkins/clone.sh sytest https://github.com/matrix-org/sytest.git

./sytest/jenkins/install_and_run.sh \
    --python $WORKSPACE/.tox/py27/bin/python \
    --synapse-directory $WORKSPACE \
