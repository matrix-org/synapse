#!/bin/bash

set -eux

: ${WORKSPACE:="$(pwd)"}

export WORKSPACE
export PYTHONDONTWRITEBYTECODE=yep
export SYNAPSE_CACHE_FACTOR=1

./jenkins/prepare_synapse.sh
./jenkins/clone.sh sytest https://github.com/matrix-org/sytest.git
./jenkins/clone.sh dendron https://github.com/matrix-org/dendron.git
./dendron/jenkins/build_dendron.sh
./sytest/jenkins/prep_sytest_for_postgres.sh

./sytest/jenkins/install_and_run.sh \
    --python $WORKSPACE/.tox/py27/bin/python \
    --synapse-directory $WORKSPACE \
    --dendron $WORKSPACE/dendron/bin/dendron \
