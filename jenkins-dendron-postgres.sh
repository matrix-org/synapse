#!/bin/bash

set -eux

: ${WORKSPACE:="$(pwd)"}

export PYTHONDONTWRITEBYTECODE=yep
export SYNAPSE_CACHE_FACTOR=1

# Output test results as junit xml
export TRIAL_FLAGS="--reporter=subunit"
export TOXSUFFIX="| subunit-1to2 | subunit2junitxml --no-passthrough --output-to=results.xml"
# Write coverage reports to a separate file for each process
export COVERAGE_OPTS="-p"
export DUMP_COVERAGE_COMMAND="coverage help"

# Output flake8 violations to violations.flake8.log
# Don't exit with non-0 status code on Jenkins,
# so that the build steps continue and a later step can decided whether to
# UNSTABLE or FAILURE this build.
export PEP8SUFFIX="--output-file=violations.flake8.log || echo flake8 finished with status code \$?"

rm .coverage* || echo "No coverage files to remove"

./jenkins/prepare_synapse.sh

./jenkins/clone.sh sytest https://github.com/matrix-org/sytest.git
./jenkins/clone.sh dendron https://github.com/matrix-org/dendron.git

: ${GOPATH:=${WORKSPACE}/.gopath}
if [[ "${GOPATH}" != *:* ]]; then
  mkdir -p "${GOPATH}"
  export PATH="${GOPATH}/bin:${PATH}"
fi
export GOPATH

cd dendron

go get github.com/constabulary/gb/...
gb generate
gb build

cd ../sytest

: ${PORT_BASE:=20000}
: ${PORT_COUNT=100}
export PORT_BASE
export PORT_COUNT

./jenkins/prep_sytest_for_postgres.sh

mkdir -p var

echo >&2 "Running sytest with PostgreSQL";

TOX_BIN=$WORKSPACE/.tox/py27/bin
./jenkins/install_and_run.sh --python $TOX_BIN/python \
                             --synapse-directory $WORKSPACE \
                             --dendron $WORKSPACE/dendron/bin/dendron \
                             --pusher \
                             --synchrotron \
                             --federation-reader \
                             --port-range ${PORT_BASE}:$((PORT_BASE+PORT_COUNT-1))

cd ..
