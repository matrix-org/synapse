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

tox --notest -e py27
TOX_BIN=$WORKSPACE/.tox/py27/bin
python synapse/python_dependencies.py | xargs -n1 $TOX_BIN/pip install
$TOX_BIN/pip install lxml

tox -e py27
