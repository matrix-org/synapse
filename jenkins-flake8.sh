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
export PEP8SUFFIX="--output-file=violations.flake8.log"

rm .coverage* || echo "No coverage files to remove"

tox -e packaging -e pep8
