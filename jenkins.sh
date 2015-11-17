#!/bin/bash -eu

export PYTHONDONTWRITEBYTECODE=yep

# Output test results as junit xml
export TRIAL_FLAGS="--reporter=subunit"
export TOXSUFFIX="| subunit-1to2 | subunit2junitxml --no-passthrough --output-to=results.xml"

# Output coverage to coverage.xml
export DUMP_COVERAGE_COMMAND="coverage xml -o coverage.xml"

# Output flake8 violations to violations.flake8.log
# Don't exit with non-0 status code on Jenkins,
# so that the build steps continue and a later step can decided whether to
# UNSTABLE or FAILURE this build.
export PEP8SUFFIX="--output-file=violations.flake8.log || echo flake8 finished with status code \$?"

tox

: ${GIT_BRANCH:="$(git rev-parse --abbrev-ref HEAD)"}

set +u
. .tox/py27/bin/activate
set -u

rm -rf sytest
git clone https://github.com/matrix-org/sytest.git sytest
cd sytest

git checkout "${GIT_BRANCH}" || (echo >&2 "No ref ${GIT_BRANCH} found, falling back to develop" ; git checkout develop)

: ${PERL5LIB:=$WORKSPACE/perl5/lib/perl5}
: ${PERL_MB_OPT:=--install_base=$WORKSPACE/perl5}
: ${PERL_MM_OPT:=INSTALL_BASE=$WORKSPACE/perl5}
export PERL5LIB PERL_MB_OPT PERL_MM_OPT

./install-deps.pl

./run-tests.pl -O tap --synapse-directory .. --all > results.tap
