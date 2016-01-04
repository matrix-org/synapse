#!/bin/bash -eu

export PYTHONDONTWRITEBYTECODE=yep

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

tox

: ${GIT_BRANCH:="origin/$(git rev-parse --abbrev-ref HEAD)"}

TOX_BIN=$WORKSPACE/.tox/py27/bin

if [[ ! -e .sytest-base ]]; then
  git clone https://github.com/matrix-org/sytest.git .sytest-base --mirror
else
  (cd .sytest-base; git fetch)
fi

rm -rf sytest
git clone .sytest-base sytest --shared
cd sytest

git checkout "${GIT_BRANCH}" || (echo >&2 "No ref ${GIT_BRANCH} found, falling back to develop" ; git checkout develop)

: ${PERL5LIB:=$WORKSPACE/perl5/lib/perl5}
: ${PERL_MB_OPT:=--install_base=$WORKSPACE/perl5}
: ${PERL_MM_OPT:=INSTALL_BASE=$WORKSPACE/perl5}
export PERL5LIB PERL_MB_OPT PERL_MM_OPT

./install-deps.pl

: ${PORT_BASE:=8000}

echo >&2 "Running sytest with SQLite3";
./run-tests.pl --coverage -O tap --synapse-directory $WORKSPACE \
    --python $TOX_BIN/python --all --port-base $PORT_BASE > results-sqlite3.tap

RUN_POSTGRES=""

for port in $(($PORT_BASE + 1)) $(($PORT_BASE + 2)); do
    if psql synapse_jenkins_$port <<< ""; then
        RUN_POSTGRES=$RUN_POSTGRES:$port
        cat > localhost-$port/database.yaml << EOF
name: psycopg2
args:
    database: synapse_jenkins_$port
EOF
    fi
done

# Run if both postgresql databases exist
if test $RUN_POSTGRES = ":$(($PORT_BASE + 1)):$(($PORT_BASE + 2))"; then
    echo >&2 "Running sytest with PostgreSQL";
    $TOX_BIN/pip install psycopg2
    ./run-tests.pl --coverage -O tap --synapse-directory $WORKSPACE \
        --python $TOX_BIN/python --all --port-base $PORT_BASE > results-postgresql.tap
else
    echo >&2 "Skipping running sytest with PostgreSQL, $RUN_POSTGRES"
fi

cd ..
cp sytest/.coverage.* .

# Combine the coverage reports
echo "Combining:" .coverage.*
$TOX_BIN/python -m coverage combine
# Output coverage to coverage.xml
$TOX_BIN/coverage xml -o coverage.xml
