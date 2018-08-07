#! /usr/bin/env bash

set -x

if [ -e "/test/run-tests.pl" ]
then
    echo "Using local sytests..."
else
    branch_name="$(git --git-dir=/src/.git symbolic-ref HEAD 2>/dev/null)" || branch_name="(unnamed branch)"

    echo "Trying to get same-named sytest..."
    wget -q https://github.com/matrix-org/sytest/archive/$branch_name.tar.gz -O sytest.tar.gz
4
    if [ $? -eq 0 ]
    then
        echo "Using $branch_name!"
    else
        echo "Using develop instead..."
        wget -q https://github.com/matrix-org/sytest/archive/develop.tar.gz -O sytest.tar.gz
    fi

    tar --strip-components=1 -xf sytest.tar.gz

fi

# PostgreSQL setup
if [ -n "$POSTGRES" ]
then

    export PGDATA=/var/lib/postgresql/data
    export PGUSER=postgres
    export POSTGRES_DB_1=pg1
    export POSTGRES_DB_2=pg2

    su -c '/usr/lib/postgresql/9.6/bin/initdb -E "UTF-8" --lc-collate="en_US.UTF-8" --lc-ctype="en_US.UTF-8" --username=postgres' postgres
    su -c '/usr/lib/postgresql/9.6/bin/pg_ctl -w -D /var/lib/postgresql/data start' postgres

    jenkins/prep_sytest_for_postgres.sh

    su -c 'psql -c "CREATE DATABASE pg1;"' postgres
    su -c 'psql -c "CREATE DATABASE pg2;"' postgres

fi

# Build the virtualenv
$PYTHON -m virtualenv -p $PYTHON /venv/
/venv/bin/pip install -q --no-cache-dir -e /src/
/venv/bin/pip install -q --no-cache-dir lxml psycopg2

# Make sure all deps are installed -- this is done in the docker build so it shouldn't be too many
./install-deps.pl

# Run the tests
./run-tests.pl -I Synapse --python=/venv/bin/python -O tap --all > results.tap

# Copy out the logs
cp results.tap /logs/results.tap
cp server-0/homeserver.log /logs/homeserver-0.log
cp server-1/homeserver.log /logs/homeserver-1.log
