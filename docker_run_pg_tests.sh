export PGDATA=/var/lib/postgresql/data
export PGUSER=postgres

# Initialise the database files and start the database
su -c '/usr/lib/postgresql/9.6/bin/initdb -E "UTF-8" --lc-collate="en_US.UTF-8" --lc-ctype="en_US.UTF-8" --username=postgres' postgres
su -c '/usr/lib/postgresql/9.6/bin/pg_ctl -w -D /var/lib/postgresql/data start' postgres

cd /src
export TRIAL_FLAGS="-j 4"
tox -e py27-postgres
