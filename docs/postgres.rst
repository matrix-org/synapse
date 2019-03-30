Using Postgres
--------------

Postgres version 9.4 or later is known to work.

Set up database
===============

Assuming your PostgreSQL database user is called ``postgres``, create a user
``synapse_user`` with::

   su - postgres
   createuser --pwprompt synapse_user

The PostgreSQL database used *must* have the correct encoding set, otherwise it
would not be able to store UTF8 strings. To create a database with the correct
encoding use, e.g.::

   CREATE DATABASE synapse
    ENCODING 'UTF8'
    LC_COLLATE='C'
    LC_CTYPE='C'
    template=template0
    OWNER synapse_user;

This would create an appropriate database named ``synapse`` owned by the
``synapse_user`` user (which must already exist).

Set up client in Debian/Ubuntu
===========================

Postgres support depends on the postgres python connector ``psycopg2``. In the
virtual env::

    sudo apt-get install libpq-dev
    pip install psycopg2

Set up client in RHEL/CentOs 7
==============================

Make sure you have the appropriate version of postgres-devel installed. For a
postgres 9.4, use the postgres 9.4 packages from
[here](https://wiki.postgresql.org/wiki/YUM_Installation).

As with Debian/Ubuntu, postgres support depends on the postgres python connector
``psycopg2``. In the virtual env::

    sudo yum install postgresql-devel libpqxx-devel.x86_64
    export PATH=/usr/pgsql-9.4/bin/:$PATH
    pip install psycopg2

Tuning Postgres
===============

The default settings should be fine for most deployments. For larger scale
deployments tuning some of the settings is recommended, details of which can be
found at https://wiki.postgresql.org/wiki/Tuning_Your_PostgreSQL_Server.

In particular, we've found tuning the following values helpful for performance:

- ``shared_buffers``
- ``effective_cache_size``
- ``work_mem``
- ``maintenance_work_mem``
- ``autovacuum_work_mem``

Note that the appropriate values for those fields depend on the amount of free
memory the database host has available.

Synapse config
==============

When you are ready to start using PostgreSQL, edit the ``database`` section in
your config file to match the following lines::

    database:
        name: psycopg2
        args:
            user: <user>
            password: <pass>
            database: <db>
            host: <host>
            cp_min: 5
            cp_max: 10

All key, values in ``args`` are passed to the ``psycopg2.connect(..)``
function, except keys beginning with ``cp_``, which are consumed by the twisted
adbapi connection pool.


Porting from SQLite
===================

Overview
~~~~~~~~

The script ``synapse_port_db`` allows porting an existing synapse server
backed by SQLite to using PostgreSQL. This is done in as a two phase process:

1. Copy the existing SQLite database to a separate location (while the server
   is down) and running the port script against that offline database.
2. Shut down the server. Rerun the port script to port any data that has come
   in since taking the first snapshot. Restart server against the PostgreSQL
   database.

The port script is designed to be run repeatedly against newer snapshots of the
SQLite database file. This makes it safe to repeat step 1 if there was a delay
between taking the previous snapshot and being ready to do step 2.

It is safe to at any time kill the port script and restart it.

Using the port script
~~~~~~~~~~~~~~~~~~~~~

Firstly, shut down the currently running synapse server and copy its database
file (typically ``homeserver.db``) to another location. Once the copy is
complete, restart synapse.  For instance::

    ./synctl stop
    cp homeserver.db homeserver.db.snapshot
    ./synctl start

Copy the old config file into a new config file::

    cp homeserver.yaml homeserver-postgres.yaml

Edit the database section as described in the section *Synapse config* above
and with the SQLite snapshot located at ``homeserver.db.snapshot`` simply run::

    synapse_port_db --sqlite-database homeserver.db.snapshot \
        --postgres-config homeserver-postgres.yaml

The flag ``--curses`` displays a coloured curses progress UI.

If the script took a long time to complete, or time has otherwise passed since
the original snapshot was taken, repeat the previous steps with a newer
snapshot.

To complete the conversion shut down the synapse server and run the port
script one last time, e.g. if the SQLite database is at  ``homeserver.db``
run::

    synapse_port_db --sqlite-database homeserver.db \
        --postgres-config homeserver-postgres.yaml

Once that has completed, change the synapse config to point at the PostgreSQL
database configuration file ``homeserver-postgres.yaml``::

    ./synctl stop
    mv homeserver.yaml homeserver-old-sqlite.yaml
    mv homeserver-postgres.yaml homeserver.yaml
    ./synctl start

Synapse should now be running against PostgreSQL.
