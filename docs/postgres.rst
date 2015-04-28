Using Postgres
--------------

Set up client
=============
We need to have installed the postgres python connector ``psycopg2``. In the
virtual env::

    sudo apt-get install libpq-dev
    pip install psycopg2


Synapse config
==============

Add the following line to your config file::

    database_config: <db_config_file>

Where ``<db_config_file>`` is the file name that points to a yaml file of the
following form::

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
