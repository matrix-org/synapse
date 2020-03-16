Building full schema dumps
==========================

These schemas need to be made from a database that has had all background updates run.

Postgres
--------

$ pg_dump --format=plain --schema-only --no-tablespaces --no-acl --no-owner $DATABASE_NAME| sed -e '/^--/d' -e 's/public\.//g' -e '/^SET /d' -e '/^SELECT /d' > full.sql.postgres

SQLite
------

$ sqlite3 $DATABASE_FILE ".schema" > full.sql.sqlite

After
-----

Delete the CREATE statements for "sqlite_stat1", "schema_version", "applied_schema_deltas", and "applied_module_schemas".