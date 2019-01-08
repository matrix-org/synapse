Building full schema dumps
==========================

Postgres
--------

$ pg_dump --schema-only --no-comments --no-tablespaces --no-acl --no-owner ${DATABASE_NAME} > full.sql.postgres

In the resulting file, delete all SET commands from the top of the file.

SQLite
------

$ sqlite3 $DATABASE_FILE ".schema" > full.sql.sqlite

Delete the CREATE statements for "schema_version", "applied_schema_deltas", and "applied_module_schemas".

Adding Empty Values To Tables
-----------------------------

Some tables need data added, like stream ID tables. This is done in 54/zzz-inserts.sql and should be copied to any subsequent full schemas.