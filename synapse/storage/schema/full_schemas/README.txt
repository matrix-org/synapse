Building full schema dumps
==========================

Postgres
--------

$ pg_dump --format=plain --schema-only --no-tablespaces --no-acl --no-owner $DATABASE_NAME| sed -e '/^--/d' -e 's/public.//g' -e '/^SET /d' -e '/^SELECT /d' > full.sql.postgres

SQLite
------

$ sqlite3 $DATABASE_FILE ".schema" > full.sql.sqlite

Delete the CREATE statements for "schema_version", "applied_schema_deltas", and "applied_module_schemas".