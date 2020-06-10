# Synapse Database Schemas

These schemas are used as a basis to create brand new Synapse databases, on both
SQLite3 and Postgres.

## Building full schema dumps

If you want to recreate these schemas, they need to be made from a database that
has had all background updates run.

To do so, use `scripts-dev/make_full_schema.sh`. This will produce new
`full.sql.postgres ` and `full.sql.sqlite` files. 

Ensure postgres is installed and your user has the ability to run bash commands
such as `createdb`, then call

    ./scripts-dev/make_full_schema.sh -p postgres_username -o output_dir/

There are currently two folders with full-schema snapshots. `16` is a snapshot
from 2015, for historical reference. The other contains the most recent full
schema snapshot.
