# Synapse Database Schemas

This directory contains the schema files used to build Synapse databases.

Synapse supports splitting its datastore across multiple physical databases (which can
be useful for large installations), and the schema files are therefore split according
to the logical database they are apply to.

At the time of writing, the following "logical" databases are supported:

* `state` - used to store Matrix room state (more specifically, `state_groups`,
  their relationships and contents.)
* `main` - stores everything else.

Addionally, the `common` directory contains schema files for tables which must be
present on *all* physical databases.

## Full schema dumps

In the `full_schemas` directories, only the most recently-numbered snapshot is useful
(`54` at the time of writing). Older snapshots (eg, `16`) are present for historical
reference only.

## Building full schema dumps

If you want to recreate these schemas, they need to be made from a database that
has had all background updates run.

To do so, use `scripts-dev/make_full_schema.sh`. This will produce new
`full.sql.postgres` and `full.sql.sqlite` files.

Ensure postgres is installed, then run:

    ./scripts-dev/make_full_schema.sh -p postgres_username -o output_dir/

NB at the time of writing, this script predates the split into separate `state`/`main`
databases so will require updates to handle that correctly.
