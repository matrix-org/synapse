# Synapse database schema files

Synapse's database schema is stored in the `synapse.storage.schema` module.

## Logical databases

Synapse supports splitting its datastore across multiple physical databases (which can
be useful for large installations), and the schema files are therefore split according
to the logical database they apply to.

At the time of writing, the following "logical" databases are supported:

* `state` - used to store Matrix room state (more specifically, `state_groups`,
  their relationships and contents).
* `main` - stores everything else.

Additionally, the `common` directory contains schema files for tables which must be
present on *all* physical databases.

## Synapse schema versions

Synapse manages its database schema via "schema versions". These are mainly used to
help avoid confusion if the Synapse codebase is rolled back after the database is
updated. They work as follows:

 * The Synapse codebase defines a constant `synapse.storage.schema.SCHEMA_VERSION`
   which represents the expectations made about the database by that version. For
   example, as of Synapse v1.36, this is `59`.

 * The database stores a "compatibility version" in
   `schema_compat_version.compat_version` which defines the `SCHEMA_VERSION` of the
   oldest version of Synapse which will work with the database. On startup, if
   `compat_version` is found to be newer than `SCHEMA_VERSION`, Synapse will refuse to
   start.

   Synapse automatically updates this field from
   `synapse.storage.schema.SCHEMA_COMPAT_VERSION`.

 * Whenever a backwards-incompatible change is made to the database format (normally
   via a `delta` file), `synapse.storage.schema.SCHEMA_COMPAT_VERSION` is also updated
   so that administrators can not accidentally roll back to a too-old version of Synapse.

Generally, the goal is to maintain compatibility with at least one or two previous
releases of Synapse, so any substantial change tends to require multiple releases and a
bit of forward-planning to get right.

As a worked example: we want to remove the `room_stats_historical` table. Here is how it
might pan out.

 1. Replace any code that *reads* from `room_stats_historical` with alternative
    implementations, but keep writing to it in case of rollback to an earlier version.
    Also, increase `synapse.storage.schema.SCHEMA_VERSION`.  In this
    instance, there is no existing code which reads from `room_stats_historical`, so
    our starting point is:

    v1.36.0: `SCHEMA_VERSION=59`, `SCHEMA_COMPAT_VERSION=59`

 2. Next (say in Synapse v1.37.0): remove the code that *writes* to
    `room_stats_historical`, but don’t yet remove the table in case of rollback to
    v1.36.0. Again, we increase `synapse.storage.schema.SCHEMA_VERSION`, but
    because we have not broken compatibility with v1.36, we do not yet update
    `SCHEMA_COMPAT_VERSION`. We now have:

    v1.37.0: `SCHEMA_VERSION=60`, `SCHEMA_COMPAT_VERSION=59`.

 3. Later (say in Synapse v1.38.0): we can remove the table altogether. This will
    break compatibility with v1.36.0, so we must update `SCHEMA_COMPAT_VERSION` accordingly.
    There is no need to update `synapse.storage.schema.SCHEMA_VERSION`, since there is no
    change to the Synapse codebase here. So we end up with:

    v1.38.0: `SCHEMA_VERSION=60`, `SCHEMA_COMPAT_VERSION=60`.

If in doubt about whether to update `SCHEMA_VERSION` or not, it is generally best to
lean towards doing so.

## Full schema dumps

In the `full_schemas` directories, only the most recently-numbered snapshot is used
(`54` at the time of writing). Older snapshots (eg, `16`) are present for historical
reference only.

### Building full schema dumps

If you want to recreate these schemas, they need to be made from a database that
has had all background updates run.

To do so, use `scripts-dev/make_full_schema.sh`. This will produce new
`full.sql.postgres` and `full.sql.sqlite` files.

Ensure postgres is installed, then run:

```sh
./scripts-dev/make_full_schema.sh -p postgres_username -o output_dir/
```

NB at the time of writing, this script predates the split into separate `state`/`main`
databases so will require updates to handle that correctly.

## Delta files

Delta files define the steps required to upgrade the database from an earlier version.
They can be written as either a file containing a series of SQL statements, or a Python
module.

Synapse remembers which delta files it has applied to a database (they are stored in the
`applied_schema_deltas` table) and will not re-apply them (even if a given file is
subsequently updated).

Delta files should be placed in a directory named `synapse/storage/schema/<database>/delta/<version>/`.
They are applied in alphanumeric order, so  by convention the first two characters
of the filename should be an integer such as `01`, to put the file in the right order.

### SQL delta files

These should be named `*.sql`, or —  for changes which should only be applied for a
given database engine — `*.sql.posgres` or `*.sql.sqlite`. For example, a delta which
adds a new column to the `foo` table might be called `01add_bar_to_foo.sql`.

Note that our SQL parser is a bit simple - it understands comments (`--` and `/*...*/`),
but complex statements which require a `;` in the middle of them (such as `CREATE
TRIGGER`) are beyond it and you'll have to use a Python delta file.

### Python delta files

For more flexibility, a delta file can take the form of a python module. These should
be named `*.py`. Note that database-engine-specific modules are not supported here –
instead you can write `if isinstance(database_engine, PostgresEngine)` or similar.

A Python delta module should define either or both of the following functions:

```python
import synapse.config.homeserver
import synapse.storage.engines
import synapse.storage.types


def run_create(
    cur: synapse.storage.types.Cursor,
    database_engine: synapse.storage.engines.BaseDatabaseEngine,
) -> None:
    """Called whenever an existing or new database is to be upgraded"""
    ...

def run_upgrade(
    cur: synapse.storage.types.Cursor,
    database_engine: synapse.storage.engines.BaseDatabaseEngine,
    config: synapse.config.homeserver.HomeServerConfig,
) -> None:
    """Called whenever an existing database is to be upgraded."""
    ...
```

## Boolean columns

Boolean columns require special treatment, since SQLite treats booleans the
same as integers.

There are three separate aspects to this:

 * Any new boolean column must be added to the `BOOLEAN_COLUMNS` list in
   `synapse/_scripts/synapse_port_db.py`. This tells the port script to cast
   the integer value from SQLite to a boolean before writing the value to the
   postgres database.

 * Before SQLite 3.23, `TRUE` and `FALSE` were not recognised as constants by
   SQLite, and the `IS [NOT] TRUE`/`IS [NOT] FALSE` operators were not
   supported. This makes it necessary to avoid using `TRUE` and `FALSE`
   constants in SQL commands.

   For example, to insert a `TRUE` value into the database, write:

   ```python
   txn.execute("INSERT INTO tbl(col) VALUES (?)", (True, ))
   ```

 * Default values for new boolean columns present a particular
   difficulty. Generally it is best to create separate schema files for
   Postgres and SQLite. For example:

   ```sql
   # in 00delta.sql.postgres:
   ALTER TABLE tbl ADD COLUMN col BOOLEAN DEFAULT FALSE;
   ```

   ```sql
   # in 00delta.sql.sqlite:
   ALTER TABLE tbl ADD COLUMN col BOOLEAN DEFAULT 0;
   ```

   Note that there is a particularly insidious failure mode here: the Postgres
   flavour will be accepted by SQLite 3.22, but will give a column whose
   default value is the **string** `"FALSE"` - which, when cast back to a boolean
   in Python, evaluates to `True`.
