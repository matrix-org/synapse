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

## Background updates

It is sometimes appropriate to perform database migrations as part of a background
process (instead of blocking Synapse until the migration is done). In particular,
this is useful for migrating data when adding new columns or tables.

Pending background updates stored in the `background_updates` table and are denoted
by a unique name, the current status (stored in JSON), and some dependency information:

* Whether the update requires a previous update to be complete.
* A rough ordering for which to complete updates.

A new background updates needs to be added to the `background_updates` table:

```sql
INSERT INTO background_updates (ordering, update_name, depends_on, progress_json) VALUES
  (7706, 'my_background_update', 'a_previous_background_update' '{}');
```

And then needs an associated handler in the appropriate datastore:

```python
self.db_pool.updates.register_background_update_handler(
    "my_background_update",
    update_handler=self._my_background_update,
)
```

There are a few types of updates that can be performed, see the `BackgroundUpdater`:

* `register_background_update_handler`: A generic handler for custom SQL
* `register_background_index_update`: Create an index in the background
* `register_background_validate_constraint`: Validate a constraint in the background
  (PostgreSQL-only)
* `register_background_validate_constraint_and_delete_rows`: Similar to
  `register_background_validate_constraint`, but deletes rows which don't fit
  the constraint.

For `register_background_update_handler`, the generic handler must track progress
and then finalize the background update:

```python
async def _my_background_update(self, progress: JsonDict, batch_size: int) -> int:
    def _do_something(txn: LoggingTransaction) -> int:
        ...
        self.db_pool.updates._background_update_progress_txn(
            txn, "my_background_update", {"last_processed": last_processed}
        )
        return last_processed - prev_last_processed

    num_processed = await self.db_pool.runInteraction("_do_something", _do_something)
    await self.db_pool.updates._end_background_update("my_background_update")

    return num_processed
```

Synapse will attempt to rate-limit how often background updates are run via the
given batch-size and the returned number of processed entries (and how long the
function took to run). See
[background update controller callbacks](../modules/background_update_controller_callbacks.md).

## Boolean columns

Boolean columns require special treatment, since SQLite treats booleans the
same as integers.

Any new boolean column must be added to the `BOOLEAN_COLUMNS` list in
   `synapse/_scripts/synapse_port_db.py`. This tells the port script to cast
   the integer value from SQLite to a boolean before writing the value to the
   postgres database.


## `event_id` global uniqueness

`event_id`'s can be considered globally unique although there has been a lot of
debate on this topic in places like
[MSC2779](https://github.com/matrix-org/matrix-spec-proposals/issues/2779) and
[MSC2848](https://github.com/matrix-org/matrix-spec-proposals/pull/2848) which
has no resolution yet (as of 2022-09-01). There are several places in Synapse
and even in the Matrix APIs like [`GET
/_matrix/federation/v1/event/{eventId}`](https://spec.matrix.org/v1.1/server-server-api/#get_matrixfederationv1eventeventid)
where we assume that event IDs are globally unique.

When scoping `event_id` in a database schema, it is often nice to accompany it
with `room_id` (`PRIMARY KEY (room_id, event_id)` and a `FOREIGN KEY(room_id)
REFERENCES rooms(room_id)`) which makes flexible lookups easy. For example it
makes it very easy to find and clean up everything in a room when it needs to be
purged (no need to use sub-`select` query or join from the `events` table).

A note on collisions: In room versions `1` and `2` it's possible to end up with
two events with the same `event_id` (in the same or different rooms). After room
version `3`, that can only happen with a hash collision, which we basically hope
will never happen (SHA256 has a massive big key space).


## Worked examples of gradual migrations

Some migrations need to be performed gradually. A prime example of this is anything
which would need to do a large table scan — including adding columns, indices or
`NOT NULL` constraints to non-empty tables — such a migration should be done as a
background update where possible, at least on Postgres.
We can afford to be more relaxed about SQLite databases since they are usually
used on smaller deployments and SQLite does not support the same concurrent
DDL operations as Postgres.

We also typically insist on having at least one Synapse version's worth of
backwards compatibility, so that administrators can roll back Synapse if an upgrade
did not go smoothly.

This sometimes results in having to plan a migration across multiple versions
of Synapse.

This section includes an example and may include more in the future.



### Transforming a column into another one, with `NOT NULL` constraints

This example illustrates how you would introduce a new column, write data into it
based on data from an old column and then drop the old column.

We are aiming for semantic equivalence to:

```sql
ALTER TABLE mytable ADD COLUMN new_column INTEGER;
UPDATE mytable SET new_column = old_column * 100;
ALTER TABLE mytable ALTER COLUMN new_column ADD CONSTRAINT NOT NULL;
ALTER TABLE mytable DROP COLUMN old_column;
```

#### Synapse version `N`

```python
SCHEMA_VERSION = S
SCHEMA_COMPAT_VERSION = ... # unimportant at this stage
```

**Invariants:**
1. `old_column` is read by Synapse and written to by Synapse.


#### Synapse version `N + 1`

```python
SCHEMA_VERSION = S + 1
SCHEMA_COMPAT_VERSION = ... # unimportant at this stage
```

**Changes:**
1.
   ```sql
   ALTER TABLE mytable ADD COLUMN new_column INTEGER;
   ```

**Invariants:**
1. `old_column` is read by Synapse and written to by Synapse.
2. `new_column` is written to by Synapse.

**Notes:**
1. `new_column` can't have a `NOT NULL NOT VALID` constraint yet, because the previous Synapse version did not write to the new column (since we haven't bumped the `SCHEMA_COMPAT_VERSION` yet, we still need to be compatible with the previous version).


#### Synapse version `N + 2`

```python
SCHEMA_VERSION = S + 2
SCHEMA_COMPAT_VERSION = S + 1 # this signals that we can't roll back to a time before new_column existed
```

**Changes:**
1. On Postgres, add a `NOT VALID` constraint to ensure new rows are compliant. *SQLite does not have such a construct, but it would be unnecessary anyway since there is no way to concurrently perform this migration on SQLite.*
   ```sql
   ALTER TABLE mytable ADD CONSTRAINT CHECK new_column_not_null (new_column IS NOT NULL) NOT VALID;
   ```
2. Start a background update to perform migration: it should gradually run e.g.
   ```sql
   UPDATE mytable SET new_column = old_column * 100 WHERE 0 < mytable_id AND mytable_id <= 5;
   ```
   This background update is technically pointless on SQLite, but you must schedule it anyway so that the `portdb` script to migrate to Postgres still works.
3. Upon completion of the background update, you should run `VALIDATE CONSTRAINT` on Postgres to turn the `NOT VALID` constraint into a valid one.
   ```sql
   ALTER TABLE mytable VALIDATE CONSTRAINT new_column_not_null;
   ```
   This will take some time but does **NOT** hold an exclusive lock over the table.

**Invariants:**
1. `old_column` is read by Synapse and written to by Synapse.
2. `new_column` is written to by Synapse and new rows always have a non-`NULL` value in this field.


**Notes:**
1. If you wish, you can convert the `CHECK (new_column IS NOT NULL)` to a `NOT NULL` constraint free of charge in Postgres by adding the `NOT NULL` constraint and then dropping the `CHECK` constraint, because Postgres can statically verify that the `NOT NULL` constraint is implied by the `CHECK` constraint without performing a table scan.
2. It might be tempting to make version `N + 2` redundant by moving the background update to `N + 1` and delaying adding the `NOT NULL` constraint to `N + 3`, but that would mean the constraint would always be validated in the foreground in `N + 3`. Whereas if the `N + 2` step is kept, the migration in `N + 3` would be fast in the happy case.

#### Synapse version `N + 3`

```python
SCHEMA_VERSION = S + 3
SCHEMA_COMPAT_VERSION = S + 1 # we can't roll back to a time before new_column existed
```

**Changes:**
1. (Postgres) Update the table to populate values of `new_column` in case the background update had not completed. Additionally, `VALIDATE CONSTRAINT` to make the check fully valid.
   ```sql
   -- you ideally want an index on `new_column` or e.g. `(new_column) WHERE new_column IS NULL` first, or perhaps you can find a way to skip this if the `NOT NULL` constraint has already been validated.
   UPDATE mytable SET new_column = old_column * 100 WHERE new_column IS NULL;

   -- this is a no-op if it already ran as part of the background update
   ALTER TABLE mytable VALIDATE CONSTRAINT new_column_not_null;
   ```
2. (SQLite) Recreate the table by precisely following [the 12-step procedure for SQLite table schema changes](https://www.sqlite.org/lang_altertable.html#otheralter).
   During this table rewrite, you should recreate `new_column` as `NOT NULL` and populate any outstanding `NULL` values at the same time.
   Unfortunately, you can't drop `old_column` yet because it must be present for compatibility with the Postgres schema, as needed by `portdb`.
   (Otherwise you could do this all in one go with SQLite!)

**Invariants:**
1. `old_column` is written to by Synapse (but no longer read by Synapse!).
2. `new_column` is read by Synapse and written to by Synapse. Moreover, all rows have a non-`NULL` value in this field, as guaranteed by a schema constraint.

**Notes:**
1. We can't drop `old_column` yet, or even stop writing to it, because that would break a rollback to the previous version of Synapse.
2. Application code can now rely on `new_column` being populated. The remaining steps are only motivated by the wish to clean-up old columns.


#### Synapse version `N + 4`

```python
SCHEMA_VERSION = S + 4
SCHEMA_COMPAT_VERSION = S + 3 # we can't roll back to a time before new_column was entirely non-NULL
```

**Invariants:**
1. `old_column` exists but is not written to or read from by Synapse.
2. `new_column` is read by Synapse and written to by Synapse. Moreover, all rows have a non-`NULL` value in this field, as guaranteed by a schema constraint.

**Notes:**
1. We can't drop `old_column` yet because that would break a rollback to the previous version of Synapse. \
   **TODO:** It may be possible to relax this and drop the column straight away as long as the previous version of Synapse detected a rollback occurred and stopped attempting to write to the column. This could possibly be done by checking whether the database's schema compatibility version was `S + 3`.


#### Synapse version `N + 5`

```python
SCHEMA_VERSION = S + 5
SCHEMA_COMPAT_VERSION = S + 4 # we can't roll back to a time before old_column was no longer being touched
```

**Changes:**
1.
   ```sql
   ALTER TABLE mytable DROP COLUMN old_column;
   ```
