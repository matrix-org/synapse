The `10_replica_identity_xxx.sql.postgres` series of schema deltas adds replica identities for tables that do not have one implicitly as a result of having a primary key.

This is needed to use logical replication with Synapse (at least without `UPDATE` and `DELETE` statements failing!).

Where possible, we use an existing `UNIQUE` index on `NOT NULL` columns as the replica identity. Otherwise, we have to fall back to using the full row as a replica identity.

Unfortunately, by running all the `ALTER TABLE` statements in one schema delta per database, it was too likely to hit a deadlock as it would only take
one other transaction from a running Synapse worker to access the tables out of order and trigger a deadlock.

By having each statement in its own delta file, each one is run in its own transaction and only needs to take a very brief (instant) lock on the table but no other tables,
so there should be no chance of deadlock.

Like many schema deltas we already apply to Synapse, it is probably blocked by an ongoing `pg_dump`.
