This blog post by Victor Berger explains how to use many of the tools listed on this page: https://levans.fr/shrink-synapse-database.html

# List of useful tools and scripts for maintenance Synapse database:

## [Purge Remote Media API](../../admin_api/media_admin_api.md#purge-remote-media-api)
The purge remote media API allows server admins to purge old cached remote media.

#### Purge local media 

There is no purge API for local media because you may be the only one with a copy. If you are sure you want to delete local media you could use something like the following to delete media that hasn't been accessed in a while.

```
find /path/to/synapse/media_store/local_content -atime +365 -delete
find /path/to/synapse/media_store/local_thumbnails -atime +365 -delete
```

This will delete media that hasn't been accessed in 365 days.

**Warning, check noatime flag**: You also have to double-check that the filesystem where synapse's media store don't have [noatime flag](https://unix.stackexchange.com/questions/219015/how-to-disable-access-time-settings-in-debian-linux/219017#219017). Check it with `mount`, `noatime` is something that is usually enabled by default to reduce read-write operations in the filesystem for a feature is not so demanded.

## [Purge History API](../../admin_api/purge_history_api.md)
The purge history API allows server admins to purge historic events from their database, reclaiming disk space.

## [synapse_janitor.sql](https://github.com/xwiki-labs/synapse_scripts)

- this project is [unmantained and dangerous](https://github.com/xwiki-labs/synapse_scripts#unmaintained-and-dangerous)
- USE WITH CAUTION. It may cause database corruption (see https://github.com/matrix-org/synapse/issues/7305 for example).
- ["Our team hasn't used any of these scripts for some time (possibly years) (...) if anyone wants to volunteer to maintain this repo I'd be happy to transfer ownership.](https://github.com/xwiki-labs/synapse_scripts/pull/12#issuecomment-617275345) 

Cleans a synapse Postgres database of deleted messages and abandoned rooms.

## [synapse-compress-state](https://github.com/matrix-org/rust-synapse-compress-state)
Tool for compressing (deduplicating) `state_groups_state` table.

## [SQL for analyzing Synapse PostgreSQL database stats](https://github.com/matrix-org/synapse/wiki/SQL-for-analyzing-Synapse-PostgreSQL-database-stats)
Some easy SQL that reports useful stat about Matrix Synapse database.