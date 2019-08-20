Room and User Statistics
========================

Synapse maintains room and user statistics (as well as a cache of room state),
in various tables.

These can be used for administrative purposes but are also used when generating
the public room directory. If these tables get stale or out of sync (possibly
after database corruption), you may wish to regenerate them.


# Synapse Administrator Documentation

## Various SQL scripts that you may find useful

### Delete stats, including historical stats

```sql
DELETE FROM room_stats_current;
DELETE FROM room_stats_historical;
DELETE FROM user_stats_current;
DELETE FROM user_stats_historical;
```

### Regenerate stats (all subjects)

```sql
BEGIN;
    DELETE FROM stats_incremental_position;
    INSERT INTO stats_incremental_position (
        state_delta_stream_id,
        total_events_min_stream_ordering,
        total_events_max_stream_ordering,
        is_background_contract
    ) VALUES (NULL, NULL, NULL, FALSE), (NULL, NULL, NULL, TRUE);
COMMIT;

DELETE FROM room_stats_current;
DELETE FROM user_stats_current;
```

then follow the steps below for **'Regenerate stats (missing subjects only)'**

### Regenerate stats (missing subjects only)

```sql
-- Set up staging tables
-- we depend on current_state_events_membership because this is used
-- in our counting.
INSERT INTO background_updates (update_name, progress_json) VALUES
    ('populate_stats_prepare', '{}', 'current_state_events_membership');

-- Run through each room and update stats
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_rooms', '{}', 'populate_stats_prepare');

-- Run through each user and update stats.
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_process_users', '{}', 'populate_stats_process_rooms');

-- Clean up staging tables
INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
    ('populate_stats_cleanup', '{}', 'populate_stats_process_users');
```

then **restart Synapse**.


# Synapse Developer Documentation

## High-Level Concepts

### Definitions

* **subject**: Something we are tracking stats about – currently a room or user.
* **current row**: An entry for a subject in the appropriate current statistics
    table. Each subject can have only one.
* **historical row**: An entry for a subject in the appropriate historical
    statistics table. Each subject can have any number of these.

### Overview

Stats are maintained as time series. There are two kinds of column:

* absolute columns – where the value is correct for the time given by `end_ts`
    in the stats row. (Imagine a line graph for these values)
* per-slice columns – where the value corresponds to how many of the occurrences
    occurred within the time slice given by `(end_ts − bucket_size)…end_ts`
    or `start_ts…end_ts`. (Imagine a histogram for these values)

Currently, only absolute columns are in use.

Stats are maintained in two tables (for each type): current and historical.

Current stats correspond to the present values. Each subject can only have one
entry.

Historical stats correspond to values in the past. Subjects may have multiple
entries.

## Concepts around the management of stats

### current rows

#### dirty current rows

Current rows can be **dirty**, which means that they have changed since the
latest historical row for the same subject.
**Dirty** current rows possess an end timestamp, `end_ts`.

#### old current rows and old collection

When a (necessarily dirty) current row has an `end_ts` in the past, it is said
to be **old**.
Old current rows must be copied into a historical row, and cleared of their dirty
status, before further statistics can be tracked for that subject.
The process which does this is referred to as **old collection**.

#### incomplete current rows

There are also **incomplete** current rows, which are current rows that do not
contain a full count yet – this is because they are waiting for the stats
regenerator to give them an initial count. Incomplete current rows DO NOT contain
correct and up-to-date values. As such, *incomplete rows are not old-collected*.
Instead, old incomplete rows will be extended so they are no longer old.

### historical rows

Historical rows can always be considered to be valid for the time slice and
end time specified. (This, of course, assumes a lack of defects in the code
to track the statistics, and assumes integrity of the database).

Even still, there are two considerations that we may need to bear in mind:

* historical rows will not exist for every time slice – they will be omitted
    if there were no changes. In this case, the following assumptions can be
    made to interpolate/recreate missing rows:
    - absolute fields have the same values as in the preceding row
    - per-slice fields are zero (`0`)
* historical rows will not be retained forever – rows older than a configurable
    time will be purged.

#### purge

The purging of historical rows is not yet implemented.

