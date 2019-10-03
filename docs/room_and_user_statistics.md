Room and User Statistics
========================

Synapse maintains room and user statistics (as well as a cache of room state),
in various tables. These can be used for administrative purposes but are also
used when generating the public room directory.


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
    * They can also be thought of as 'gauges' in Prometheus, if you are familiar.
* per-slice columns – where the value corresponds to how many of the occurrences
    occurred within the time slice given by `(end_ts − bucket_size)…end_ts`
    or `start_ts…end_ts`. (Imagine a histogram for these values)

Stats are maintained in two tables (for each type): current and historical.

Current stats correspond to the present values. Each subject can only have one
entry.

Historical stats correspond to values in the past. Subjects may have multiple
entries.

## Concepts around the management of stats

### Current rows

Current rows contain the most up-to-date statistics for a room.
They only contain absolute columns

### Historical rows

Historical rows can always be considered to be valid for the time slice and
end time specified.

* historical rows will not exist for every time slice – they will be omitted
    if there were no changes. In this case, the following assumptions can be
    made to interpolate/recreate missing rows:
    - absolute fields have the same values as in the preceding row
    - per-slice fields are zero (`0`)
* historical rows will not be retained forever – rows older than a configurable
    time will be purged.

#### Purge

The purging of historical rows is not yet implemented.
