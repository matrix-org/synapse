Room and User Statistics
========================

Synapse maintains room and user statistics in various tables. These can be used
for administrative purposes but are also used when generating the public room
directory.


# Synapse Developer Documentation

## High-Level Concepts

### Definitions

* **subject**: Something we are tracking stats about – currently a room or user.
* **current row**: An entry for a subject in the appropriate current statistics
    table. Each subject can have only one.

### Overview

Stats correspond to the present values. Current rows contain the most up-to-date
statistics for a room. Each subject can only have one entry.
