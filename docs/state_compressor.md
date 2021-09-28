# State compressor

The state compressor is an **experimental** tool that attempts to reduce the number of rows 
in the `state_groups_state` table inside of a postgres database. Documentation on how it works
can be found on [its github repository](https://github.com/matrix-org/rust-synapse-compress-state).

## Enabling the state compressor

The state compressor requires the python library for the `synapse_auto_compressor` tool to be 
installed. This can be done with pip or by following the instructions for this can be found in [the `python.md` file in the source
repo](https://github.com/matrix-org/rust-synapse-compress-state/blob/main/docs/python.md).

The following configuration options are provided:

- `chunk_size`  
The number of state groups to work on at once. All of the entries from 
`state_groups_state` are requested from the database for state groups that are 
worked on. Therefore small chunk sizes may be needed on machines with low memory. 
Note: if the compressor fails to find space savings on the chunk as a whole 
(which may well happen in rooms with lots of backfill in) then the entire chunk 
is skipped. This defaults to 500 
  
- `number_of_chunks`  
The compressor will stop once it has finished compressing this many chunks. Defaults to 100

- `default_levels`  
Sizes of each new level in the compression algorithm, as a comma separated list.
The first entry in the list is for the lowest, most granular level, with each 
subsequent entry being for the next highest level. The number of entries in the
list determines the number of levels that will be used. The sum of the sizes of
the levels effect the performance of fetching the state from the database, as the
sum of the sizes is the upper bound on number of iterations needed to fetch a
given set of state. This defaults to "100,50,25"

- `time_between_runs`
This controls how often the state compressor is run. This defaults to once every
day.

An example configuration:
```yaml
state_compressor:
    enabled: true
    chunk_size: 500
    number_of_chunks: 50
    default_levels: 100,50,25
    time_between_runs: 1d
```