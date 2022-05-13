# Background update controller callbacks

Background update controller callbacks allow module developers to control (e.g. rate-limit)
how database background updates are run. A database background update is an operation
Synapse runs on its database in the background after it starts. It's usually used to run
database operations that would take too long if they were run at the same time as schema
updates (which are run on startup) and delay Synapse's startup too much: populating a
table with a big amount of data, adding an index on a big table, deleting superfluous data,
etc.

Background update controller callbacks can be registered using the module API's
`register_background_update_controller_callbacks` method. Only the first module (in order
of appearance in Synapse's configuration file) calling this method can register background
update controller callbacks, subsequent calls are ignored.

The available background update controller callbacks are:

### `on_update`

_First introduced in Synapse v1.49.0_

```python
def on_update(update_name: str, database_name: str, one_shot: bool) -> AsyncContextManager[int]
```

Called when about to do an iteration of a background update. The module is given the name
of the update, the name of the database, and a flag to indicate whether the background
update will happen in one go and may take a long time (e.g. creating indices). If this last
argument is set to `False`, the update will be run in batches.

The module must return an async context manager. It will be entered before Synapse runs a 
background update; this should return the desired duration of the iteration, in
milliseconds.

The context manager will be exited when the iteration completes. Note that the duration
returned by the context manager is a target, and an iteration may take substantially longer
or shorter. If the `one_shot` flag is set to `True`, the duration returned is ignored.

__Note__: Unlike most module callbacks in Synapse, this one is _synchronous_. This is
because asynchronous operations are expected to be run by the async context manager.

This callback is required when registering any other background update controller callback.

### `default_batch_size`

_First introduced in Synapse v1.49.0_

```python
async def default_batch_size(update_name: str, database_name: str) -> int
```

Called before the first iteration of a background update, with the name of the update and
of the database. The module must return the number of elements to process in this first
iteration.

If this callback is not defined, Synapse will use a default value of 100.

### `min_batch_size`

_First introduced in Synapse v1.49.0_

```python
async def min_batch_size(update_name: str, database_name: str) -> int
```

Called before running a new batch for a background update, with the name of the update and
of the database. The module must return an integer representing the minimum number of
elements to process in this iteration. This number must be at least 1, and is used to
ensure that progress is always made.

If this callback is not defined, Synapse will use a default value of 100.
