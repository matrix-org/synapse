# Cancellation
Sometimes, requests take a long time to service and clients disconnect
before Synapse produces a response. To avoid wasting resources, Synapse
can cancel request processing for select endpoints marked with the
`@cancellable` decorator.

Synapse makes use of Twisted's `Deferred.cancel()` feature to make
cancellation work. The `@cancellable` decorator does nothing by itself
and merely acts as a flag, signalling to developers and other code alike
that a method can be cancelled.

## Enabling cancellation for an endpoint
1. Check that the endpoint method, and any `async` functions in its call
   tree handle cancellation correctly. See
   [Handling cancellation correctly](#handling-cancellation-correctly)
   for a list of things to look out for.
2. Add the `@cancellable` decorator to the `on_GET/POST/PUT/DELETE`
   method. It's not recommended to make non-`GET` methods cancellable,
   since cancellation midway through some database updates is less
   likely to be handled correctly.

## Mechanics
There are two stages to cancellation: downward propagation of a
`cancel()` call, followed by upwards propagation of a `CancelledError`
out of a blocked `await`.
Both Twisted and asyncio have a cancellation mechanism.

|               | Method              | Exception                               | Exception inherits from |
|---------------|---------------------|-----------------------------------------|-------------------------|
| Twisted       | `Deferred.cancel()` | `twisted.internet.defer.CancelledError` | `Exception` (!)         |
| asyncio       | `Task.cancel()`     | `asyncio.CancelledError`                | `BaseException`         |

### Deferred.cancel()
When Synapse starts handling a request, it runs the async method
responsible for handling it using `defer.ensureDeferred`, which returns
a `Deferred`. For example:

```python
def do_something() -> Deferred[None]:
    ...

@cancellable
async def on_GET() -> Tuple[int, JsonDict]:
    d = make_deferred_yieldable(do_something())
    await d
    return 200, {}

request = defer.ensureDeferred(on_GET())
```

When a client disconnects early, Synapse checks for the presence of the
`@cancellable` decorator on `on_GET`. Since `on_GET` is cancellable,
`Deferred.cancel()` is called on the `Deferred` from
`defer.ensureDeferred`, ie. `request`. Twisted knows which `Deferred`
`request` is waiting on and passes the `cancel()` call on to `d`.

The `Deferred` being waited on, `d`, may have its own handling for
`cancel()` and pass the call on to other `Deferred`s.

Eventually, a `Deferred` handles the `cancel()` call by resolving itself
with a `CancelledError`.

### CancelledError
The `CancelledError` gets raised out of the `await` and bubbles up, as
per normal Python exception handling.

## Handling cancellation correctly
In general, when writing code that might be subject to cancellation, two
things must be considered:
 * The effect of `CancelledError`s raised out of `await`s.
 * The effect of `Deferred`s being `cancel()`ed.

Examples of code that handles cancellation incorrectly include:
 * `try-except` blocks which swallow `CancelledError`s.
 * Code that shares the same `Deferred`, which may be cancelled, between
   multiple requests.
 * Code that starts some processing that's exempt from cancellation, but
   uses a logging context from cancellable code. The logging context
   will be finished upon cancellation, while the uncancelled processing
   is still using it.

Some common patterns are listed below in more detail.

### `async` function calls
Most functions in Synapse are relatively straightforward from a
cancellation standpoint: they don't do anything with `Deferred`s and
purely call and `await` other `async` functions.

An `async` function handles cancellation correctly if its own code
handles cancellation correctly and all the async function it calls
handle cancellation correctly. For example:
```python
async def do_two_things() -> None:
    check_something()
    await do_something()
    await do_something_else()
```
`do_two_things` handles cancellation correctly if `do_something` and
`do_something_else` handle cancellation correctly.

That is, when checking whether a function handles cancellation
correctly, its implementation and all its `async` function calls need to
be checked, recursively.

As `check_something` is not `async`, it does not need to be checked.

### CancelledErrors
Because Twisted's `CancelledError`s are `Exception`s, it's easy to
accidentally catch and suppress them. Care must be taken to ensure that
`CancelledError`s are allowed to propagate upwards.

<table width="100%">
<tr>
<td width="50%" valign="top">

**Bad**:
```python
try:
    await do_something()
except Exception:
    # `CancelledError` gets swallowed here.
    logger.info(...)
```
</td>
<td width="50%" valign="top">

**Good**:
```python
try:
    await do_something()
except CancelledError:
    raise
except Exception:
    logger.info(...)
```
</td>
</tr>
<tr>
<td width="50%" valign="top">

**OK**:
```python
try:
    check_something()
    # A `CancelledError` won't ever be raised here.
except Exception:
    logger.info(...)
```
</td>
<td width="50%" valign="top">

**Good**:
```python
try:
    await do_something()
except ValueError:
    logger.info(...)
```
</td>
</tr>
</table>

#### defer.gatherResults
`defer.gatherResults` produces a `Deferred` which:
 * broadcasts `cancel()` calls to every `Deferred` being waited on.
 * wraps the first exception it sees in a `FirstError`.

Together, this means that `CancelledError`s will be wrapped in
a `FirstError` unless unwrapped. Such `FirstError`s are liable to be
swallowed, so they must be unwrapped.

<table width="100%">
<tr>
<td width="50%" valign="top">

**Bad**:
```python
async def do_something() -> None:
    await make_deferred_yieldable(
        defer.gatherResults([...], consumeErrors=True)
    )

try:
    await do_something()
except CancelledError:
    raise
except Exception:
    # `FirstError(CancelledError)` gets swallowed here.
    logger.info(...)
```

</td>
<td width="50%" valign="top">

**Good**:
```python
async def do_something() -> None:
    await make_deferred_yieldable(
        defer.gatherResults([...], consumeErrors=True)
    ).addErrback(unwrapFirstError)

try:
    await do_something()
except CancelledError:
    raise
except Exception:
    logger.info(...)
```
</td>
</tr>
</table>

### Creation of `Deferred`s
If a function creates a `Deferred`, the effect of cancelling it must be considered. `Deferred`s that get shared are likely to have unintended behaviour when cancelled.

<table width="100%">
<tr>
<td width="50%" valign="top">

**Bad**:
```python
cache: Dict[str, Deferred[None]] = {}

def wait_for_room(room_id: str) -> Deferred[None]:
    deferred = cache.get(room_id)
    if deferred is None:
        deferred = Deferred()
        cache[room_id] = deferred
    # `deferred` can have multiple waiters.
    # All of them will observe a `CancelledError`
    # if any one of them is cancelled.
    return make_deferred_yieldable(deferred)

# Request 1
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
# Request 2
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
```
</td>
<td width="50%" valign="top">

**Good**:
```python
cache: Dict[str, Deferred[None]] = {}

def wait_for_room(room_id: str) -> Deferred[None]:
    deferred = cache.get(room_id)
    if deferred is None:
        deferred = Deferred()
        cache[room_id] = deferred
    # `deferred` will never be cancelled now.
    # A `CancelledError` will still come out of
    # the `await`.
    # `delay_cancellation` may also be used.
    return make_deferred_yieldable(stop_cancellation(deferred))

# Request 1
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
# Request 2
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
```
</td>
</tr>
<tr>
<td width="50%" valign="top">
</td>
<td width="50%" valign="top">

**Good**:
```python
cache: Dict[str, List[Deferred[None]]] = {}

def wait_for_room(room_id: str) -> Deferred[None]:
    if room_id not in cache:
        cache[room_id] = []
    # Each request gets its own `Deferred` to wait on.
    deferred = Deferred()
    cache[room_id]].append(deferred)
    return make_deferred_yieldable(deferred)

# Request 1
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
# Request 2
await wait_for_room("!aAAaaAaaaAAAaAaAA:matrix.org")
```
</td>
</table>

### Uncancelled processing
Some `async` functions may kick off some `async` processing which is
intentionally protected from cancellation, by `stop_cancellation` or
other means. If the `async` processing inherits the logcontext of the
request which initiated it, care must be taken to ensure that the
logcontext is not finished before the `async` processing completes.

<table width="100%">
<tr>
<td width="50%" valign="top">

**Bad**:
```python
cache: Optional[ObservableDeferred[None]] = None

async def do_something_else(
    to_resolve: Deferred[None]
) -> None:
    await ...
    logger.info("done!")
    to_resolve.callback(None)

async def do_something() -> None:
    if not cache:
        to_resolve = Deferred()
        cache = ObservableDeferred(to_resolve)
        # `do_something_else` will never be cancelled and
        # can outlive the `request-1` logging context.
        run_in_background(do_something_else, to_resolve)

    await make_deferred_yieldable(cache.observe())

with LoggingContext("request-1"):
    await do_something()
```
</td>
<td width="50%" valign="top">

**Good**:
```python
cache: Optional[ObservableDeferred[None]] = None

async def do_something_else(
    to_resolve: Deferred[None]
) -> None:
    await ...
    logger.info("done!")
    to_resolve.callback(None)

async def do_something() -> None:
    if not cache:
        to_resolve = Deferred()
        cache = ObservableDeferred(to_resolve)
        run_in_background(do_something_else, to_resolve)
        # We'll wait until `do_something_else` is
        # done before raising a `CancelledError`.
        await make_deferred_yieldable(
            delay_cancellation(cache.observe())
        )
    else:
        await make_deferred_yieldable(cache.observe())

with LoggingContext("request-1"):
    await do_something()
```
</td>
</tr>
<tr>
<td width="50%">

**OK**:
```python
cache: Optional[ObservableDeferred[None]] = None

async def do_something_else(
    to_resolve: Deferred[None]
) -> None:
    await ...
    logger.info("done!")
    to_resolve.callback(None)

async def do_something() -> None:
    if not cache:
        to_resolve = Deferred()
        cache = ObservableDeferred(to_resolve)
        # `do_something_else` will get its own independent
        # logging context. `request-1` will not count any
        # metrics from `do_something_else`.
        run_as_background_process(
            "do_something_else",
            do_something_else,
            to_resolve,
        )

    await make_deferred_yieldable(cache.observe())

with LoggingContext("request-1"):
    await do_something()
```
</td>
<td width="50%">
</td>
</tr>
</table>
