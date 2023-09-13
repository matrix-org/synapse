# Log Contexts

To help track the processing of individual requests, synapse uses a
'`log context`' to track which request it is handling at any given
moment. This is done via a thread-local variable; a `logging.Filter` is
then used to fish the information back out of the thread-local variable
and add it to each log record.

Logcontexts are also used for CPU and database accounting, so that we
can track which requests were responsible for high CPU use or database
activity.

The `synapse.logging.context` module provides facilities for managing
the current log context (as well as providing the `LoggingContextFilter`
class).

Asynchronous functions make the whole thing complicated, so this document describes
how it all works, and how to write code which follows the rules.

In this document, "awaitable" refers to any object which can be `await`ed. In the context of
Synapse, that normally means either a coroutine or a Twisted 
[`Deferred`](https://twistedmatrix.com/documents/current/api/twisted.internet.defer.Deferred.html).

## Logcontexts without asynchronous code

In the absence of any asynchronous voodoo, things are simple enough. As with
any code of this nature, the rule is that our function should leave
things as it found them:

```python
from synapse.logging import context         # omitted from future snippets

def handle_request(request_id):
    request_context = context.LoggingContext()

    calling_context = context.set_current_context(request_context)
    try:
        request_context.request = request_id
        do_request_handling()
        logger.debug("finished")
    finally:
        context.set_current_context(calling_context)

def do_request_handling():
    logger.debug("phew")  # this will be logged against request_id
```

LoggingContext implements the context management methods, so the above
can be written much more succinctly as:

```python
def handle_request(request_id):
    with context.LoggingContext() as request_context:
        request_context.request = request_id
        do_request_handling()
        logger.debug("finished")

def do_request_handling():
    logger.debug("phew")
```

## Using logcontexts with awaitables

Awaitables break the linear flow of code so that there is no longer a single entry point
where we should set the logcontext and a single exit point where we should remove it.

Consider the example above, where `do_request_handling` needs to do some
blocking operation, and returns an awaitable:

```python
async def handle_request(request_id):
    with context.LoggingContext() as request_context:
        request_context.request = request_id
        await do_request_handling()
        logger.debug("finished")
```

In the above flow:

-   The logcontext is set
-   `do_request_handling` is called, and returns an awaitable
-   `handle_request` awaits the awaitable
-   Execution of `handle_request` is suspended

So we have stopped processing the request (and will probably go on to
start processing the next), without clearing the logcontext.

To circumvent this problem, synapse code assumes that, wherever you have
an awaitable, you will want to `await` it. To that end, wherever
functions return awaitables, we adopt the following conventions:

**Rules for functions returning awaitables:**

> -   If the awaitable is already complete, the function returns with the
>     same logcontext it started with.
> -   If the awaitable is incomplete, the function clears the logcontext
>     before returning; when the awaitable completes, it restores the
>     logcontext before running any callbacks.

That sounds complicated, but actually it means a lot of code (including
the example above) "just works". There are two cases:

-   If `do_request_handling` returns a completed awaitable, then the
    logcontext will still be in place. In this case, execution will
    continue immediately after the `await`; the "finished" line will
    be logged against the right context, and the `with` block restores
    the original context before we return to the caller.
-   If the returned awaitable is incomplete, `do_request_handling` clears
    the logcontext before returning. The logcontext is therefore clear
    when `handle_request` `await`s the awaitable.

    Once `do_request_handling`'s awaitable completes, it will reinstate
    the logcontext, before running the second half of `handle_request`,
    so again the "finished" line will be logged against the right context,
    and the `with` block restores the original context.

As an aside, it's worth noting that `handle_request` follows our rules
- though that only matters if the caller has its own logcontext which it
cares about.

The following sections describe pitfalls and helpful patterns when
implementing these rules.

Always await your awaitables
----------------------------

Whenever you get an awaitable back from a function, you should `await` on
it as soon as possible. Do not pass go; do not do any logging; do not
call any other functions.

```python
async def fun():
    logger.debug("starting")
    await do_some_stuff()       # just like this

    coro = more_stuff()
    result = await coro         # also fine, of course

    return result
```

Provided this pattern is followed all the way back up to the callchain
to where the logcontext was set, this will make things work out ok:
provided `do_some_stuff` and `more_stuff` follow the rules above, then
so will `fun`.

It's all too easy to forget to `await`: for instance if we forgot that
`do_some_stuff` returned an awaitable, we might plough on regardless. This
leads to a mess; it will probably work itself out eventually, but not
before a load of stuff has been logged against the wrong context.
(Normally, other things will break, more obviously, if you forget to
`await`, so this tends not to be a major problem in practice.)

Of course sometimes you need to do something a bit fancier with your
awaitable - not all code follows the linear A-then-B-then-C pattern.
Notes on implementing more complex patterns are in later sections.

## Where you create a new awaitable, make it follow the rules

Most of the time, an awaitable comes from another synapse function.
Sometimes, though, we need to make up a new awaitable, or we get an awaitable
back from external code. We need to make it follow our rules.

The easy way to do it is by using `context.make_deferred_yieldable`. Suppose we want to implement
`sleep`, which returns a deferred which will run its callbacks after a
given number of seconds. That might look like:

```python
# not a logcontext-rules-compliant function
def get_sleep_deferred(seconds):
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, None)
    return d
```

That doesn't follow the rules, but we can fix it by calling it through
`context.make_deferred_yieldable`:

```python
async def sleep(seconds):
    return await context.make_deferred_yieldable(get_sleep_deferred(seconds))
```

## Fire-and-forget

Sometimes you want to fire off a chain of execution, but not wait for
its result. That might look a bit like this:

```python
async def do_request_handling():
    await foreground_operation()

    # *don't* do this
    background_operation()

    logger.debug("Request handling complete")

async def background_operation():
    await first_background_step()
    logger.debug("Completed first step")
    await second_background_step()
    logger.debug("Completed second step")
```

The above code does a couple of steps in the background after
`do_request_handling` has finished. The log lines are still logged
against the `request_context` logcontext, which may or may not be
desirable. There are two big problems with the above, however. The first
problem is that, if `background_operation` returns an incomplete
awaitable, it will expect its caller to `await` immediately, so will have
cleared the logcontext. In this example, that means that 'Request
handling complete' will be logged without any context.

The second problem, which is potentially even worse, is that when the
awaitable returned by `background_operation` completes, it will restore
the original logcontext. There is nothing waiting on that awaitable, so
the logcontext will leak into the reactor and possibly get attached to
some arbitrary future operation.

There are two potential solutions to this.

One option is to surround the call to `background_operation` with a
`PreserveLoggingContext` call. That will reset the logcontext before
starting `background_operation` (so the context restored when the
deferred completes will be the empty logcontext), and will restore the
current logcontext before continuing the foreground process:

```python
async def do_request_handling():
    await foreground_operation()

    # start background_operation off in the empty logcontext, to
    # avoid leaking the current context into the reactor.
    with PreserveLoggingContext():
        background_operation()

    # this will now be logged against the request context
    logger.debug("Request handling complete")
```

Obviously that option means that the operations done in
`background_operation` would be not be logged against a logcontext
(though that might be fixed by setting a different logcontext via a
`with LoggingContext(...)` in `background_operation`).

The second option is to use `context.run_in_background`, which wraps a
function so that it doesn't reset the logcontext even when it returns
an incomplete awaitable, and adds a callback to the returned awaitable to
reset the logcontext. In other words, it turns a function that follows
the Synapse rules about logcontexts and awaitables into one which behaves
more like an external function --- the opposite operation to that
described in the previous section. It can be used like this:

```python
async def do_request_handling():
    await foreground_operation()

    context.run_in_background(background_operation)

    # this will now be logged against the request context
    logger.debug("Request handling complete")
```

## Passing synapse deferreds into third-party functions

A typical example of this is where we want to collect together two or
more awaitables via `defer.gatherResults`:

```python
a1 = operation1()
a2 = operation2()
a3 = defer.gatherResults([a1, a2])
```

This is really a variation of the fire-and-forget problem above, in that
we are firing off `a1` and `a2` without awaiting on them. The difference
is that we now have third-party code attached to their callbacks. Anyway
either technique given in the [Fire-and-forget](#fire-and-forget)
section will work.

Of course, the new awaitable returned by `gather` needs to be
wrapped in order to make it follow the logcontext rules before we can
yield it, as described in [Where you create a new awaitable, make it
follow the
rules](#where-you-create-a-new-awaitable-make-it-follow-the-rules).

So, option one: reset the logcontext before starting the operations to
be gathered:

```python
async def do_request_handling():
    with PreserveLoggingContext():
        a1 = operation1()
        a2 = operation2()
        result = await defer.gatherResults([a1, a2])
```

In this case particularly, though, option two, of using
`context.run_in_background` almost certainly makes more sense, so that
`operation1` and `operation2` are both logged against the original
logcontext. This looks like:

```python
async def do_request_handling():
    a1 = context.run_in_background(operation1)
    a2 = context.run_in_background(operation2)

    result = await make_deferred_yieldable(defer.gatherResults([a1, a2]))
```

## A note on garbage-collection of awaitable chains

It turns out that our logcontext rules do not play nicely with awaitable
chains which get orphaned and garbage-collected.

Imagine we have some code that looks like this:

```python
listener_queue = []

def on_something_interesting():
    for d in listener_queue:
        d.callback("foo")

async def await_something_interesting():
    new_awaitable = defer.Deferred()
    listener_queue.append(new_awaitable)

    with PreserveLoggingContext():
        await new_awaitable
```

Obviously, the idea here is that we have a bunch of things which are
waiting for an event. (It's just an example of the problem here, but a
relatively common one.)

Now let's imagine two further things happen. First of all, whatever was
waiting for the interesting thing goes away. (Perhaps the request times
out, or something *even more* interesting happens.)

Secondly, let's suppose that we decide that the interesting thing is
never going to happen, and we reset the listener queue:

```python
def reset_listener_queue():
    listener_queue.clear()
```

So, both ends of the awaitable chain have now dropped their references,
and the awaitable chain is now orphaned, and will be garbage-collected at
some point. Note that `await_something_interesting` is a coroutine, 
which Python implements as a generator function.  When Python
garbage-collects generator functions, it gives them a chance to 
clean up by making the `await` (or `yield`) raise a `GeneratorExit`
exception. In our case, that means that the `__exit__` handler of
`PreserveLoggingContext` will carefully restore the request context, but
there is now nothing waiting for its return, so the request context is
never cleared.

To reiterate, this problem only arises when *both* ends of a awaitable
chain are dropped. Dropping the the reference to an awaitable you're
supposed to be awaiting is bad practice, so this doesn't
actually happen too much. Unfortunately, when it does happen, it will
lead to leaked logcontexts which are incredibly hard to track down.
