Log contexts
============

.. contents::

To help track the processing of individual requests, synapse uses a
'log context' to track which request it is handling at any given moment. This
is done via a thread-local variable; a ``logging.Filter`` is then used to fish
the information back out of the thread-local variable and add it to each log
record.

Logcontexts are also used for CPU and database accounting, so that we can track
which requests were responsible for high CPU use or database activity.

The ``synapse.util.logcontext`` module provides a facilities for managing the
current log context (as well as providing the ``LoggingContextFilter`` class).

Deferreds make the whole thing complicated, so this document describes how it
all works, and how to write code which follows the rules.

Logcontexts without Deferreds
-----------------------------

In the absence of any Deferred voodoo, things are simple enough. As with any
code of this nature, the rule is that our function should leave things as it
found them:

.. code:: python

    from synapse.util import logcontext         # omitted from future snippets

    def handle_request(request_id):
        request_context = logcontext.LoggingContext()

        calling_context = logcontext.LoggingContext.current_context()
        logcontext.LoggingContext.set_current_context(request_context)
        try:
            request_context.request = request_id
            do_request_handling()
            logger.debug("finished")
        finally:
            logcontext.LoggingContext.set_current_context(calling_context)

    def do_request_handling():
        logger.debug("phew")  # this will be logged against request_id


LoggingContext implements the context management methods, so the above can be
written much more succinctly as:

.. code:: python

    def handle_request(request_id):
        with logcontext.LoggingContext() as request_context:
            request_context.request = request_id
            do_request_handling()
            logger.debug("finished")

    def do_request_handling():
        logger.debug("phew")


Using logcontexts with Deferreds
--------------------------------

Deferreds — and in particular, ``defer.inlineCallbacks`` — break
the linear flow of code so that there is no longer a single entry point where
we should set the logcontext and a single exit point where we should remove it.

Consider the example above, where ``do_request_handling`` needs to do some
blocking operation, and returns a deferred:

.. code:: python

    @defer.inlineCallbacks
    def handle_request(request_id):
        with logcontext.LoggingContext() as request_context:
            request_context.request = request_id
            yield do_request_handling()
            logger.debug("finished")


In the above flow:

* The logcontext is set
* ``do_request_handling`` is called, and returns a deferred
* ``handle_request`` yields the deferred
* The ``inlineCallbacks`` wrapper of ``handle_request`` returns a deferred

So we have stopped processing the request (and will probably go on to start
processing the next), without clearing the logcontext.

To circumvent this problem, synapse code assumes that, wherever you have a
deferred, you will want to yield on it. To that end, whereever functions return
a deferred, we adopt the following conventions:

**Rules for functions returning deferreds:**

  * If the deferred is already complete, the function returns with the same
    logcontext it started with.
  * If the deferred is incomplete, the function clears the logcontext before
    returning; when the deferred completes, it restores the logcontext before
    running any callbacks.

That sounds complicated, but actually it means a lot of code (including the
example above) "just works". There are two cases:

* If ``do_request_handling`` returns a completed deferred, then the logcontext
  will still be in place. In this case, execution will continue immediately
  after the ``yield``; the "finished" line will be logged against the right
  context, and the ``with`` block restores the original context before we
  return to the caller.

* If the returned deferred is incomplete, ``do_request_handling`` clears the
  logcontext before returning. The logcontext is therefore clear when
  ``handle_request`` yields the deferred. At that point, the ``inlineCallbacks``
  wrapper adds a callback to the deferred, and returns another (incomplete)
  deferred to the caller, and it is safe to begin processing the next request.

  Once ``do_request_handling``'s deferred completes, it will reinstate the
  logcontext, before running the callback added by the ``inlineCallbacks``
  wrapper. That callback runs the second half of ``handle_request``, so again
  the "finished" line will be logged against the right
  context, and the ``with`` block restores the original context.

As an aside, it's worth noting that ``handle_request`` follows our rules -
though that only matters if the caller has its own logcontext which it cares
about.

The following sections describe pitfalls and helpful patterns when implementing
these rules.

Always yield your deferreds
---------------------------

Whenever you get a deferred back from a function, you should ``yield`` on it
as soon as possible. (Returning it directly to your caller is ok too, if you're
not doing ``inlineCallbacks``.) Do not pass go; do not do any logging; do not
call any other functions.

.. code:: python

    @defer.inlineCallbacks
    def fun():
        logger.debug("starting")
        yield do_some_stuff()       # just like this

        d = more_stuff()
        result = yield d            # also fine, of course

        defer.returnValue(result)

    def nonInlineCallbacksFun():
        logger.debug("just a wrapper really")
        return do_some_stuff()      # this is ok too - the caller will yield on
                                    # it anyway.

Provided this pattern is followed all the way back up to the callchain to where
the logcontext was set, this will make things work out ok: provided
``do_some_stuff`` and ``more_stuff`` follow the rules above, then so will
``fun`` (as wrapped by ``inlineCallbacks``) and ``nonInlineCallbacksFun``.

It's all too easy to forget to ``yield``: for instance if we forgot that
``do_some_stuff`` returned a deferred, we might plough on regardless. This
leads to a mess; it will probably work itself out eventually, but not before
a load of stuff has been logged against the wrong content. (Normally, other
things will break, more obviously, if you forget to ``yield``, so this tends
not to be a major problem in practice.)

Of course sometimes you need to do something a bit fancier with your Deferreds
- not all code follows the linear A-then-B-then-C pattern. Notes on
implementing more complex patterns are in later sections.

Where you create a new Deferred, make it follow the rules
---------------------------------------------------------

Most of the time, a Deferred comes from another synapse function. Sometimes,
though, we need to make up a new Deferred, or we get a Deferred back from
external code. We need to make it follow our rules.

The easy way to do it is with a combination of ``defer.inlineCallbacks``, and
``logcontext.PreserveLoggingContext``. Suppose we want to implement ``sleep``,
which returns a deferred which will run its callbacks after a given number of
seconds. That might look like:

.. code:: python

    # not a logcontext-rules-compliant function
    def get_sleep_deferred(seconds):
        d = defer.Deferred()
        reactor.callLater(seconds, d.callback, None)
        return d

That doesn't follow the rules, but we can fix it by wrapping it with
``PreserveLoggingContext`` and ``yield`` ing on it:

.. code:: python

    @defer.inlineCallbacks
    def sleep(seconds):
        with PreserveLoggingContext():
            yield get_sleep_deferred(seconds)

This technique works equally for external functions which return deferreds,
or deferreds we have made ourselves.

You can also use ``logcontext.make_deferred_yieldable``, which just does the
boilerplate for you, so the above could be written:

.. code:: python

    def sleep(seconds):
        return logcontext.make_deferred_yieldable(get_sleep_deferred(seconds))


Fire-and-forget
---------------

Sometimes you want to fire off a chain of execution, but not wait for its
result. That might look a bit like this:

.. code:: python

    @defer.inlineCallbacks
    def do_request_handling():
        yield foreground_operation()

        # *don't* do this
        background_operation()

        logger.debug("Request handling complete")

    @defer.inlineCallbacks
    def background_operation():
        yield first_background_step()
        logger.debug("Completed first step")
        yield second_background_step()
        logger.debug("Completed second step")

The above code does a couple of steps in the background after
``do_request_handling`` has finished. The log lines are still logged against
the ``request_context`` logcontext, which may or may not be desirable. There
are two big problems with the above, however. The first problem is that, if
``background_operation`` returns an incomplete Deferred, it will expect its
caller to ``yield`` immediately, so will have cleared the logcontext. In this
example, that means that 'Request handling complete' will be logged without any
context.

The second problem, which is potentially even worse, is that when the Deferred
returned by ``background_operation`` completes, it will restore the original
logcontext. There is nothing waiting on that Deferred, so the logcontext will
leak into the reactor and possibly get attached to some arbitrary future
operation.

There are two potential solutions to this.

One option is to surround the call to ``background_operation`` with a
``PreserveLoggingContext`` call. That will reset the logcontext before
starting ``background_operation`` (so the context restored when the deferred
completes will be the empty logcontext), and will restore the current
logcontext before continuing the foreground process:

.. code:: python

    @defer.inlineCallbacks
    def do_request_handling():
        yield foreground_operation()

        # start background_operation off in the empty logcontext, to
        # avoid leaking the current context into the reactor.
        with PreserveLoggingContext():
            background_operation()

        # this will now be logged against the request context
        logger.debug("Request handling complete")

Obviously that option means that the operations done in
``background_operation`` would be not be logged against a logcontext (though
that might be fixed by setting a different logcontext via a ``with
LoggingContext(...)`` in ``background_operation``).

The second option is to use ``logcontext.preserve_fn``, which wraps a function
so that it doesn't reset the logcontext even when it returns an incomplete
deferred, and adds a callback to the returned deferred to reset the
logcontext. In other words, it turns a function that follows the Synapse rules
about logcontexts and Deferreds into one which behaves more like an external
function — the opposite operation to that described in the previous section.
It can be used like this:

.. code:: python

    @defer.inlineCallbacks
    def do_request_handling():
        yield foreground_operation()

        logcontext.preserve_fn(background_operation)()

        # this will now be logged against the request context
        logger.debug("Request handling complete")

XXX: I think ``preserve_context_over_fn`` is supposed to do the first option,
but the fact that it does ``preserve_context_over_deferred`` on its results
means that its use is fraught with difficulty.

Passing synapse deferreds into third-party functions
----------------------------------------------------

A typical example of this is where we want to collect together two or more
deferred via ``defer.gatherResults``:

.. code:: python

    d1 = operation1()
    d2 = operation2()
    d3 = defer.gatherResults([d1, d2])

This is really a variation of the fire-and-forget problem above, in that we are
firing off ``d1`` and ``d2`` without yielding on them. The difference
is that we now have third-party code attached to their callbacks. Anyway either
technique given in the `Fire-and-forget`_ section will work.

Of course, the new Deferred returned by ``gatherResults`` needs to be wrapped
in order to make it follow the logcontext rules before we can yield it, as
described in `Where you create a new Deferred, make it follow the rules`_.

So, option one: reset the logcontext before starting the operations to be
gathered:

.. code:: python

    @defer.inlineCallbacks
    def do_request_handling():
        with PreserveLoggingContext():
            d1 = operation1()
            d2 = operation2()
            result = yield defer.gatherResults([d1, d2])

In this case particularly, though, option two, of using
``logcontext.preserve_fn`` almost certainly makes more sense, so that
``operation1`` and ``operation2`` are both logged against the original
logcontext. This looks like:

.. code:: python

    @defer.inlineCallbacks
    def do_request_handling():
        d1 = logcontext.preserve_fn(operation1)()
        d2 = logcontext.preserve_fn(operation2)()

        with PreserveLoggingContext():
            result = yield defer.gatherResults([d1, d2])


Was all this really necessary?
------------------------------

The conventions used work fine for a linear flow where everything happens in
series via ``defer.inlineCallbacks`` and ``yield``, but are certainly tricky to
follow for any more exotic flows. It's hard not to wonder if we could have done
something else.

We're not going to rewrite Synapse now, so the following is entirely of
academic interest, but I'd like to record some thoughts on an alternative
approach.

I briefly prototyped some code following an alternative set of rules. I think
it would work, but I certainly didn't get as far as thinking how it would
interact with concepts as complicated as the cache descriptors.

My alternative rules were:

* functions always preserve the logcontext of their caller, whether or not they
  are returning a Deferred.

* Deferreds returned by synapse functions run their callbacks in the same
  context as the function was orignally called in.

The main point of this scheme is that everywhere that sets the logcontext is
responsible for clearing it before returning control to the reactor.

So, for example, if you were the function which started a ``with
LoggingContext`` block, you wouldn't ``yield`` within it — instead you'd start
off the background process, and then leave the ``with`` block to wait for it:

.. code:: python

    def handle_request(request_id):
        with logcontext.LoggingContext() as request_context:
            request_context.request = request_id
            d = do_request_handling()

        def cb(r):
            logger.debug("finished")

        d.addCallback(cb)
        return d

(in general, mixing ``with LoggingContext`` blocks and
``defer.inlineCallbacks`` in the same function leads to slighly
counter-intuitive code, under this scheme).

Because we leave the original ``with`` block as soon as the Deferred is
returned (as opposed to waiting for it to be resolved, as we do today), the
logcontext is cleared before control passes back to the reactor; so if there is
some code within ``do_request_handling`` which needs to wait for a Deferred to
complete, there is no need for it to worry about clearing the logcontext before
doing so:

.. code:: python

    def handle_request():
        r = do_some_stuff()
        r.addCallback(do_some_more_stuff)
        return r

— and provided ``do_some_stuff`` follows the rules of returning a Deferred which
runs its callbacks in the original logcontext, all is happy.

The business of a Deferred which runs its callbacks in the original logcontext
isn't hard to achieve — we have it today, in the shape of
``logcontext._PreservingContextDeferred``:

.. code:: python

    def do_some_stuff():
        deferred = do_some_io()
        pcd = _PreservingContextDeferred(LoggingContext.current_context())
        deferred.chainDeferred(pcd)
        return pcd

It turns out that, thanks to the way that Deferreds chain together, we
automatically get the property of a context-preserving deferred with
``defer.inlineCallbacks``, provided the final Defered the function ``yields``
on has that property. So we can just write:

.. code:: python

    @defer.inlineCallbacks
    def handle_request():
        yield do_some_stuff()
        yield do_some_more_stuff()

To conclude: I think this scheme would have worked equally well, with less
danger of messing it up, and probably made some more esoteric code easier to
write. But again — changing the conventions of the entire Synapse codebase is
not a sensible option for the marginal improvement offered.
