===========
OpenTracing
===========

Background
----------

OpenTracing is a semi-standard being adopted by a number of distributed tracing
platforms. It is a common api for facilitating vendor-agnostic tracing
instrumentation. That is, we can use the OpenTracing api and select one of a
number of tracer implementations to do the heavy lifting in the background.
Our current selected implementation is Jaeger.

OpenTracing is a tool which gives an insight into the causal relationship of
work done in and between servers. The servers each track events and report them
to a centralised server - in our Synapse's case: Jaeger. The basic unit used to
represent events is the span. The span roughly represents a single piece of work
that was done and the time at which it occurred. A span can have child spans,
meaning that the work of the child had to be completed for the parent span to
complete, or it can have follow-on spans which represent work that is undertaken
as a result of the parent but is not depended on by the parent to in order to
finish.

Since this is undertaken in a distributed environment a request to another
server, such as an RPC or a simple GET, can be considered a span (a unit or
work) for the local server. This causal link is what OpenTracing aims to
capture and visualise. In order to do this metadata about the local server's
span, i.e the 'span context', needs to be included with the request to the
remote.

It is up to the remote server to decide what it does with the spans
it creates. This is called the sampling policy and it can be configured
through Jaeger's settings.

For OpenTracing concepts see 
https://opentracing.io/docs/overview/what-is-tracing/.

For more information about Jaeger's implementation see
https://www.jaegertracing.io/docs/

=====================
Seting up OpenTracing
=====================

To receive OpenTracing spans, start up a Jaeger server. This can be done
using docker like so:

.. code-block:: bash

   docker run -d --name jaeger
     -p 6831:6831/udp \
     -p 6832:6832/udp \
     -p 5778:5778 \
     -p 16686:16686 \
     -p 14268:14268 \
     jaegertracing/all-in-one:1.13

Latest documentation is probably at
https://www.jaegertracing.io/docs/1.13/getting-started/


Enable opentracing in Synapse
-----------------------------

Opentracing is not enabled by default. It must be enabled in the homeserver
config by uncommenting the config options under ``opentracing`` as shown in
the [sample config](./sample_config.yaml). For example:

.. code-block:: yaml

  opentracing:
    tracer_enabled: true
    homeserver_whitelist:
      - "mytrustedhomeserver.org"
      - "*.myotherhomeservers.com"

Homeserver whitelisting
-----------------------

The homeserver whitelist is configured using regular expression. A list of regular
expressions can be given and their union will be compared when propagating any
spans contexts to another homeserver. 

Though it's mostly safe to send and receive span contexts to and from
untrusted users since span contexts are usually opaque ids it can lead to
two problems, namely:

- If the span context is marked as sampled by the sending homeserver the receiver will
  sample it. Therefore two homeservers with wildly disparaging sampling policies
  could incur higher sampling counts than intended.
- Span baggage can be arbitrary data. For safety this has been disabled in Synapse
  but that doesn't prevent another server sending you baggage which will be logged
  to OpenTracing's logs.

========================================
Developers: Using OpenTracing in Synapse
========================================

Python-specific tracing concepts are at https://opentracing.io/guides/python/.
Note that Synapse wraps OpenTracing in a small module in order to make the
OpenTracing dependency optional. That means that the access patterns are
different to those demonstrated in the OpenTracing guides. However, it is
still useful to know, especially if OpenTracing is included as a full dependency
in the future or if you are modifying Synapse's `opentracing` module.


Access to the OpenTracing API is mediated through the
``logging/opentracing.py`` module. OpenTracing is encapsulated so that
no span objects from OpenTracing are exposed in Synapses code. This allows
OpenTracing to be easily disabled in Synapse and thereby have OpenTracing as
an optional dependency. This does however limit the number of modifiable spans
at any point in the code to one. From here out references to `opentracing`
in the code snippets refer to the Synapses module.

Tracing
-------

In Synapse it is not possible to start a non-active span. Spans can be started
using the ``start_active_span`` method. This returns a scope (see
OpenTracing docs) which is a context manager that needs to be entered and
exited. This is usually done by using ``with``.

.. code-block:: python

   from synapse.logging.opentracing import start_active_span

   with start_active_span("operation name"):
       # Do something we want to tracer

Forgetting to enter or exit a scope will result in some mysterious and grievous log
context errors.

At anytime where there is an active span ``opentracing.set_tag`` can be used to
set a tag on the current active span.

Tracing functions
-----------------

Functions can be easily traced using decorators. There is a decorator for
'normal' function and for functions which are actually deferreds. The name of
the function becomes the operation name for the span.

.. code-block:: python
    
   from synapse.logging.opentracing import trace, trace_deferred

   # Start a span using 'normal_function' as the operation name
   @trace
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   # Start a span using 'deferred_function' as the operation name
   @trace_deferred
   @defer.inlineCallbacks
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Operation names can be explicitly set for functions by using
``trace_using_operation_name`` and
``trace_deferred_using_operation_name``

.. code-block:: python

   from synapse.logging.opentracing import (
       trace_using_operation_name,
       trace_deferred_using_operation_name
   )

   @trace_using_operation_name("A *much* better operation name")
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   @trace_deferred_using_operation_name("Another exciting operation name!")
   @defer.inlineCallbacks
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Contexts and carriers
---------------------

There are a selection of wrappers for injecting and extracting contexts from
carriers provided. Unfortunately OpenTracing's three context injection
techniques are not adequate for our inject of OpenTracing span-contexts into
Twisted's http headers, EDU contents and our database tables. Also note that
the binary encoding format mandated by OpenTracing is not actually implemented
by jaeger_client v4.0.0 - it will silently noop.
Please refer to the end of ``logging/opentracing.py`` for the available
injection and extraction methods.

homeserver whitelisting
-----------------------

Most of the whitelist checks are encapsulated in the modules's injection
and extraction method but be aware that using custom carriers or crossing
unchartered waters will require the enforcement of the whitelist.
``logging/opentracing.py`` has a ``whitelisted_homeserver`` method which takes
in a destination and compares it to the whitelist.

==================
Configuring Jaeger
==================

Sampling strategies can be set as in this document:
https://www.jaegertracing.io/docs/1.13/sampling/

=======
Gotchas
=======

- Checking whitelists on span propagation
- Inserting pii
- Forgetting to enter or exit a scope
- Span source: make sure that the span you expect to be active across a
  function call really will be that one. Does the current function have more
  than one caller? Will all of those calling functions have be in a context
  with an active span?
