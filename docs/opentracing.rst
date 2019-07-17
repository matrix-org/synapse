===========
Opentracing
===========

Background
----------

Opentracing is semi-standard being addopted by a number of distributed tracing
platforms. It is a standardised api for facilitating vendor agnostic tracing
instrumentation. That is, we can use the opentracing api and select one of a
number of tracer implementations to do the heavy lifting in the background.
Our current selected implementation is Jaeger.

Opentracing concepts can be found at
https://opentracing.io/docs/overview/what-is-tracing/

Python specific tracing concepts are at https://opentracing.io/guides/python/.
Note that synapse wraps opentracing in a small library in order to make the
opentracing dependency optional. That means that the access patterns are
different to those demonstrated here. However, it is still usefull to know.
Especially if opentracing is included as a full dependency in the future or if
you are modifying synapse's opentracing lib.

For more information about Jaeger's implementation see
https://www.jaegertracing.io/docs/

=================
Setup opentracing
=================

To receive opentracing spans start up a Jaeger server using docker like so

.. code-block:: bash

   docker run -d --name jaeger \ -e COLLECTOR_ZIPKIN_HTTP_PORT=9411 \
     -p 5775:5775/udp \
     -p 6831:6831/udp \
     -p 6832:6832/udp \
     -p 5778:5778 \
     -p 16686:16686 \
     -p 14268:14268 \
     -p 9411:9411 \
     jaegertracing/all-in-one:1.13

Latest documentation is probably at
https://www.jaegertracing.io/docs/1.13/getting-started/


Enable opentracing in synapse
-----------------------------

Opentracing is not enabled by default. It must be enabled in the homeserver
config by uncommenting the config options under ``opentracing``. For example:

.. code-block:: yaml

  opentracing:
    # Enable / disable tracer
    tracer_enabled: true
    # The list of homeservers we wish to expose our current traces to.
    # The list is a list of regexes which are matched against the
    # servername of the homeserver
    homeserver_whitelist:
      - ".*"

Homeserver whitelisting
-----------------------

The homeserver whitelist is configured using regex. A list of regexes can be
given and their union will be compared when propagating any spans through a
carrier. Most of the whitelist checks are encapsulated in the lib's injection
and extraction method but be aware that using custom carriers or crossing
unchartered waters will require the enforcement of this whitelist.

``logging/opentracing.py`` has a ``whitelisted_homeserver`` method which takes
in a destination and compares it to the whitelist.

============================
Using opentracing in synapse
============================

Access to the opentracing api is mediated through the
``logging/opentracing.py`` lib. Opentracing is encapsulated such that
no statefull spans from opentracing are used in synapses code. This allows
opentracing to be easily disabled in synapse and thereby have opentracing as
an optional dependency. This does however limit the number of modifyable spans
at any point in the code to one. From here out references to opentracing refer
to the lib implemented in synapse.

Tracing
-------

In synapse it is not possible to start a non-active span. Spans can be started
using the ``opentracing.start_active_span`` method. This returns a scope (see
opentracing docs) which is a context manager that needs to be entered and
exited. This is usually done by using ``with``.

.. code-block:: python

   with start_active_span("operation name"):
       # Do something we want to tracer

Forgetting to enter or exit a scope will result in some mysterious grevious log
context errors.

At anytime where there is an active span ``opentracing.set_tag`` can be used to
set a tag on the current active span.

Tracing functions
-----------------

Functions can be easily traced using decorators. There is a decorator for
'normal' function and for functions which are actually deferreds. The name of
function becomes the operation name for the span.

.. code-block:: python

   # Start a span using 'normal_function' as the operation name
   @trace
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   # Start a span using 'deferred_function' as the operation name
   @trace_deferred
   # Yes, there is a typo in the lib. I will fix this
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Operation names can be explicitely set for functions by using
``trace_using_operation_name`` and
``trace_deferred_using_operation_name``

.. code-block:: python

   @trace_using_operation_name("A *much* better operation name")
   def normal_function(*args, **kwargs):
       # Does all kinds of cool and expected things
       return something_usual_and_useful

   @trace_deferred_using_operation_name("An operation name that fixes the typo!")
   # Yes, there is a typo in the lib. I will fix this
   def deferred_function(*args, **kwargs):
       # We start
       yield we_wait
       # we finish
       defer.returnValue(something_usual_and_useful)

Contexts and carriers
---------------------

There are a selection of wrappers for injecting and extracting contexts from
carriers provided. Unfortunately opentracing's standard three are not adequate
in the majority of cases. Also note that the binnary encoding format mandated
by opentracing is not actually implemented by Jaeger and it will silently noop.
Please refer to the the end of ``logging/opentracing.py`` for the available
injection and extraction methods.

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
