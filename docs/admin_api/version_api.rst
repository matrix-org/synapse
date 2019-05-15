Version API
===========

This API returns the running Synapse version and the Python version
on which Synapse is being run. This is useful when a Synapse instance
is behind a proxy that does not forward the 'Server' header (which also
contains Synapse version information).

The api is::

    GET /_synapse/admin/v1/server_version

It returns a JSON body like the following:

.. code:: json

    {
        "server_version": "0.99.2rc1 (b=develop, abcdef123)",
        "python_version": "3.6.8"
    }
