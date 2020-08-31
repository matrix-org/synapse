Shows reported events
====================

This API returns information about reported events.

The api is::

    GET /_synapse/admin/v1/event_reports?from=0&limit=10

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

It returns a JSON body like the following:

.. code:: json

    {
        "event_reports": [
            {
                "content": "{\"reason\": \"foo\", \"score\": -100}",
                "event_id": "$bNUFCwGzWca1meCGkjp-zwslF-GfVcXukvRLI1_FaVY",
                "id": 2,
                "reason": "foo",
                "received_ts": 1570897107409,
                "room_id": "!ERAgBpSOcCCuTJqQPk:matrix.org",
                "user_id": "@foo:matrix.org"
            },
            {
                "content": "{\"score\":-100,\"reason\":\"bar\"}",
                "event_id": "$3IcdZsDaN_En-S1DF4EMCy3v4gNRKeOJs8W5qTOKj4I",
                "id": 3,
                "reason": "bar",
                "received_ts": 1598889612059,
                "room_id": "!eGvUQuTCkHGVwNMOjv:matrix.org",
                "user_id": "@bar:matrix.org"
            }
        ],
        "next_token": "2",
        "total": 4
}

To paginate, check for ``next_token`` and if present, call the endpoint again
with from set to the value of ``next_token``. This will return a new page.

If the endpoint does not return a ``next_token`` then there are no more
users to paginate through.

**URL parameters:**

- ``limit``: Is optional but is used for pagination,
  denoting the maximum number of items to return in this call. Defaults to ``100``.
- ``from``: Is optional but used for pagination,
  denoting the offset in the returned results. This should be treated as an opaque value and
  not explicitly set to anything other than the return value of next_token from a previous call.
  Defaults to ``0``.
- ``user_id``: Is optional and filters to only return users with user IDs that contain this value.
- ``room_id``: Is optional and filters to only return rooms with room IDs that contain this value.
