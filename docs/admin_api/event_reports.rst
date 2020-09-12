Show reported events
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
                "content": {
                    "reason": "foo",
                    "score": -100
                },
                "event_id": "$bNUFCwGzWca1meCGkjp-zwslF-GfVcXukvRLI1_FaVY",
                "event_json": {
                    "auth_events": [
                        "$YK4arsKKcc0LRoe700pS8DSjOvUT4NDv0HfInlMFw2M",
                        "$oggsNXxzPFRE3y53SUNd7nsj69-QzKv03a1RucHu-ws"
                    ],
                    "content": {
                        "body": "matrix.org: This Week in Matrix",
                        "format": "org.matrix.custom.html",
                        "formatted_body": "<strong>matrix.org</strong>:<br><a href=\"https://matrix.org/blog/\"><strong>This Week in Matrix</strong></a>",
                        "msgtype": "m.notice"
                    },
                    "depth": 546,
                    "hashes": {
                        "sha256": "xK1//xnmvHJIOvbgXlkI8eEqdvoMmihVDJ9J4SNlsAw"
                    },
                    "origin": "matrix.org",
                    "origin_server_ts": 1592291711430,
                    "prev_events": [
                        "$YK4arsKKcc0LRoe700pS8DSjOvUT4NDv0HfInlMFw2M"
                    ],
                    "prev_state": [],
                    "room_id": "!ERAgBpSOcCCuTJqQPk:matrix.org",
                    "sender": "@foobar:matrix.org",
                    "signatures": {
                        "matrix.org": {
                            "ed25519:a_JaEG": "cs+OUKW/iHx5pEidbWxh0UiNNHwe46Ai9LwNz+Ah16aWDNszVIe2gaAcVZfvNsBhakQTew51tlKmL2kspXk/Dg"
                        }
                    },
                    "type": "m.room.message",
                    "unsigned": {
                        "age_ts": 1592291711430,
                    }
                },
                "id": 2,
                "reason": "foo",
                "received_ts": 1570897107409,
                "room_alias": "#alias1:matrix.org",
                "room_id": "!ERAgBpSOcCCuTJqQPk:matrix.org",
                "sender": "@foobar:matrix.org",
                "user_id": "@foo:matrix.org"
            },
            {
                "content": {
                    "reason": "bar",
                    "score": -100
                },
                "event_id": "$3IcdZsDaN_En-S1DF4EMCy3v4gNRKeOJs8W5qTOKj4I",
                "event_json": {
                    "_comment": "... (hidden items) ..."
                },
                "id": 3,
                "reason": "bar",
                "received_ts": 1598889612059,
                "room_alias": "#alias2:matrix.org",
                "room_id": "!eGvUQuTCkHGVwNMOjv:matrix.org",
                "sender": "@foobar:matrix.org",
                "user_id": "@bar:matrix.org"
            }
        ],
        "next_token": "2",
        "total": 4
    }

To paginate, check for ``next_token`` and if present, call the endpoint again
with ``from`` set to the value of ``next_token``. This will return a new page.

If the endpoint does not return a ``next_token`` then there are no more
reports to paginate through.

**URL parameters:**

- ``limit``: Is optional but is used for pagination,
  denoting the maximum number of items to return in this call. Defaults to ``100``.
- ``from``: Is optional but used for pagination,
  denoting the offset in the returned results. This should be treated as an opaque value and
  not explicitly set to anything other than the return value of ``next_token`` from a previous call.
  Defaults to ``0``.
- ``dir`` - Direction of event report order. Whether to fetch the most recent first (``b``) or the
  oldest first (``f``). Defaults to ``b``.
- ``user_id``: Is optional and filters to only return users with user IDs that contain this value.
  This is the user who reported the event and wrote the reason.
- ``room_id``: Is optional and filters to only return rooms with room IDs that contain this value.

**Response**

The following fields are returned in the JSON response body:

- ``id``: Id of event report.
- ``received_ts``: The timestamp (in milliseconds since the unix epoch) when this report was sent.
- ``room_id``: The ID of the room.
- ``event_id``: The ID of the reported event.
- ``user_id``: This is the user who reported the event and wrote the reason.
- ``reason``: Comment made by the ``user_id`` in this report.
- ``content``: Content of reported event.
- ``sender``: This is the ID of the user who sent the original message/event that was reported.
- ``room_alias``: The alias of the room.
- ``event_json``: Details of the original event that was reported.

