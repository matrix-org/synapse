Show reported events
====================

This API returns information about reported events.

The api is::

    GET /_synapse/admin/v1/event_reports?from=0&limit=10

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

It returns a JSON body like the following:

.. code:: jsonc

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
                    // hidden items
                    // see above
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
        "next_token": 2,
        "total": 4
    }

To paginate, check for ``next_token`` and if present, call the endpoint again
with ``from`` set to the value of ``next_token``. This will return a new page.

If the endpoint does not return a ``next_token`` then there are no more
reports to paginate through.

**URL parameters:**

- ``limit``: integer - Is optional but is used for pagination,
  denoting the maximum number of items to return in this call. Defaults to ``100``.
- ``from``: integer - Is optional but used for pagination,
  denoting the offset in the returned results. This should be treated as an opaque value and
  not explicitly set to anything other than the return value of ``next_token`` from a previous call.
  Defaults to ``0``.
- ``dir``: string - Direction of event report order. Whether to fetch the most recent first (``b``) or the
  oldest first (``f``). Defaults to ``b``.
- ``user_id``: string - Is optional and filters to only return users with user IDs that contain this value.
  This is the user who reported the event and wrote the reason.
- ``room_id``: string - Is optional and filters to only return rooms with room IDs that contain this value.

**Response**

The following fields are returned in the JSON response body:

- ``id``: integer - ID of event report.
- ``received_ts``: integer - The timestamp (in milliseconds since the unix epoch) when this report was sent.
- ``room_id``: string - The ID of the room in which the event being reported is located.
- ``event_id``: string - The ID of the reported event.
- ``user_id``: string - This is the user who reported the event and wrote the reason.
- ``reason``: string - Comment made by the ``user_id`` in this report. May be blank.
- ``content``: object - Content of reported event.

  - ``reason``: string - Comment made by the ``user_id`` in this report. May be blank.
  - ``score``: integer - Content is reported based upon a negative score, where -100 is "most offensive" and 0 is "inoffensive".

- ``sender``: string - This is the ID of the user who sent the original message/event that was reported.
- ``room_alias``: string - The alias of the room. ``null`` if the room does not have a canonical alias set.
- ``event_json``: object - Details of the original event that was reported.
- ``next_token``: integer - Indication for pagination. See above.
- ``total``: integer - Total number of event reports related to the query (``user_id`` and ``room_id``).

