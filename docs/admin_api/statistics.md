# Users' media usage statistics

Returns information about all local media usage of users. Gives the
possibility to filter them by time and user.

The API is:

```
GET /_synapse/admin/v1/statistics/users/media
```

To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [README.rst](README.rst).

A response body like the following is returned:

```json
{
  "users": [
    {
      "displayname": "foo_user_0",
      "media_count": 2,
      "media_length": 134,
      "user_id": "@foo_user_0:test"
    },
    {
      "displayname": "foo_user_1",
      "media_count": 2,
      "media_length": 134,
      "user_id": "@foo_user_1:test"
    }
  ],
  "next_token": 3,
  "total": 10
}
```

To paginate, check for `next_token` and if present, call the endpoint
again with `from` set to the value of `next_token`. This will return a new page.

If the endpoint does not return a `next_token` then there are no more
reports to paginate through.

**Parameters**

The following parameters should be set in the URL:

* `limit`: string representing a positive integer - Is optional but is
  used for pagination, denoting the maximum number of items to return
  in this call. Defaults to `100`.
* `from`: string representing a positive integer - Is optional but used for pagination,
  denoting the offset in the returned results. This should be treated as an opaque value
  and not explicitly set to anything other than the return value of `next_token` from a
  previous call. Defaults to `0`.
* `order_by` - string - The method in which to sort the returned list of users. Valid values are:
  - `user_id` - Users are ordered alphabetically by `user_id`. This is the default.
  - `displayname` - Users are ordered alphabetically by `displayname`.
  - `media_length` - Users are ordered by the total size of uploaded media in bytes.
    Smallest to largest.
  - `media_count` - Users are ordered by number of uploaded media. Smallest to largest.
* `from_ts` - string representing a positive integer - Considers only
  files created at this timestamp or later. Unix timestamp in ms.
* `until_ts` - string representing a positive integer - Considers only
  files created at this timestamp or earlier. Unix timestamp in ms.
* `search_term` - string - Filter users by their user ID localpart **or** displayname.
  The search term can be found in any part of the string.
  Defaults to no filtering.
* `dir` - string - Direction of order. Either `f` for forwards or `b` for backwards.
  Setting this value to `b` will reverse the above sort order. Defaults to `f`.


**Response**

The following fields are returned in the JSON response body:

* `users` - An array of objects, each containing information
  about the user and their local media. Objects contain the following fields:
  - `displayname` - string - Displayname of this user.
  - `media_count` - integer - Number of uploaded media by this user.
  - `media_length` - integer - Size of uploaded media in bytes by this user.
  - `user_id` - string - Fully-qualified user ID (ex. `@user:server.com`).
* `next_token` - integer - Opaque value used for pagination. See above.
* `total` - integer - Total number of users after filtering.
