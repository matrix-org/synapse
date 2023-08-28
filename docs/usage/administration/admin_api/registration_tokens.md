# Registration Tokens

**Note:** This API is disabled when MSC3861 is enabled. [See #15582](https://github.com/matrix-org/synapse/pull/15582)

This API allows you to manage tokens which can be used to authenticate
registration requests, as proposed in
[MSC3231](https://github.com/matrix-org/matrix-doc/blob/main/proposals/3231-token-authenticated-registration.md)
and stabilised in version 1.2 of the Matrix specification.
To use it, you will need to enable the `registration_requires_token` config
option, and authenticate by providing an `access_token` for a server admin:
see [Admin API](../admin_api/).


## Registration token objects

Most endpoints make use of JSON objects that contain details about tokens.
These objects have the following fields:
- `token`: The token which can be used to authenticate registration.
- `uses_allowed`: The number of times the token can be used to complete a
  registration before it becomes invalid.
- `pending`: The number of pending uses the token has. When someone uses
  the token to authenticate themselves, the pending counter is incremented
  so that the token is not used more than the permitted number of times.
  When the person completes registration the pending counter is decremented,
  and the completed counter is incremented.
- `completed`: The number of times the token has been used to successfully
  complete a registration.
- `expiry_time`: The latest time the token is valid. Given as the number of
  milliseconds since 1970-01-01 00:00:00 UTC (the start of the Unix epoch).
  To convert this into a human-readable form you can remove the milliseconds
  and use the `date` command. For example, `date -d '@1625394937'`.


## List all tokens

Lists all tokens and details about them. If the request is successful, the top
level JSON object will have a `registration_tokens` key which is an array of
registration token objects.

```
GET /_synapse/admin/v1/registration_tokens
```

Optional query parameters:
- `valid`: `true` or `false`. If `true`, only valid tokens are returned.
  If `false`, only tokens that have expired or have had all uses exhausted are
  returned. If omitted, all tokens are returned regardless of validity.

Example:

```
GET /_synapse/admin/v1/registration_tokens
```
```
200 OK

{
    "registration_tokens": [
        {
            "token": "abcd",
            "uses_allowed": 3,
            "pending": 0,
            "completed": 1,
            "expiry_time": null
        },
        {
            "token": "pqrs",
            "uses_allowed": 2,
            "pending": 1,
            "completed": 1,
            "expiry_time": null
        },
        {
            "token": "wxyz",
            "uses_allowed": null,
            "pending": 0,
            "completed": 9,
            "expiry_time": 1625394937000    // 2021-07-04 10:35:37 UTC
        }
    ]
}
```

Example using the `valid` query parameter:

```
GET /_synapse/admin/v1/registration_tokens?valid=false
```
```
200 OK

{
    "registration_tokens": [
        {
            "token": "pqrs",
            "uses_allowed": 2,
            "pending": 1,
            "completed": 1,
            "expiry_time": null
        },
        {
            "token": "wxyz",
            "uses_allowed": null,
            "pending": 0,
            "completed": 9,
            "expiry_time": 1625394937000    // 2021-07-04 10:35:37 UTC
        }
    ]
}
```


## Get one token

Get details about a single token. If the request is successful, the response
body will be a registration token object.

```
GET /_synapse/admin/v1/registration_tokens/<token>
```

Path parameters:
- `token`: The registration token to return details of.

Example:

```
GET /_synapse/admin/v1/registration_tokens/abcd
```
```
200 OK

{
    "token": "abcd",
    "uses_allowed": 3,
    "pending": 0,
    "completed": 1,
    "expiry_time": null
}
```


## Create token

Create a new registration token. If the request is successful, the newly created
token will be returned as a registration token object in the response body.

```
POST /_synapse/admin/v1/registration_tokens/new
```

The request body must be a JSON object and can contain the following fields:
- `token`: The registration token. A string of no more than 64 characters that
  consists only of characters matched by the regex `[A-Za-z0-9._~-]`.
  Default: randomly generated.
- `uses_allowed`: The integer number of times the token can be used to complete
  a registration before it becomes invalid.
  Default: `null` (unlimited uses).
- `expiry_time`: The latest time the token is valid. Given as the number of
  milliseconds since 1970-01-01 00:00:00 UTC (the start of the Unix epoch).
  You could use, for example, `date '+%s000' -d 'tomorrow'`.
  Default: `null` (token does not expire).
- `length`: The length of the token randomly generated if `token` is not
  specified. Must be between 1 and 64 inclusive. Default: `16`.

If a field is omitted the default is used.

Example using defaults:

```
POST /_synapse/admin/v1/registration_tokens/new

{}
```
```
200 OK

{
    "token": "0M-9jbkf2t_Tgiw1",
    "uses_allowed": null,
    "pending": 0,
    "completed": 0,
    "expiry_time": null
}
```

Example specifying some fields:

```
POST /_synapse/admin/v1/registration_tokens/new

{
    "token": "defg",
    "uses_allowed": 1
}
```
```
200 OK

{
    "token": "defg",
    "uses_allowed": 1,
    "pending": 0,
    "completed": 0,
    "expiry_time": null
}
```


## Update token

Update the number of allowed uses or expiry time of a token. If the request is
successful, the updated token will be returned as a registration token object
in the response body.

```
PUT /_synapse/admin/v1/registration_tokens/<token>
```

Path parameters:
- `token`: The registration token to update.

The request body must be a JSON object and can contain the following fields:
- `uses_allowed`: The integer number of times the token can be used to complete
  a registration before it becomes invalid. By setting `uses_allowed` to `0`
  the token can be easily made invalid without deleting it.
  If `null` the token will have an unlimited number of uses.
- `expiry_time`: The latest time the token is valid. Given as the number of
  milliseconds since 1970-01-01 00:00:00 UTC (the start of the Unix epoch).
  If `null` the token will not expire.

If a field is omitted its value is not modified.

Example:

```
PUT /_synapse/admin/v1/registration_tokens/defg

{
    "expiry_time": 4781243146000    // 2121-07-06 11:05:46 UTC
}
```
```
200 OK

{
    "token": "defg",
    "uses_allowed": 1,
    "pending": 0,
    "completed": 0,
    "expiry_time": 4781243146000
}
```


## Delete token

Delete a registration token. If the request is successful, the response body
will be an empty JSON object.

```
DELETE /_synapse/admin/v1/registration_tokens/<token>
```

Path parameters:
- `token`: The registration token to delete.

Example:

```
DELETE /_synapse/admin/v1/registration_tokens/wxyz
```
```
200 OK

{}
```


## Errors

If a request fails a "standard error response" will be returned as defined in
the [Matrix Client-Server API specification](https://matrix.org/docs/spec/client_server/r0.6.1#api-standards).

For example, if the token specified in a path parameter does not exist a
`404 Not Found` error will be returned.

```
GET /_synapse/admin/v1/registration_tokens/1234
```
```
404 Not Found

{
    "errcode": "M_NOT_FOUND",
    "error": "No such registration token: 1234"
}
```
