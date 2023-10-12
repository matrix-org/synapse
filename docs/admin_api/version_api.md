# Version API

This API returns the running Synapse version.
This is useful when a Synapse instance
is behind a proxy that does not forward the 'Server' header (which also
contains Synapse version information).

The api is:

```
GET /_synapse/admin/v1/server_version
```

It returns a JSON body like the following:

```json
{
    "server_version": "0.99.2rc1 (b=develop, abcdef123)"
}
```

*Changed in Synapse 1.94.0:* The `python_version` key was removed from the
response body.
