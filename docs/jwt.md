# JWT Login Type

Synapse comes with a non-standard login type to support
[JSON Web Tokens](https://en.wikipedia.org/wiki/JSON_Web_Token). In general the
documentation for
[the login endpoint](https://matrix.org/docs/spec/client_server/r0.6.1#login)
is still valid (and the mechanism works similarly to the
[token based login](https://matrix.org/docs/spec/client_server/r0.6.1#token-based)).

To log in using a JSON Web Token, clients should submit a `/login` request as
follows:

```json
{
  "type": "org.matrix.login.jwt",
  "token": "<jwt>"
}
```

The `token` field should include the JSON web token with the following claims:

* A claim that encodes the local part of the user ID is required. By default,
  the `sub` (subject) claim is used, or a custom claim can be set in the
  configuration file.
* The expiration time (`exp`), not before time (`nbf`), and issued at (`iat`)
  claims are optional, but validated if present.
* The issuer (`iss`) claim is optional, but required and validated if configured.
* The audience (`aud`) claim is optional, but required and validated if configured.
  Providing the audience claim when not configured will cause validation to fail.

In the case that the token is not valid, the homeserver must respond with
`403 Forbidden` and an error code of `M_FORBIDDEN`.

As with other login types, there are additional fields (e.g. `device_id` and
`initial_device_display_name`) which can be included in the above request.

## Preparing Synapse

The JSON Web Token integration in Synapse uses the
[`Authlib`](https://docs.authlib.org/en/latest/index.html) library, which must be installed
as follows:

* The relevant libraries are included in the Docker images and Debian packages
  provided by `matrix.org` so no further action is needed.

* If you installed Synapse into a virtualenv, run `/path/to/env/bin/pip
  install synapse[jwt]` to install the necessary dependencies.

* For other installation mechanisms, see the documentation provided by the
  maintainer.

To enable the JSON web token integration, you should then add a `jwt_config` option
to your configuration file. See the [configuration manual](usage/configuration/config_documentation.md#jwt_config) for some
sample settings.

## How to test JWT as a developer

Although JSON Web Tokens are typically generated from an external server, the
example below uses a locally generated JWT.

1.  Configure Synapse with JWT logins, note that this example uses a pre-shared
    secret and an algorithm of HS256:

    ```yaml
    jwt_config:
        enabled: true
        secret: "my-secret-token"
        algorithm: "HS256"
    ```
2.  Generate a JSON web token:

    You can use the following short Python snippet to generate a JWT
    protected by an HMAC.
    Take care that the `secret` and the algorithm given in the `header` match
    the entries from `jwt_config` above.

    ```python
    from authlib.jose import jwt

    header = {"alg": "HS256"}
    payload = {"sub": "user1", "aud": ["audience"]}
    secret = "my-secret-token"
    result = jwt.encode(header, payload, secret)
    print(result.decode("ascii"))
    ```

3.  Query for the login types and ensure `org.matrix.login.jwt` is there:

    ```bash
    curl http://localhost:8080/_matrix/client/r0/login
    ```
4.  Login used the generated JSON web token from above:

    ```bash
    $ curl http://localhost:8082/_matrix/client/r0/login -X POST \
        --data '{"type":"org.matrix.login.jwt","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.Ag71GT8v01UO3w80aqRPTeuVPBIBZkYhNTJJ-_-zQIc"}'
    {
        "access_token": "<access token>",
        "device_id": "ACBDEFGHI",
        "home_server": "localhost:8080",
        "user_id": "@test-user:localhost:8480"
    }
    ```

You should now be able to use the returned access token to query the client API.
