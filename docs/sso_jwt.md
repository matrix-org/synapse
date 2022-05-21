# JWT Login Type (as external_id)

Synapse contains a non-standard login type to support "standalone"
[JSON Web Tokens](https://en.wikipedia.org/wiki/JSON_Web_Token)
as external identifiers.
The general mechanics is similar to other standard
[authentication types](https://spec.matrix.org/v1.2/client-server-api/#authentication-types).

## API call

To log in using this way, clients should `POST` a request to `/_matrix/client/r0/login`
with the following body:

```json
{
  "type": "org.matrix.login.sso_jwt"
}
```

Additionally, the request must contain an auth HTTP header with a JWT inside (which is usual
for OAuth2 ressource servers).
```
    Authorization: Bearer <jwt>
```

that's it.

(Alternatively, if for some reason a client can't set this HTTP header, it can add an  entry
`"token" : "<jwt>"` to the body's payload. This will then override the header if present.)

## User mapping

So which user will be logged in with a given JWT? This login flow
will decode and check the given JWT. It will extract the issuer (the `iss` claim) and the
OAuth2 principal (the `sub` claim) and search the
[user database](admin_api/user_admin_api.html) for a user with an `external_ids` entry
where `auth_provider` matches the issuer and `external_id` matches the principal.

If such a user is not contained in the database the login attempt will be rejected.
This login flow has no mechanism to automatically create users. This has to be done
in beforehand by an administrator.

## Required configuration

Configuration for this login flow is part of the [oidc_providers](openid.md) section.
There are two extra parameters which can be added per `oidc_provider`:
* `sso_jwt_enabled` - A boolean value which defaults to `true` if not given. This entry can be used
  to disable this login flow for a specific OIDC provider.
* `standalone_jwt_audience` - The `aud` (audience) claim of a JWT says whether a JWT is intended to
  be used for a specific service (see also [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)).
  This parameter can contain a string which will then be searched in the list of audiences
  carried by the JWT. If the configured audience is not contained in the JWT, synapse will
  reject the login attempt. If this parameter is not given, the `aud` claim in a given
  JWT will be ignored.

There are very few requirements regarding the other parameters in the `oidc_providers` section:
* `issuer` - must be given so that the login mechanism can identify the config section for a received JWT
* `jwks_uri` - must be given so that the public key(s) of the issuer can be downloaded (required for
  checking the JWT's signature)
* `discover` can be set to `false` as this flow doesn't need any other endpoints of the auth provider

## Requirements to a received JWT

There are some checks done with a received JWT before the user is actually logged in:

* The signature of the JWT is verified and rejected if wrong
* The JWT must contain an issuer (`iss`) entry. This issuer must have its own entry in
 `oidc_providers` with `sso_jwt_enabled` set to `true` (or absent).
* The expiration time (`exp`), not before time (`nbf`), and issued at (`iat`)
  claims are optional, but validated if present.
* The JWT must contain a `sub` claim which will be used to find the assigned
  matrix user
* The audience (`aud`) claim is optional. If given it will be checked against
  the configured `aud` expectation (if given)

In the case that the token is not valid, the homeserver will respond with
`403 Forbidden` and an error code of `M_FORBIDDEN`.

## Testing locally

During development, I found it helpful to start a 
dockerized keycloak server and set `oidc_providers.skip_verification` to `true`.