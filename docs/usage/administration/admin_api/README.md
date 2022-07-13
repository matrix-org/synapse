# The Admin API

## Authenticate as a server admin

Many of the API calls in the admin api will require an `access_token` for a
server admin. (Note that a server admin is distinct from a room admin.)

An existing user can be marked as a server admin by updating the database directly.

When using PostgreSQL, switch to the `postgres` user and start the command line tool.
```sh
su - postgres
psql
```

Check your  [database settings](config_documentation.md#database) in the `homeserver.yaml`, connect to the
specified database called e.g. `synapse` and elevate the user `@foo:bar.com` to administrator.
```sql
\c synapse
UPDATE users SET admin = 1 WHERE name = '@foo:bar.com';
```

A new server admin user can also be created using the `register_new_matrix_user`
command. This is a script that is distributed as part of synapse. It is possibly
already on your `$PATH` depending on how Synapse was installed.

Finding your user's `access_token` is client-dependent, but will usually be shown in the client's settings.

## Making an Admin API request
Once you have your `access_token`, you will need to authenticate each request to an Admin API endpoint by
providing the token as either a query parameter or a request header. To add it as a request header in cURL:

```sh
curl --header "Authorization: Bearer <access_token>" <the_rest_of_your_API_request>
```

For more details on access tokens in Matrix, please refer to the complete
[matrix spec documentation](https://matrix.org/docs/spec/client_server/r0.6.1#using-access-tokens).
