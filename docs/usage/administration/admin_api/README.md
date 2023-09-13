# The Admin API

## Authenticate as a server admin

Many of the API calls in the admin api will require an `access_token` for a
server admin. (Note that a server admin is distinct from a room admin.)

An existing user can be marked as a server admin by updating the database directly.

Check your [database settings](../../configuration/config_documentation.md#database) in the configuration file, connect to the correct database using either `psql [database name]` (if using PostgreSQL) or `sqlite3 path/to/your/database.db` (if using SQLite) and elevate the user `@foo:bar.com` to administrator.
```sql
UPDATE users SET admin = 1 WHERE name = '@foo:bar.com';
```

A new server admin user can also be created using the `register_new_matrix_user`
command. This is a script that is distributed as part of synapse. It is possibly
already on your `$PATH` depending on how Synapse was installed.

Finding your user's `access_token` is client-dependent, but will usually be shown in the client's settings.

## Making an Admin API request
For security reasons, we [recommend](../../../reverse_proxy.md#synapse-administration-endpoints)
that the Admin API (`/_synapse/admin/...`) should be hidden from public view using a
reverse proxy. This means you should typically query the Admin API from a terminal on
the machine which runs Synapse.

Once you have your `access_token`, you will need to authenticate each request to an Admin API endpoint by
providing the token as either a query parameter or a request header. To add it as a request header in cURL:

```sh
curl --header "Authorization: Bearer <access_token>" <the_rest_of_your_API_request>
```

For example, suppose we want to
[query the account](../../../admin_api/user_admin_api.md#query-user-account) of the user
`@foo:bar.com`. We need an admin access token (e.g.
`syt_AjfVef2_L33JNpafeif_0feKJfeaf0CQpoZk`), and we need to know which port
Synapse's [`client` listener](../../configuration/config_documentation.md#listeners) is listening
on (e.g. `8008`). Then we can use the following command to request the account
information from the Admin API.

```sh
curl --header "Authorization: Bearer syt_AjfVef2_L33JNpafeif_0feKJfeaf0CQpoZk" -X GET http://127.0.0.1:8008/_synapse/admin/v2/users/@foo:bar.com
```

For more details on access tokens in Matrix, please refer to the complete
[matrix spec documentation](https://matrix.org/docs/spec/client_server/r0.6.1#using-access-tokens).
