# Account validity API

This API allows a server administrator to manage the validity of an account. To
use it, you must enable the account validity feature (under
`account_validity`) in Synapse's configuration.

## Renew account

This API extends the validity of an account by as much time as configured in the
`period` parameter from the `account_validity` configuration.

The API is:

```
POST /_synapse/admin/v1/account_validity/validity
```

with the following body:

```json
{
    "user_id": "<user ID for the account to renew>",
    "expiration_ts": 0,
    "enable_renewal_emails": true
}
```


`expiration_ts` is an optional parameter and overrides the expiration date,
which otherwise defaults to now + validity period.

`enable_renewal_emails` is also an optional parameter and enables/disables
sending renewal emails to the user. Defaults to true.

The API returns with the new expiration date for this account, as a timestamp in
milliseconds since epoch:

```json
{
    "expiration_ts": 0
}
```
