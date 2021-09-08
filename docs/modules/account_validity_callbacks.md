# Account validity callbacks

Account validity callbacks allow module developers to add extra steps to verify the
validity on an account, i.e. see if a user can be granted access to their account on the
Synapse instance. Account validity callbacks can be registered using the module API's
`register_account_validity_callbacks` method.

The available account validity callbacks are:

### `is_user_expired`

```python
async def is_user_expired(user: str) -> Optional[bool]
```

Called when processing any authenticated request (except for logout requests). The module
can return a `bool` to indicate whether the user has expired and should be locked out of
their account, or `None` if the module wasn't able to figure it out. The user is
represented by their Matrix user ID (e.g. `@alice:example.com`).

If the module returns `True`, the current request will be denied with the error code
`ORG_MATRIX_EXPIRED_ACCOUNT` and the HTTP status code 403. Note that this doesn't
invalidate the user's access token.

### `on_user_registration`

```python
async def on_user_registration(user: str) -> None
```

Called after successfully registering a user, in case the module needs to perform extra
operations to keep track of them. (e.g. add them to a database table). The user is
represented by their Matrix user ID.
