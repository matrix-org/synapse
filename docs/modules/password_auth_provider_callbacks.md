# Password auth provider callbacks

Password auth providers offer a way for server administrators to integrate
their Synapse installation with an external authentication system. The callbacks can be
registered by using the Module API's `register_password_auth_provider_callbacks` method.

## Callbacks

### `auth_checkers`

_First introduced in Synapse v1.46.0_

```python
auth_checkers: Dict[Tuple[str, Tuple[str, ...]], Callable]
```

A dict mapping from tuples of a login type identifier (such as `m.login.password`) and a
tuple of field names (such as `("password", "secret_thing")`) to authentication checking
callbacks, which should be of the following form:

```python
async def check_auth(
    user: str,
    login_type: str,
    login_dict: "synapse.module_api.JsonDict",
) -> Optional[
    Tuple[
        str, 
        Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]]
    ]
]
```

The login type and field names should be provided by the user in the
request to the `/login` API. [The Matrix specification](https://matrix.org/docs/spec/client_server/latest#authentication-types)
defines some types, however user defined ones are also allowed.

The callback is passed the `user` field provided by the client (which might not be in
`@username:server` form), the login type, and a dictionary of login secrets passed by
the client.

If the authentication is successful, the module must return the user's Matrix ID (e.g. 
`@alice:example.com`) and optionally a callback to be called with the response to the
`/login` request. If the module doesn't wish to return a callback, it must return `None`
instead.

If the authentication is unsuccessful, the module must return `None`.

Note that the user is not automatically registered, the `register_user(..)` method of
the [module API](writing_a_module.html) can be used to lazily create users.

If multiple modules register an auth checker for the same login type but with different
fields, Synapse will refuse to start.

If multiple modules register an auth checker for the same login type with the same fields,
then the callbacks will be executed in order, until one returns a Matrix User ID (and
optionally a callback). In that case, the return value of that callback will be accepted
and subsequent callbacks will not be fired. If every callback returns `None`, then the
authentication fails.

### `check_3pid_auth`

_First introduced in Synapse v1.46.0_

```python
async def check_3pid_auth(
    medium: str, 
    address: str,
    password: str,
) -> Optional[
    Tuple[
        str, 
        Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]]
    ]
]
```

Called when a user attempts to register or log in with a third party identifier,
such as email. It is passed the medium (eg. `email`), an address (eg. `jdoe@example.com`)
and the user's password.

If the authentication is successful, the module must return the user's Matrix ID (e.g. 
`@alice:example.com`) and optionally a callback to be called with the response to the `/login` request.
If the module doesn't wish to return a callback, it must return None instead.

If the authentication is unsuccessful, the module must return `None`.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `None`, Synapse falls through to the next one. The value of the first
callback that does not return `None` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback. If every callback returns `None`,
the authentication is denied.

### `on_logged_out`

_First introduced in Synapse v1.46.0_

```python
async def on_logged_out(
    user_id: str,
    device_id: Optional[str],
    access_token: str
) -> None
``` 
Called during a logout request for a user. It is passed the qualified user ID, the ID of the
deactivated device (if any: access tokens are occasionally created without an associated
device ID), and the (now deactivated) access token.

Deleting the related pushers is done after calling `on_logged_out`, so you can rely on them
to still be present.

If multiple modules implement this callback, Synapse runs them all in order.

### `get_username_for_registration`

_First introduced in Synapse v1.52.0_

```python
async def get_username_for_registration(
    uia_results: Dict[str, Any],
    params: Dict[str, Any],
) -> Optional[str]
```

Called when registering a new user. The module can return a username to set for the user
being registered by returning it as a string, or `None` if it doesn't wish to force a
username for this user. If a username is returned, it will be used as the local part of a
user's full Matrix ID (e.g. it's `alice` in `@alice:example.com`).

This callback is called once [User-Interactive Authentication](https://spec.matrix.org/latest/client-server-api/#user-interactive-authentication-api)
has been completed by the user. It is not called when registering a user via SSO. It is
passed two dictionaries, which include the information that the user has provided during
the registration process.

The first dictionary contains the results of the [User-Interactive Authentication](https://spec.matrix.org/latest/client-server-api/#user-interactive-authentication-api)
flow followed by the user. Its keys are the identifiers of every step involved in the flow,
associated with either a boolean value indicating whether the step was correctly completed,
or additional information (e.g. email address, phone number...). A list of most existing
identifiers can be found in the [Matrix specification](https://spec.matrix.org/v1.1/client-server-api/#authentication-types).
Here's an example featuring all currently supported keys:

```python
{
    "m.login.dummy": True,  # Dummy authentication
    "m.login.terms": True,  # User has accepted the terms of service for the homeserver
    "m.login.recaptcha": True,  # User has completed the recaptcha challenge
    "m.login.email.identity": {  # User has provided and verified an email address
        "medium": "email",
        "address": "alice@example.com",
        "validated_at": 1642701357084,
    },
    "m.login.msisdn": {  # User has provided and verified a phone number
        "medium": "msisdn",
        "address": "33123456789",
        "validated_at": 1642701357084,
    },
    "m.login.registration_token": "sometoken",  # User has registered through a registration token
}
```

The second dictionary contains the parameters provided by the user's client in the request
to `/_matrix/client/v3/register`. See the [Matrix specification](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3register)
for a complete list of these parameters.

If the module cannot, or does not wish to, generate a username for this user, it must
return `None`.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `None`, Synapse falls through to the next one. The value of the first
callback that does not return `None` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback. If every callback returns `None`,
the username provided by the user is used, if any (otherwise one is automatically
generated).

### `get_displayname_for_registration`

_First introduced in Synapse v1.54.0_

```python
async def get_displayname_for_registration(
    uia_results: Dict[str, Any],
    params: Dict[str, Any],
) -> Optional[str]
```

Called when registering a new user. The module can return a display name to set for the
user being registered by returning it as a string, or `None` if it doesn't wish to force a
display name for this user.

This callback is called once [User-Interactive Authentication](https://spec.matrix.org/latest/client-server-api/#user-interactive-authentication-api)
has been completed by the user. It is not called when registering a user via SSO. It is
passed two dictionaries, which include the information that the user has provided during
the registration process. These dictionaries are identical to the ones passed to
[`get_username_for_registration`](#get_username_for_registration), so refer to the
documentation of this callback for more information about them.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `None`, Synapse falls through to the next one. The value of the first
callback that does not return `None` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback. If every callback returns `None`,
the username will be used (e.g. `alice` if the user being registered is `@alice:example.com`).

## `is_3pid_allowed`

_First introduced in Synapse v1.53.0_

```python
async def is_3pid_allowed(self, medium: str, address: str, registration: bool) -> bool
```

Called when attempting to bind a third-party identifier (i.e. an email address or a phone
number). The module is given the medium of the third-party identifier (which is `email` if
the identifier is an email address, or `msisdn` if the identifier is a phone number) and
its address, as well as a boolean indicating whether the attempt to bind is happening as
part of registering a new user. The module must return a boolean indicating whether the
identifier can be allowed to be bound to an account on the local homeserver.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

## Example

The example module below implements authentication checkers for two different login types: 
-  `my.login.type` 
    - Expects a `my_field` field to be sent to `/login`
    - Is checked by the method: `self.check_my_login`
- `m.login.password` (defined in [the spec](https://matrix.org/docs/spec/client_server/latest#password-based))
    - Expects a `password` field to be sent to `/login`
    - Is checked by the method: `self.check_pass`

```python
from typing import Awaitable, Callable, Optional, Tuple

import synapse
from synapse import module_api


class MyAuthProvider:
    def __init__(self, config: dict, api: module_api):

        self.api = api

        self.credentials = {
            "bob": "building",
            "@scoop:matrix.org": "digging",
        }

        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("my.login_type", ("my_field",)): self.check_my_login,
                ("m.login.password", ("password",)): self.check_pass,
            },
        )

    async def check_my_login(
        self,
        username: str,
        login_type: str,
        login_dict: "synapse.module_api.JsonDict",
    ) -> Optional[
        Tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        if login_type != "my.login_type":
            return None

        if self.credentials.get(username) == login_dict.get("my_field"):
            return (self.api.get_qualified_user_id(username), None)

    async def check_pass(
        self,
        username: str,
        login_type: str,
        login_dict: "synapse.module_api.JsonDict",
    ) -> Optional[
        Tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        if login_type != "m.login.password":
            return None

        if self.credentials.get(username) == login_dict.get("password"):
            return (self.api.get_qualified_user_id(username), None)
```
