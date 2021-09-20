# Password auth provider callbacks

Password auth providers offer a way for server administrators to integrate
their Synapse installation with an external authentication system. The callbacks can be
registered by using the Module API's `register_password_auth_provider_callbacks` method.

## Callbacks

### `auth_checkers`

```
 auth_checkers: Dict[Tuple[str,Tuple], Callable]
```

A dict mapping from tuples of a login type identifier (such as `m.login.password`) and a
tuple of field names (such as `("password", "secret_thing")`) to authentication checking
callbacks, which should be of the following form:

```python
async def check_auth(
    username: str,
    login_type: str,
    login_dict: "synapse.module_api.JsonDict",
) -> Optional[
    Tuple[
        str, 
        Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]]
    ]
]
```

The login type and field names are the things that should be provided by the user in their
request to the `/login` API. [The spec](https://matrix.org/docs/spec/client_server/latest#user-interactive-authentication-api)
defines some types, however user defined ones are also allowed.

It is passed the user field provided by the client (which might not be in `@username:server` form), 
the login type, and a dictionary of login secrets passed by the client.

If the authentication is successful, the module must return the user's Matrix ID (e.g. 
`@alice:example.com`) and optionally a callback to be called with the response to the `/login` request.
If the module doesn't wish to return a callback, it must return None instead.

If the authentication is unsuccessful, the module must return None.

### `check_3pid_auth`

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
such as email. It is passed the medium (eg. `"email"`), an address (eg. `"jdoe@example.com"`)
and the user's password.

If the authentication is successful, the module must return the user's Matrix ID (e.g. 
`"@alice:example.com"`) and optionally a callback to be called with the response to the `/login` request.
If the module doesn't wish to return a callback, it must return None instead.

If the authentication is unsuccessful, the module must return None.

### `on_logged_out`

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

## Example

The following module implements authentication checkers for two different login types: 
-  `my.login.type` 
    - Expects a `my_field` field to be sent to `/login`
    - Is checked by the method: `self.check_my_login`
- `m.login.password`
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
            return self.api.get_qualified_user_id(username)

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
            return self.api.get_qualified_user_id(username)
```
