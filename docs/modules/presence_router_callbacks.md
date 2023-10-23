# Presence router callbacks

Presence router callbacks allow module developers to define additional users
which receive presence updates from local users. The additional users
can be local or remote.

For example, it could be used to direct all of `@alice:example.com` (a local user)'s
presence updates to `@bob:matrix.org` (a remote user), even though they don't share a
room. (Note that those presence updates might not make it to `@bob:matrix.org`'s client
unless a similar presence router is running on that homeserver.)

Presence router callbacks can be registered using the module API's
`register_presence_router_callbacks` method.

## Callbacks

The available presence router callbacks are:

### `get_users_for_states`

_First introduced in Synapse v1.42.0_

```python 
async def get_users_for_states(
    state_updates: Iterable["synapse.api.UserPresenceState"],
) -> Dict[str, Set["synapse.api.UserPresenceState"]]
```
**Requires** `get_interested_users` to also be registered

Called when processing updates to the presence state of one or more users. This callback can
be used to instruct the server to forward that presence state to specific users. The module
must return a dictionary that maps from Matrix user IDs (which can be local or remote) to the
`UserPresenceState` changes that they should be forwarded.

Synapse will then attempt to send the specified presence updates to each user when possible.

If multiple modules implement this callback, Synapse merges all the dictionaries returned
by the callbacks. If multiple callbacks return a dictionary containing the same key,
Synapse concatenates the sets associated with this key from each dictionary. 

### `get_interested_users`

_First introduced in Synapse v1.42.0_

```python
async def get_interested_users(
    user_id: str
) -> Union[Set[str], "synapse.module_api.PRESENCE_ALL_USERS"]
```
**Requires** `get_users_for_states` to also be registered

Called when determining which users someone should be able to see the presence state of. This
callback should return complementary results to `get_users_for_state` or the presence information 
may not be properly forwarded.

The callback is given the Matrix user ID for a local user that is requesting presence data and
should return the Matrix user IDs of the users whose presence state they are allowed to
query. The returned users can be local or remote. 

Alternatively the callback can return `synapse.module_api.PRESENCE_ALL_USERS`
to indicate that the user should receive updates from all known users.

If multiple modules implement this callback, they will be considered in order. Synapse
calls each callback one by one, and use a concatenation of all the `set`s returned by the
callbacks. If one callback returns `synapse.module_api.PRESENCE_ALL_USERS`, Synapse uses
this value instead. If this happens, Synapse does not call any of the subsequent
implementations of this callback.

## Example

The example below is a module that implements both presence router callbacks, and ensures
that `@alice:example.org` receives all presence updates from `@bob:example.com` and
`@charlie:somewhere.org`, regardless of whether Alice shares a room with any of them.

```python
from typing import Dict, Iterable, Set, Union

from synapse.module_api import ModuleApi


class CustomPresenceRouter:
    def __init__(self, config: dict, api: ModuleApi):
        self.api = api

        self.api.register_presence_router_callbacks(
            get_users_for_states=self.get_users_for_states,
            get_interested_users=self.get_interested_users,
        )

    async def get_users_for_states(
        self,
        state_updates: Iterable["synapse.api.UserPresenceState"],
    ) -> Dict[str, Set["synapse.api.UserPresenceState"]]:
        res = {}
        for update in state_updates:
            if (
                update.user_id == "@bob:example.com"
                or update.user_id == "@charlie:somewhere.org"
            ):
                res.setdefault("@alice:example.com", set()).add(update)

        return res

    async def get_interested_users(
        self,
        user_id: str,
    ) -> Union[Set[str], "synapse.module_api.PRESENCE_ALL_USERS"]:
        if user_id == "@alice:example.com":
            return {"@bob:example.com", "@charlie:somewhere.org"}

        return set()
```
