# Presence router callbacks

Presence router callbacks allow module developers to specify additional users (local or remote)
to receive certain presence updates from local users. Presence router callbacks can be 
registered using the module API's `register_presence_router_callbacks` method.

The available presence router callbacks are:

```python 
async def get_users_for_states(
    self,
    state_updates: Iterable["synapse.api.UserPresenceState"],
) -> Dict[str, Set["synapse.api.UserPresenceState"]]:
```
**Requires** `get_interested_users` to also be registered

Called when processing updates to the presence state of one or more users. This callback can
be used to instruct the server to forward that presence state to specific users. The module
must return a dictionary that maps from Matrix user IDs (which can be local or remote) to the
`UserPresenceState` changes that they should be forwarded.

Synapse will then attempt to send the specified presence updates to each user when possible.

```python
async def get_interested_users(
        self, 
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

For example, if the user `@alice:example.org` is passed to this method, and the Set 
`{"@bob:example.com", "@charlie:somewhere.org"}` is returned, this signifies that Alice 
should receive presence updates sent by Bob and Charlie, regardless of whether these users 
share a room.
