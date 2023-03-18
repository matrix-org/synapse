# Third party rules callbacks

Third party rules callbacks allow module developers to add extra checks to verify the
validity of incoming events. Third party event rules callbacks can be registered using
the module API's `register_third_party_rules_callbacks` method.

## Callbacks

The available third party rules callbacks are:

### `check_event_allowed`

_First introduced in Synapse v1.39.0_

```python
async def check_event_allowed(
    event: "synapse.events.EventBase",
    state_events: "synapse.types.StateMap",
) -> Tuple[bool, Optional[dict]]
```

**<span style="color:red">
This callback is very experimental and can and will break without notice. Module developers
are encouraged to implement `check_event_for_spam` from the spam checker category instead.
</span>**

Called when processing any incoming event, with the event and a `StateMap`
representing the current state of the room the event is being sent into. A `StateMap` is
a dictionary that maps tuples containing an event type and a state key to the
corresponding state event. For example retrieving the room's `m.room.create` event from
the `state_events` argument would look like this: `state_events.get(("m.room.create", ""))`.
The module must return a boolean indicating whether the event can be allowed.

Note that this callback function processes incoming events coming via federation
traffic (on top of client traffic). This means denying an event might cause the local
copy of the room's history to diverge from that of remote servers. This may cause
federation issues in the room. It is strongly recommended to only deny events using this
callback function if the sender is a local user, or in a private federation in which all
servers are using the same module, with the same configuration.

If the boolean returned by the module is `True`, it may also tell Synapse to replace the
event with new data by returning the new event's data as a dictionary. In order to do
that, it is recommended the module calls `event.get_dict()` to get the current event as a
dictionary, and modify the returned dictionary accordingly.

If `check_event_allowed` raises an exception, the module is assumed to have failed.
The event will not be accepted but is not treated as explicitly rejected, either.
An HTTP request causing the module check will likely result in a 500 Internal
Server Error.

When the boolean returned by the module is `False`, the event is rejected.
(Module developers should not use exceptions for rejection.)

Note that replacing the event only works for events sent by local users, not for events
received over federation.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `on_create_room`

_First introduced in Synapse v1.39.0_

```python
async def on_create_room(
    requester: "synapse.types.Requester",
    request_content: dict,
    is_requester_admin: bool,
) -> None
```

Called when processing a room creation request, with the `Requester` object for the user
performing the request, a dictionary representing the room creation request's JSON body
(see [the spec](https://matrix.org/docs/spec/client_server/latest#post-matrix-client-r0-createroom)
for a list of possible parameters), and a boolean indicating whether the user performing
the request is a server admin.

Modules can modify the `request_content` (by e.g. adding events to its `initial_state`),
or deny the room's creation by raising a `module_api.errors.SynapseError`.

If multiple modules implement this callback, they will be considered in order. If a
callback returns without raising an exception, Synapse falls through to the next one. The
room creation will be forbidden as soon as one of the callbacks raises an exception. If
this happens, Synapse will not call any of the subsequent implementations of this
callback.

### `check_threepid_can_be_invited`

_First introduced in Synapse v1.39.0_

```python
async def check_threepid_can_be_invited(
    medium: str,
    address: str,
    state_events: "synapse.types.StateMap",
) -> bool:
```

Called when processing an invite via a third-party identifier (i.e. email or phone number).
The module must return a boolean indicating whether the invite can go through.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `check_visibility_can_be_modified`

_First introduced in Synapse v1.39.0_

```python
async def check_visibility_can_be_modified(
    room_id: str,
    state_events: "synapse.types.StateMap",
    new_visibility: str,
) -> bool:
```

Called when changing the visibility of a room in the local public room directory. The
visibility is a string that's either "public" or "private". The module must return a
boolean indicating whether the change can go through.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `on_new_event`

_First introduced in Synapse v1.47.0_

```python
async def on_new_event(
    event: "synapse.events.EventBase",
    state_events: "synapse.types.StateMap",
) -> None:
```

Called after sending an event into a room. The module is passed the event, as well
as the state of the room _after_ the event. This means that if the event is a state event,
it will be included in this state.

Note that this callback is called when the event has already been processed and stored
into the room, which means this callback cannot be used to deny persisting the event. To
deny an incoming event, see [`check_event_for_spam`](spam_checker_callbacks.md#check_event_for_spam) instead.

For any given event, this callback will be called on every worker process, even if that worker will not end up
acting on that event. This callback will not be called for events that are marked as rejected.

If multiple modules implement this callback, Synapse runs them all in order.

### `check_can_shutdown_room`

_First introduced in Synapse v1.55.0_

```python
async def check_can_shutdown_room(
    user_id: str, room_id: str,
) -> bool:
```

Called when an admin user requests the shutdown of a room. The module must return a
boolean indicating whether the shutdown can go through. If the callback returns `False`,
the shutdown will not proceed and the caller will see a `M_FORBIDDEN` error.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `check_can_deactivate_user`

_First introduced in Synapse v1.55.0_

```python
async def check_can_deactivate_user(
    user_id: str, by_admin: bool,
) -> bool:
```

Called when the deactivation of a user is requested. User deactivation can be
performed by an admin or the user themselves, so developers are encouraged to check the
requester when implementing this callback. The module must return a
boolean indicating whether the deactivation can go through. If the callback returns `False`,
the deactivation will not proceed and the caller will see a `M_FORBIDDEN` error.

The module is passed two parameters, `user_id` which is the ID of the user being deactivated, and `by_admin` which is `True` if the request is made by a serve admin, and `False` otherwise.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.


### `on_profile_update`

_First introduced in Synapse v1.54.0_

```python
async def on_profile_update(
    user_id: str,
    new_profile: "synapse.module_api.ProfileInfo",
    by_admin: bool,
    deactivation: bool,
) -> None:
```

Called after updating a local user's profile. The update can be triggered either by the
user themselves or a server admin. The update can also be triggered by a user being
deactivated (in which case their display name is set to an empty string (`""`) and the
avatar URL is set to `None`). The module is passed the Matrix ID of the user whose profile
has been updated, their new profile, as well as a `by_admin` boolean that is `True` if the
update was triggered by a server admin (and `False` otherwise), and a `deactivated`
boolean that is `True` if the update is a result of the user being deactivated.

Note that the `by_admin` boolean is also `True` if the profile change happens as a result
of the user logging in through Single Sign-On, or if a server admin updates their own
profile.

Per-room profile changes do not trigger this callback to be called. Synapse administrators
wishing this callback to be called on every profile change are encouraged to disable
per-room profiles globally using the `allow_per_room_profiles` configuration setting in
Synapse's configuration file.
This callback is not called when registering a user, even when setting it through the
[`get_displayname_for_registration`](https://matrix-org.github.io/synapse/latest/modules/password_auth_provider_callbacks.html#get_displayname_for_registration)
module callback.

If multiple modules implement this callback, Synapse runs them all in order.

### `on_user_deactivation_status_changed`

_First introduced in Synapse v1.54.0_

```python
async def on_user_deactivation_status_changed(
    user_id: str, deactivated: bool, by_admin: bool
) -> None:
```

Called after deactivating a local user, or reactivating them through the admin API. The
deactivation can be triggered either by the user themselves or a server admin. The module
is passed the Matrix ID of the user whose status is changed, as well as a `deactivated`
boolean that is `True` if the user is being deactivated and `False` if they're being
reactivated, and a `by_admin` boolean that is `True` if the deactivation was triggered by
a server admin (and `False` otherwise). This latter `by_admin` boolean is always `True`
if the user is being reactivated, as this operation can only be performed through the
admin API.

If multiple modules implement this callback, Synapse runs them all in order.

### `on_threepid_bind`

_First introduced in Synapse v1.56.0_

**<span style="color:red">
This callback is deprecated in favour of the `on_add_user_third_party_identifier` callback, which
features the same functionality. The only difference is in name.
</span>**

```python
async def on_threepid_bind(user_id: str, medium: str, address: str) -> None:
```

Called after creating an association between a local user and a third-party identifier
(email address, phone number). The module is given the Matrix ID of the user the
association is for, as well as the medium (`email` or `msisdn`) and address of the
third-party identifier.

Note that this callback is _not_ called after a successful association on an _identity
server_.

If multiple modules implement this callback, Synapse runs them all in order.

### `on_add_user_third_party_identifier`

_First introduced in Synapse v1.79.0_

```python
async def on_add_user_third_party_identifier(user_id: str, medium: str, address: str) -> None:
```

Called after successfully creating an association between a user and a third-party identifier
(email address, phone number). The module is given the Matrix ID of the user the
association is for, as well as the medium (`email` or `msisdn`) and address of the
third-party identifier (i.e. an email address).

Note that this callback is _not_ called if a user attempts to bind their third-party identifier
to an identity server (via a call to [`POST
/_matrix/client/v3/account/3pid/bind`](https://spec.matrix.org/v1.5/client-server-api/#post_matrixclientv3account3pidbind)).

If multiple modules implement this callback, Synapse runs them all in order.

### `on_remove_user_third_party_identifier`

_First introduced in Synapse v1.79.0_

```python
async def on_remove_user_third_party_identifier(user_id: str, medium: str, address: str) -> None:
```

Called after successfully removing an association between a user and a third-party identifier
(email address, phone number). The module is given the Matrix ID of the user the
association is for, as well as the medium (`email` or `msisdn`) and address of the
third-party identifier (i.e. an email address).

Note that this callback is _not_ called if a user attempts to unbind their third-party
identifier from an identity server (via a call to [`POST
/_matrix/client/v3/account/3pid/unbind`](https://spec.matrix.org/v1.5/client-server-api/#post_matrixclientv3account3pidunbind)).

If multiple modules implement this callback, Synapse runs them all in order.

## Example

The example below is a module that implements the third-party rules callback
`check_event_allowed` to censor incoming messages as dictated by a third-party service.

```python
from typing import Optional, Tuple

from synapse.module_api import ModuleApi

_DEFAULT_CENSOR_ENDPOINT = "https://my-internal-service.local/censor-event"

class EventCensorer:
    def __init__(self, config: dict, api: ModuleApi):
        self.api = api
        self._endpoint = config.get("endpoint", _DEFAULT_CENSOR_ENDPOINT)

        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed,
        )

    async def check_event_allowed(
        self,
        event: "synapse.events.EventBase",
        state_events: "synapse.types.StateMap",
    ) -> Tuple[bool, Optional[dict]]:
        event_dict = event.get_dict()
        new_event_content = await self.api.http_client.post_json_get_json(
            uri=self._endpoint, post_json=event_dict,
        )
        event_dict["content"] = new_event_content
        return event_dict
```