# Spam checker callbacks

Spam checker callbacks allow module developers to implement spam mitigation actions for
Synapse instances. Spam checker callbacks can be registered using the module API's
`register_spam_checker_callbacks` method.

## Callbacks

The available spam checker callbacks are:

### `check_event_for_spam`

_First introduced in Synapse v1.37.0_
_Signature extended to support Allow and Code in Synapse v1.60.0_
_Boolean and string return value types deprecated in Synapse v1.60.0_

```python
async def check_event_for_spam(event: "synapse.module_api.EventBase") -> Union["synapse.module_api.ALLOW", "synapse.module_api.error.Codes", str, bool]
```

Called when receiving an event from a client or via federation. The callback must return either:
  - `synapse.module_api.ALLOW`, to allow the operation. Other callbacks
    may still decide to reject it.
  - `synapse.api.Codes` to reject the operation with an error code. In case
    of doubt, `synapse.api.error.Codes.FORBIDDEN` is a good error code.
  - (deprecated) a `str` to reject the operation and specify an error message. Note that clients
    typically will not localize the error message to the user's preferred locale.
  - (deprecated) on `False`, behave as `ALLOW`. Deprecated as confusing, as some
    callbacks in expect `True` to allow and others `True` to reject.
  - (deprecated) on `True`, behave as `synapse.api.error.Codes.FORBIDDEN`. Deprecated as confusing, as
    some callbacks in expect `True` to allow and others `True` to reject.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `synapse.module_api.ALLOW`, Synapse falls through to the next one. The value of the
first callback that does not return `synapse.module_api.ALLOW` will be used. If this happens, Synapse
will not call any of the subsequent implementations of this callback.

### `user_may_join_room`

_First introduced in Synapse v1.37.0_

```python
async def user_may_join_room(user: str, room: str, is_invited: bool) -> bool
```

Called when a user is trying to join a room. The module must return a `bool` to indicate
whether the user can join the room. Return `False` to prevent the user from joining the
room; otherwise return `True` to permit the joining.

The user is represented by their Matrix user ID (e.g.
`@alice:example.com`) and the room is represented by its Matrix ID (e.g.
`!room:example.com`). The module is also given a boolean to indicate whether the user
currently has a pending invite in the room.

This callback isn't called if the join is performed by a server administrator, or in the
context of a room creation.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `user_may_invite`

_First introduced in Synapse v1.37.0_

```python
async def user_may_invite(inviter: str, invitee: str, room_id: str) -> bool
```

Called when processing an invitation. The module must return a `bool` indicating whether
the inviter can invite the invitee to the given room. Both inviter and invitee are
represented by their Matrix user ID (e.g. `@alice:example.com`). Return `False` to prevent
the invitation; otherwise return `True` to permit it.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `user_may_send_3pid_invite`

_First introduced in Synapse v1.45.0_

```python
async def user_may_send_3pid_invite(
    inviter: str,
    medium: str,
    address: str,
    room_id: str,
) -> bool
```

Called when processing an invitation using a third-party identifier (also called a 3PID,
e.g. an email address or a phone number). The module must return a `bool` indicating
whether the inviter can invite the invitee to the given room. Return `False` to prevent
the invitation; otherwise return `True` to permit it.

The inviter is represented by their Matrix user ID (e.g. `@alice:example.com`), and the
invitee is represented by its medium (e.g. "email") and its address
(e.g. `alice@example.com`). See [the Matrix specification](https://matrix.org/docs/spec/appendices#pid-types)
for more information regarding third-party identifiers.

For example, a call to this callback to send an invitation to the email address
`alice@example.com` would look like this:

```python
await user_may_send_3pid_invite(
    "@bob:example.com",  # The inviter's user ID
    "email",  # The medium of the 3PID to invite
    "alice@example.com",  # The address of the 3PID to invite
    "!some_room:example.com",  # The ID of the room to send the invite into
)
```

**Note**: If the third-party identifier is already associated with a matrix user ID,
[`user_may_invite`](#user_may_invite) will be used instead.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `user_may_create_room`

_First introduced in Synapse v1.37.0_

```python
async def user_may_create_room(user: str) -> bool
```

Called when processing a room creation request. The module must return a `bool` indicating
whether the given user (represented by their Matrix user ID) is allowed to create a room.
Return `False` to prevent room creation; otherwise return `True` to permit it.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `user_may_create_room_alias`

_First introduced in Synapse v1.37.0_

```python
async def user_may_create_room_alias(user: str, room_alias: "synapse.types.RoomAlias") -> bool
```

Called when trying to associate an alias with an existing room. The module must return a
`bool` indicating whether the given user (represented by their Matrix user ID) is allowed
to set the given alias. Return `False` to prevent the alias creation; otherwise return 
`True` to permit it.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `user_may_publish_room`

_First introduced in Synapse v1.37.0_

```python
async def user_may_publish_room(user: str, room_id: str) -> bool
```

Called when trying to publish a room to the homeserver's public rooms directory. The
module must return a `bool` indicating whether the given user (represented by their
Matrix user ID) is allowed to publish the given room. Return `False` to prevent the
room from being published; otherwise return `True` to permit its publication.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `True`, Synapse falls through to the next one. The value of the first
callback that does not return `True` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `check_username_for_spam`

_First introduced in Synapse v1.37.0_

```python
async def check_username_for_spam(user_profile: synapse.module_api.UserProfile) -> bool
```

Called when computing search results in the user directory. The module must return a
`bool` indicating whether the given user should be excluded from user directory 
searches. Return `True` to indicate that the user is spammy and exclude them from 
search results; otherwise return `False`.

The profile is represented as a dictionary with the following keys:

* `user_id: str`. The Matrix ID for this user.
* `display_name: Optional[str]`. The user's display name, or `None` if this user
  has not set a display name.
* `avatar_url: Optional[str]`. The `mxc://` URL to the user's avatar, or `None`
  if this user has not set an avatar.

The module is given a copy of the original dictionary, so modifying it from within the
module cannot modify a user's profile when included in user directory search results.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `False`, Synapse falls through to the next one. The value of the first
callback that does not return `False` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `check_registration_for_spam`

_First introduced in Synapse v1.37.0_

```python
async def check_registration_for_spam(
    email_threepid: Optional[dict],
    username: Optional[str],
    request_info: Collection[Tuple[str, str]],
    auth_provider_id: Optional[str] = None,
) -> "synapse.spam_checker_api.RegistrationBehaviour"
```

Called when registering a new user. The module must return a `RegistrationBehaviour`
indicating whether the registration can go through or must be denied, or whether the user
may be allowed to register but will be shadow banned.

The arguments passed to this callback are:

* `email_threepid`: The email address used for registering, if any.
* `username`: The username the user would like to register. Can be `None`, meaning that
  Synapse will generate one later.
* `request_info`: A collection of tuples, which first item is a user agent, and which
  second item is an IP address. These user agents and IP addresses are the ones that were
  used during the registration process.
* `auth_provider_id`: The identifier of the SSO authentication provider, if any.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `RegistrationBehaviour.ALLOW`, Synapse falls through to the next one.
The value of the first callback that does not return `RegistrationBehaviour.ALLOW` will
be used. If this happens, Synapse will not call any of the subsequent implementations of
this callback.

### `check_media_file_for_spam`

_First introduced in Synapse v1.37.0_

```python
async def check_media_file_for_spam(
    file_wrapper: "synapse.rest.media.v1.media_storage.ReadableFileWrapper",
    file_info: "synapse.rest.media.v1._base.FileInfo",
) -> bool
```

Called when storing a local or remote file. The module must return a `bool` indicating
whether the given file should be excluded from the homeserver's media store. Return
`True` to prevent this file from being stored; otherwise return `False`.

If multiple modules implement this callback, they will be considered in order. If a
callback returns `False`, Synapse falls through to the next one. The value of the first
callback that does not return `False` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

### `should_drop_federated_event`

_First introduced in Synapse v1.60.0_

```python
async def should_drop_federated_event(event: "synapse.events.EventBase") -> bool
```

Called when checking whether a remote server can federate an event with us. **Returning
`True` from this function will silently drop a federated event and split-brain our view
of a room's DAG, and thus you shouldn't use this callback unless you know what you are
doing.**

If multiple modules implement this callback, they will be considered in order. If a
callback returns `False`, Synapse falls through to the next one. The value of the first
callback that does not return `False` will be used. If this happens, Synapse will not call
any of the subsequent implementations of this callback.

## Example

The example below is a module that implements the spam checker callback
`check_event_for_spam` to deny any message sent by users whose Matrix user IDs are
mentioned in a configured list, and registers a web resource to the path
`/_synapse/client/list_spam_checker/is_evil` that returns a JSON object indicating
whether the provided user appears in that list.

```python
import json
from typing import Union

from twisted.web.resource import Resource
from twisted.web.server import Request

from synapse.module_api import ModuleApi


class IsUserEvilResource(Resource):
    def __init__(self, config):
        super(IsUserEvilResource, self).__init__()
        self.evil_users = config.get("evil_users") or []

    def render_GET(self, request: Request):
        user = request.args.get(b"user")[0].decode()
        request.setHeader(b"Content-Type", b"application/json")
        return json.dumps({"evil": user in self.evil_users}).encode()


class ListSpamChecker:
    def __init__(self, config: dict, api: ModuleApi):
        self.api = api
        self.evil_users = config.get("evil_users") or []

        self.api.register_spam_checker_callbacks(
            check_event_for_spam=self.check_event_for_spam,
        )

        self.api.register_web_resource(
            path="/_synapse/client/list_spam_checker/is_evil",
            resource=IsUserEvilResource(config),
        )

    async def check_event_for_spam(self, event: "synapse.events.EventBase") -> Union[bool, str]:
        return event.sender not in self.evil_users
```
