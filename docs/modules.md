# Modules

Synapse supports extending its functionality by configuring external modules.

## Using modules

To use a module on Synapse, add it to the `modules` section of the configuration file:

```yaml
modules:
  - module: my_super_module.MySuperClass
    config:
      do_thing: true
  - module: my_other_super_module.SomeClass
    config: {}
```

Each module is defined by a path to a Python class as well as a configuration. This
information for a given module should be available in the module's own documentation.

**Note**: When using third-party modules, you effectively allow someone else to run
custom code on your Synapse homeserver. Server admins are encouraged to verify the
provenance of the modules they use on their homeserver and make sure the modules aren't
running malicious code on their instance.

Also note that we are currently in the process of migrating module interfaces to this
system. While some interfaces might be compatible with it, others still require
configuring modules in another part of Synapse's configuration file. Currently, only the
spam checker interface is compatible with this new system.

## Writing a module

A module is a Python class that uses Synapse's module API to interact with the
homeserver. It can register callbacks that Synapse will call on specific operations, as
well as web resources to attach to Synapse's web server.

When instantiated, a module is given its parsed configuration as well as an instance of
the `synapse.module_api.ModuleApi` class. The configuration is a dictionary, and is
either the output of the module's `parse_config` static method (see below), or the
configuration associated with the module in Synapse's configuration file.

See the documentation for the `ModuleApi` class
[here](https://github.com/matrix-org/synapse/blob/master/synapse/module_api/__init__.py).

### Handling the module's configuration

A module can implement the following static method:

```python
@staticmethod
def parse_config(config: dict) -> dict
```

This method is given a dictionary resulting from parsing the YAML configuration for the
module. It may modify it (for example by parsing durations expressed as strings (e.g.
"5d") into milliseconds, etc.), and return the modified dictionary. It may also verify
that the configuration is correct, and raise an instance of
`synapse.module_api.errors.ConfigError` if not.

### Registering a web resource

Modules can register web resources onto Synapse's web server using the following module
API method:

```python
def ModuleApi.register_web_resource(path: str, resource: IResource) -> None
```

The path is the full absolute path to register the resource at. For example, if you
register a resource for the path `/_synapse/client/my_super_module/say_hello`, Synapse
will serve it at `http(s)://[HS_URL]/_synapse/client/my_super_module/say_hello`. Note
that Synapse does not allow registering resources for several sub-paths in the `/_matrix`
namespace (such as anything under `/_matrix/client` for example). It is strongly
recommended that modules register their web resources under the `/_synapse/client`
namespace.

The provided resource is a Python class that implements Twisted's [IResource](https://twistedmatrix.com/documents/current/api/twisted.web.resource.IResource.html)
interface (such as [Resource](https://twistedmatrix.com/documents/current/api/twisted.web.resource.Resource.html)).

Only one resource can be registered for a given path. If several modules attempt to
register a resource for the same path, the module that appears first in Synapse's
configuration file takes priority.

Modules **must** register their web resources in their `__init__` method.

### Registering a callback

Modules can use Synapse's module API to register callbacks. Callbacks are functions that
Synapse will call when performing specific actions. Callbacks must be asynchronous, and
are split in categories. A single module may implement callbacks from multiple categories,
and is under no obligation to implement all callbacks from the categories it registers
callbacks for.

Modules can register callbacks using one of the module API's `register_[...]_callbacks`
methods. The callback functions are passed to these methods as keyword arguments, with
the callback name as the argument name and the function as its value. This is demonstrated
in the example below. A `register_[...]_callbacks` method exists for each module type
documented in this section.

#### Spam checker callbacks

Spam checker callbacks allow module developers to implement spam mitigation actions for
Synapse instances. Spam checker callbacks can be registered using the module API's
`register_spam_checker_callbacks` method.

The available spam checker callbacks are:

```python
async def check_event_for_spam(event: "synapse.events.EventBase") -> Union[bool, str]
```

Called when receiving an event from a client or via federation. The module can return
either a `bool` to indicate whether the event must be rejected because of spam, or a `str`
to indicate the event must be rejected because of spam and to give a rejection reason to
forward to clients.

```python
async def user_may_invite(inviter: str, invitee: str, room_id: str) -> bool
```

Called when processing an invitation. The module must return a `bool` indicating whether
the inviter can invite the invitee to the given room. Both inviter and invitee are
represented by their Matrix user ID (e.g. `@alice:example.com`).

```python
async def user_may_create_room(user: str) -> bool
```

Called when processing a room creation request. The module must return a `bool` indicating
whether the given user (represented by their Matrix user ID) is allowed to create a room.

```python
async def user_may_create_room_alias(user: str, room_alias: "synapse.types.RoomAlias") -> bool
```

Called when trying to associate an alias with an existing room. The module must return a
`bool` indicating whether the given user (represented by their Matrix user ID) is allowed
to set the given alias.

```python
async def user_may_publish_room(user: str, room_id: str) -> bool
```

Called when trying to publish a room to the homeserver's public rooms directory. The
module must return a `bool` indicating whether the given user (represented by their
Matrix user ID) is allowed to publish the given room.

```python
async def check_username_for_spam(user_profile: Dict[str, str]) -> bool
```

Called when computing search results in the user directory. The module must return a
`bool` indicating whether the given user profile can appear in search results. The profile
is represented as a dictionary with the following keys:

* `user_id`: The Matrix ID for this user.
* `display_name`: The user's display name.
* `avatar_url`: The `mxc://` URL to the user's avatar.

The module is given a copy of the original dictionary, so modifying it from within the
module cannot modify a user's profile when included in user directory search results.

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

```python
async def check_media_file_for_spam(
    file_wrapper: "synapse.rest.media.v1.media_storage.ReadableFileWrapper",
    file_info: "synapse.rest.media.v1._base.FileInfo",
) -> bool
```

Called when storing a local or remote file. The module must return a boolean indicating
whether the given file can be stored in the homeserver's media store.

#### Account validity callbacks

Account validity callbacks allow module developers to add extra steps to verify the
validity on an account, i.e. see if a user can be granted access to their account on the
Synapse instance. Account validity callbacks can be registered using the module API's
`register_account_validity_callbacks` method.

The available account validity callbacks are:

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

```python
async def on_user_registration(user: str) -> None
```

Called after successfully registering a user, in case the module needs to perform extra
operations to keep track of them. (e.g. add them to a database table). The user is
represented by their Matrix user ID.

#### Third party rules callbacks

Third party rules callbacks allow module developers to add extra checks to verify the
validity of incoming events. Third party event rules callbacks can be registered using
the module API's `register_third_party_rules_callbacks` method.

The available third party rules callbacks are:

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

Note that replacing the event only works for events sent by local users, not for events
received over federation.

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


### Porting an existing module that uses the old interface

In order to port a module that uses Synapse's old module interface, its author needs to:

* ensure the module's callbacks are all asynchronous.
* register their callbacks using one or more of the `register_[...]_callbacks` methods
  from the `ModuleApi` class in the module's `__init__` method (see [this section](#registering-a-callback)
  for more info).

Additionally, if the module is packaged with an additional web resource, the module
should register this resource in its `__init__` method using the `register_web_resource`
method from the `ModuleApi` class (see [this section](#registering-a-web-resource) for
more info).

The module's author should also update any example in the module's configuration to only
use the new `modules` section in Synapse's configuration file (see [this section](#using-modules)
for more info).

### Example

The example below is a module that implements the spam checker callback
`user_may_create_room` to deny room creation to user `@evilguy:example.com`, and registers
a web resource to the path `/_synapse/client/demo/hello` that returns a JSON object.

```python
import json

from twisted.web.resource import Resource
from twisted.web.server import Request

from synapse.module_api import ModuleApi


class DemoResource(Resource):
    def __init__(self, config):
        super(DemoResource, self).__init__()
        self.config = config

    def render_GET(self, request: Request):
        name = request.args.get(b"name")[0]
        request.setHeader(b"Content-Type", b"application/json")
        return json.dumps({"hello": name})


class DemoModule:
    def __init__(self, config: dict, api: ModuleApi):
        self.config = config
        self.api = api

        self.api.register_web_resource(
            path="/_synapse/client/demo/hello",
            resource=DemoResource(self.config),
        )

        self.api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
        )

    @staticmethod
    def parse_config(config):
        return config

    async def user_may_create_room(self, user: str) -> bool:
        if user == "@evilguy:example.com":
            return False

        return True
```
