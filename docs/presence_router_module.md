# Presence Router Module

Synapse supports configuring a module that can specify additional users
(local or remote) to should receive certain presence updates from local
users.

Note that routing presence via Application Service transactions is not
currently supported.

The presence routing module is implemented as a Python class, which will
be imported by the running Synapse.

## Python Presence Router Class

The Python class is instantiated with two objects:

* A configuration object of some type (see below).
* An instance of `synapse.module_api.ModuleApi`.

It then implements methods related to presence routing.

Note that one method of `ModuleApi` that may be useful is:

```python
async def ModuleApi.send_local_online_presence_to(users: Iterable[str]) -> None
```

which can be given a list of local or remote MXIDs to broadcast known, online user
presence to (for those users that the receiving user is considered interested in). 
It does not include state for users who are currently offline, and it can only be
called on workers that support sending federation. Additionally, this method must
only be called from the process that has been configured to write to the
the [presence stream](https://github.com/matrix-org/synapse/blob/master/docs/workers.md#stream-writers).
By default, this is the main process, but another worker can be configured to do
so.

### Module structure

Below is a list of possible methods that can be implemented, and whether they are
required.

#### `parse_config`

```python
def parse_config(config_dict: dict) -> Any
```

**Required.** A static method that is passed a dictionary of config options, and
  should return a validated config object. This method is described further in
  [Configuration](#configuration).

#### `get_users_for_states`

```python
async def get_users_for_states(
    self,
    state_updates: Iterable[UserPresenceState],
) -> Dict[str, Set[UserPresenceState]]:
```

**Required.** An asynchronous method that is passed an iterable of user presence
state. This method can determine whether a given presence update should be sent to certain
users. It does this by returning a dictionary with keys representing local or remote
Matrix User IDs, and values being a python set
of `synapse.handlers.presence.UserPresenceState` instances.

Synapse will then attempt to send the specified presence updates to each user when
possible.

#### `get_interested_users`

```python
async def get_interested_users(self, user_id: str) -> Union[Set[str], str]
```

**Required.** An asynchronous method that is passed a single Matrix User ID. This
method is expected to return the users that the passed in user may be interested in the
presence of. Returned users may be local or remote. The presence routed as a result of
what this method returns is sent in addition to the updates already sent between users
that share a room together. Presence updates are deduplicated.

This method should return a python set of Matrix User IDs, or the object
`synapse.events.presence_router.PresenceRouter.ALL_USERS` to indicate that the passed
user should receive presence information for *all* known users.

For clarity, if the user `@alice:example.org` is passed to this method, and the Set
`{"@bob:example.com", "@charlie:somewhere.org"}` is returned, this signifies that Alice
should receive presence updates sent by Bob and Charlie, regardless of whether these
users share a room.

### Example

Below is an example implementation of a presence router class.

```python
from typing import Dict, Iterable, Set, Union
from synapse.events.presence_router import PresenceRouter
from synapse.handlers.presence import UserPresenceState
from synapse.module_api import ModuleApi

class PresenceRouterConfig:
    def __init__(self):
        # Config options with their defaults
        # A list of users to always send all user presence updates to
        self.always_send_to_users = []  # type: List[str]
        
        # A list of users to ignore presence updates for. Does not affect
        # shared-room presence relationships
        self.blacklisted_users = []  # type: List[str]

class ExamplePresenceRouter:
    """An example implementation of synapse.presence_router.PresenceRouter.
    Supports routing all presence to a configured set of users, or a subset
    of presence from certain users to members of certain rooms.

    Args:
        config: A configuration object.
        module_api: An instance of Synapse's ModuleApi.
    """
    def __init__(self, config: PresenceRouterConfig, module_api: ModuleApi):
        self._config = config
        self._module_api = module_api

    @staticmethod
    def parse_config(config_dict: dict) -> PresenceRouterConfig:
        """Parse a configuration dictionary from the homeserver config, do
        some validation and return a typed PresenceRouterConfig.

        Args:
            config_dict: The configuration dictionary.

        Returns:
            A validated config object.
        """
        # Initialise a typed config object
        config = PresenceRouterConfig()
        always_send_to_users = config_dict.get("always_send_to_users")
        blacklisted_users = config_dict.get("blacklisted_users")

        # Do some validation of config options... otherwise raise a
        # synapse.config.ConfigError.
        config.always_send_to_users = always_send_to_users
        config.blacklisted_users = blacklisted_users

        return config

    async def get_users_for_states(
        self,
        state_updates: Iterable[UserPresenceState],
    ) -> Dict[str, Set[UserPresenceState]]:
        """Given an iterable of user presence updates, determine where each one
        needs to go. Returned results will not affect presence updates that are
        sent between users who share a room.

        Args:
            state_updates: An iterable of user presence state updates.

        Returns:
          A dictionary of user_id -> set of UserPresenceState that the user should 
          receive.
        """
        destination_users = {}  # type: Dict[str, Set[UserPresenceState]

        # Ignore any updates for blacklisted users
        desired_updates = set()
        for update in state_updates:
            if update.state_key not in self._config.blacklisted_users:
                desired_updates.add(update)

        # Send all presence updates to specific users
        for user_id in self._config.always_send_to_users:
            destination_users[user_id] = desired_updates

        return destination_users

    async def get_interested_users(
        self,
        user_id: str,
    ) -> Union[Set[str], PresenceRouter.ALL_USERS]:
        """
        Retrieve a list of users that `user_id` is interested in receiving the
        presence of. This will be in addition to those they share a room with.
        Optionally, the object PresenceRouter.ALL_USERS can be returned to indicate
        that this user should receive all incoming local and remote presence updates.

        Note that this method will only be called for local users.

        Args:
          user_id: A user requesting presence updates.

        Returns:
          A set of user IDs to return additional presence updates for, or
          PresenceRouter.ALL_USERS to return presence updates for all other users.
        """
        if user_id in self._config.always_send_to_users:
            return PresenceRouter.ALL_USERS

        return set()
```

#### A note on `get_users_for_states` and `get_interested_users`

Both of these methods are effectively two different sides of the same coin. The logic
regarding which users should receive updates for other users should be the same 
between them.

`get_users_for_states` is called when presence updates come in from either federation 
or local users, and is used to either direct local presence to remote users, or to
wake up the sync streams of local users to collect remote presence.

In contrast, `get_interested_users` is used to determine the users that presence should
be fetched for when a local user is syncing. This presence is then retrieved, before
being fed through `get_users_for_states` once again, with only the syncing user's
routing information pulled from the resulting dictionary.

Their routing logic should thus line up, else you may run into unintended behaviour.

## Configuration

Once you've crafted your module and installed it into the same Python environment as
Synapse, amend your homeserver config file with the following.

```yaml
presence:
  routing_module:
    module: my_module.ExamplePresenceRouter
    config:
      # Any configuration options for your module. The below is an example.
      # of setting options for ExamplePresenceRouter.
      always_send_to_users: ["@presence_gobbler:example.org"]
      blacklisted_users:
        - "@alice:example.com"
        - "@bob:example.com"
      ...
```

The contents of `config` will be passed as a Python dictionary to the static
`parse_config` method of your class. The object returned by this method will
then be passed to the `__init__` method of your module as `config`.
