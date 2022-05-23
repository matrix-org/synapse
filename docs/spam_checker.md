<h2 style="color:red">
This page of the Synapse documentation is now deprecated. For up to date
documentation on setting up or writing a spam checker module, please see
<a href="modules.md">this page</a>.
</h2>

# Handling spam in Synapse

Synapse has support to customize spam checking behavior. It can plug into a
variety of events and affect how they are presented to users on your homeserver.

The spam checking behavior is implemented as a Python class, which must be
able to be imported by the running Synapse.

## Python spam checker class

The Python class is instantiated with two objects:

* Any configuration (see below).
* An instance of `synapse.module_api.ModuleApi`.

It then implements methods which return a boolean to alter behavior in Synapse.
All the methods must be defined.

There's a generic method for checking every event (`check_event_for_spam`), as
well as some specific methods:

* `user_may_invite`
* `user_may_create_room`
* `user_may_create_room_alias`
* `user_may_publish_room`
* `check_username_for_spam`
* `check_registration_for_spam`
* `check_media_file_for_spam`

The details of each of these methods (as well as their inputs and outputs)
are documented in the `synapse.events.spamcheck.SpamChecker` class.

The `ModuleApi` class provides a way for the custom spam checker class to
call back into the homeserver internals.

Additionally, a `parse_config` method is mandatory and receives the plugin config
dictionary. After parsing, It must return an object which will be
passed to `__init__` later.

### Example

```python
from synapse.spam_checker_api import RegistrationBehaviour

class ExampleSpamChecker:
    def __init__(self, config, api):
        self.config = config
        self.api = api

    @staticmethod
    def parse_config(config):
        return config
        
    async def check_event_for_spam(self, foo):
        return False  # allow all events

    async def user_may_invite(self, inviter_userid, invitee_userid, room_id):
        return True  # allow all invites

    async def user_may_create_room(self, userid):
        return True  # allow all room creations

    async def user_may_create_room_alias(self, userid, room_alias):
        return True  # allow all room aliases

    async def user_may_publish_room(self, userid, room_id):
        return True  # allow publishing of all rooms

    async def check_username_for_spam(self, user_profile):
        return False  # allow all usernames

    async def check_registration_for_spam(
        self,
        email_threepid,
        username,
        request_info,
        auth_provider_id,
    ):
        return RegistrationBehaviour.ALLOW  # allow all registrations

    async def check_media_file_for_spam(self, file_wrapper, file_info):
        return False  # allow all media
```

## Configuration

Modify the `spam_checker` section of your `homeserver.yaml` in the following
manner:

Create a list entry with the keys `module` and `config`.

* `module` should point to the fully qualified Python class that implements your
  custom logic, e.g. `my_module.ExampleSpamChecker`.

* `config` is a dictionary that gets passed to the spam checker class.

### Example

This section might look like:

```yaml
spam_checker:
  - module: my_module.ExampleSpamChecker
    config:
      # Enable or disable a specific option in ExampleSpamChecker.
      my_custom_option: true
```

More spam checkers can be added in tandem by appending more items to the list. An
action is blocked when at least one of the configured spam checkers flags it.

## Examples

The [Mjolnir](https://github.com/matrix-org/mjolnir) project is a full fledged
example using the Synapse spam checking API, including a bot for dynamic
configuration.
