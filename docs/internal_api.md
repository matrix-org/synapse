<!-- Maintainer note: This document is written in Github Flavoured Markdown -->

# Internal Synapse API

Synapse provides a limited internal API for 3rd party modules to listen to operations going on inside the server. For example, modules may listen for when a new room alias association is created and react upon that. The API can be enabled in your configuration using the following configuration:

```yaml
internal_api:
  module: "my_custom_project.MyCoolSynapseHook"
  config:
    example_option: "some_value"
```

## Module template

The following template can be used to get your 3rd party module off the ground:

```python
class MyCoolSynapseHook(object):
  def __init__(self, config, api):
    # This is where your init routine would go
    self._config = config  # The config from the homeserver.yaml
    self._api = api  # A reference to the InternalApi in synapse
    
    # This is required by synapse. Here you can parse and validate your configuration.
    # Be sure to return the object you expect in your constructor.
    @staticmethod
    def parse_config(config):
        return config

  # Your event handlers and other application logic goes here.
```

## Listening for informational events

Informational events are events that your module cannot modify or interrupt, but can react to. To listen to events, add a function named `on_` followed by the event name. The only argument given is the event body.

Here's an example listener:
```python
def on_some_event(self, event):
  # This is where you'd do something interesting. `event` contains the event body.
  pass
```

## Available events

#### `room_directory_association_created`
Fired when a new room alias has been successfully associated to a room.

Event body:
```python
{
  "room_alias": "#the_new_alias:server.com",
  "room_id": "!somewhere:server.com",
  "servers": ["server.com", "another.com"],
  "creator": "@someone:server.com"
}
```

## Accessing synapse from your module

**CAUTION**: The synapse code base should be considered highly volatile and may change at any time! Hooking in to the homeserver directly is dangerous and can cause unexpected results or may break between releases, even minor ones.

With that being said, if you *really* want to use the homeserver, the `synapse.server.HomeServer` object is exposed on the `api` (`synapse.internal_api.InternalApi`) object given to your constructor as `hs`.
