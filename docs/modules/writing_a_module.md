# Writing a module

A module is a Python class that uses Synapse's module API to interact with the
homeserver. It can register callbacks that Synapse will call on specific operations, as
well as web resources to attach to Synapse's web server.

When instantiated, a module is given its parsed configuration as well as an instance of
the `synapse.module_api.ModuleApi` class. The configuration is a dictionary, and is
either the output of the module's `parse_config` static method (see below), or the
configuration associated with the module in Synapse's configuration file.

See the documentation for the `ModuleApi` class
[here](https://github.com/matrix-org/synapse/blob/master/synapse/module_api/__init__.py).

## When Synapse runs with several modules configured

If Synapse is running with other modules configured, the order each module appears in
within the `modules` section of the Synapse configuration file might restrict what it can
or cannot register. See [this section](index.html#using-multiple-modules) for more
information.

On top of the rules listed in the link above, if a callback returns a value that should
cause the current operation to fail (e.g. if a callback checking an event returns with a
value that should cause the event to be denied), Synapse will fail the operation and
ignore any subsequent callbacks that should have been run after this one.

The documentation for each callback mentions how Synapse behaves when
multiple modules implement it.

## Handling the module's configuration

A module can implement the following static method:

```python
@staticmethod
def parse_config(config: dict) -> Any
```

This method is given a dictionary resulting from parsing the YAML configuration for the
module. It may modify it (for example by parsing durations expressed as strings (e.g.
"5d") into milliseconds, etc.), and return the modified dictionary. It may also verify
that the configuration is correct, and raise an instance of
`synapse.module_api.errors.ConfigError` if not.

## Registering a web resource

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

The provided resource is a Python class that implements Twisted's [IResource](https://docs.twistedmatrix.com/en/stable/api/twisted.web.resource.IResource.html)
interface (such as [Resource](https://docs.twistedmatrix.com/en/stable/api/twisted.web.resource.Resource.html)).

Only one resource can be registered for a given path. If several modules attempt to
register a resource for the same path, the module that appears first in Synapse's
configuration file takes priority.

Modules **must** register their web resources in their `__init__` method.

## Registering a callback

Modules can use Synapse's module API to register callbacks. Callbacks are functions that
Synapse will call when performing specific actions. Callbacks must be asynchronous (unless
specified otherwise), and are split in categories. A single module may implement callbacks
from multiple categories, and is under no obligation to implement all callbacks from the
categories it registers callbacks for.

Modules can register callbacks using one of the module API's `register_[...]_callbacks`
methods. The callback functions are passed to these methods as keyword arguments, with
the callback name as the argument name and the function as its value. A
`register_[...]_callbacks` method exists for each category.

Callbacks for each category can be found on their respective page of the
[Synapse documentation website](https://matrix-org.github.io/synapse).

## Caching

_Added in Synapse 1.74.0._

Modules can leverage Synapse's caching tools to manage their own cached functions. This
can be helpful for modules that need to repeatedly request the same data from the database
or a remote service.

Functions that need to be wrapped with a cache need to be decorated with a `@cached()`
decorator (which can be imported from `synapse.module_api`) and registered with the
[`ModuleApi.register_cached_function`](https://github.com/matrix-org/synapse/blob/release-v1.77/synapse/module_api/__init__.py#L888)
API when initialising the module. If the module needs to invalidate an entry in a cache,
it needs to use the [`ModuleApi.invalidate_cache`](https://github.com/matrix-org/synapse/blob/release-v1.77/synapse/module_api/__init__.py#L904)
API, with the function to invalidate the cache of and the key(s) of the entry to
invalidate.

Below is an example of a simple module using a cached function:

```python
from typing import Any
from synapse.module_api import cached, ModuleApi

class MyModule:
    def __init__(self, config: Any, api: ModuleApi):
        self.api = api
        
        # Register the cached function so Synapse knows how to correctly invalidate
        # entries for it.
        self.api.register_cached_function(self.get_user_from_id)

    @cached()
    async def get_department_for_user(self, user_id: str) -> str:
        """A function with a cache."""
        # Request a department from an external service.
        return await self.http_client.get_json(
            "https://int.example.com/users", {"user_id": user_id)
        )["department"]

    async def do_something_with_users(self) -> None:
        """Calls the cached function and then invalidates an entry in its cache."""
        
        user_id = "@alice:example.com"
        
        # Get the user. Since get_department_for_user is wrapped with a cache,
        # the return value for this user_id will be cached.
        department = await self.get_department_for_user(user_id)
        
        # Do something with `department`...
        
        # Let's say something has changed with our user, and the entry we have for
        # them in the cache is out of date, so we want to invalidate it.
        await self.api.invalidate_cache(self.get_department_for_user, (user_id,))
```

See the [`cached` docstring](https://github.com/matrix-org/synapse/blob/release-v1.77/synapse/module_api/__init__.py#L190) for more details.
