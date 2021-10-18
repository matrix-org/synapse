# Modules

Synapse supports extending its functionality by configuring external modules.

**Note**: When using third-party modules, you effectively allow someone else to run
custom code on your Synapse homeserver. Server admins are encouraged to verify the
provenance of the modules they use on their homeserver and make sure the modules aren't
running malicious code on their instance.

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

## Using multiple modules

The order in which modules are listed in this section is important. When processing an
action that can be handled by several modules, Synapse will always prioritise the module
that appears first (i.e. is the highest in the list). This means:

* If several modules register the same callback, the callback registered by the module
  that appears first is used.
* If several modules try to register a handler for the same HTTP path, only the handler
  registered by the module that appears first is used. Handlers registered by the other
  module(s) are ignored and Synapse will log a warning message about them.

Note that Synapse doesn't allow multiple modules implementing authentication checkers via
the password auth provider feature for the same login type with different fields. If this
happens, Synapse will refuse to start.

## Current status

We are currently in the process of migrating module interfaces to this system. While some
interfaces might be compatible with it, others still require configuring modules in
another part of Synapse's configuration file.

Currently, only the following pre-existing interfaces are compatible with this new system:

* spam checker
* third-party rules
* presence router
* password auth providers
