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
configuring modules in another part of Synapse's configuration file.

Currently, only the following pre-existing interfaces are compatible with this new system:

* spam checker
* third-party rules
* presence router
