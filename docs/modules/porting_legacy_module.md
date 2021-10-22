# Porting an existing module that uses the old interface

In order to port a module that uses Synapse's old module interface, its author needs to:

* ensure the module's callbacks are all asynchronous.
* register their callbacks using one or more of the `register_[...]_callbacks` methods
  from the `ModuleApi` class in the module's `__init__` method (see [this section](writing_a_module.html#registering-a-callback)
  for more info).

Additionally, if the module is packaged with an additional web resource, the module
should register this resource in its `__init__` method using the `register_web_resource`
method from the `ModuleApi` class (see [this section](writing_a_module.html#registering-a-web-resource) for
more info).

There is no longer a `get_db_schema_files` callback provided for password auth provider modules. Any
changes to the database should now be made by the module using the module API class.

The module's author should also update any example in the module's configuration to only
use the new `modules` section in Synapse's configuration file (see [this section](index.html#using-modules)
for more info).
