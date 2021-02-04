# User Directory API Implementation

The user directory is currently maintained based on the 'visible' users
on this particular server - i.e. ones which your account shares a room with, or
who are present in a publicly viewable room present on the server.

The directory info is stored in various tables, which can (typically after
DB corruption) get stale or out of sync.  If this happens, for now the
solution to fix it is to execute the SQL [here](../synapse/storage/databases/main/schema/delta/53/user_dir_populate.sql)
and then restart synapse. This should then start a background task to
flush the current tables and regenerate the directory.

## Custom User Directory Search Modules

Syanpse can be configured to make use of custom modules that modify the results from a user 
directory query. These are standard python modules containing a class that implements all or a 
subset of required methods. These are then called by Synapse's `UserDirectorySearchModule` 
class. Example implementations of this module are:

* https://github.com/matrix-org/matrix-synapse-user-directory-search-dinum

### Available methods

#### parse_config

As with all Synapse modules, your class must implement the static method `parse_config` with 
the following signature:

```python
@staticmethod
def parse_config(config: dict) -> Any
```

`parse_config` is the first method to be called on your module, and will be passed a python 
dictionary derived from the options specified in the homeserver config file for your module.
`parse_config` can return any type, and that return value will be given as the `config`
argument to your class's `__init__` method during initialisation.

#### \_\_init\_\_

Your class must implement an `__init__` method with the following signature:

```python
def __init__(
    self,
    config: Any,
    database_engine_type: synapse.storage.engines.BaseDatabaseEngine,
    module_api: synapse.module_api.ModuleApi,
) -> None
```

For each argument:

* `config` - The return value from `parse_config`, containing any variables that may change 
  the behaviour of your module.
* `database_engine_type` - The type of database engine currently in use by the server - one 
  of the engine classes defined under [synapse/storage/engines/](../synapse/storage/engines)
  (i.e `PostgresEngine`, `Sqlite3Engine`). Useful for determining user 
  directory-related queries to run on the database.
* `module_api` - An instance of Synapse's [ModuleApi class](../synapse/module_api/__init__.py), 
  which provides many methods for modules to get or set parts of the running Synapse instance.
  
`__init__` is called after `parse_config` during homeserver initialisation.
  
#### get_search_query_ordering

```python
get_search_query_ordering(self) -> str
```

This method is optional. If defined, it is called each time a user directory search is performed.

`get_search_query_ordering` allows modifying the ordering of user directory search 
results by returning an SQL string that will be used as the `ORDER BY` clause when 
retrieving user directory search results from the database. The full query that the clause 
is inserted into can be found in
[`UserDirectoryStore.search_user_dir`](../synapse/storage/databases/main/user_directory.py),
and depends on the database engine in use.

### Synapse configuration

For Synapse to load your module during initialisation, the `user_directory.enabled` 
homeserver config option must be true, and the `user_directory.user_directory_search_module` 
option must be filled out. The [sample homeserver config](sample_config.yaml) provides an example 
configuration and a description of each option. The contents of the `config` option is 
what is passed to your module's `parse_config` method after being converted from a YAML to a 
python dictionary.
