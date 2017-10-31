Password auth provider modules
==============================

Password auth providers offer a way for server administrators to integrate
their Synapse installation with an existing authentication system.

A password auth provider is a Python class which is dynamically loaded into
Synapse, and provides a number of methods by which it can integrate with the
authentication system.

This document serves as a reference for those looking to implement their own
password auth providers.

Required methods
----------------

Password auth provider classes must provide the following methods:

*class* ``SomeProvider.parse_config``\(*config*)

    This method is passed the ``config`` object for this module from the
    homeserver configuration file.

    It should perform any appropriate sanity checks on the provided
    configuration, and return an object which is then passed into ``__init__``.

*class* ``SomeProvider``\(*config*, *account_handler*)

    The constructor is passed the config object returned by ``parse_config``,
    and a ``synapse.handlers.auth._AccountHandler`` object which allows the
    password provider to check if accounts exist and/or create new ones.

``someprovider.check_password``\(*user_id*, *password*)

    This is the method that actually does the work. It is passed a qualified
    ``@localpart:domain`` user id, and the password provided by the user.

    The method should return a Twisted ``Deferred`` object, which resolves to
    ``True`` if authentication is successful, and ``False`` if not.

Optional methods
----------------

Password provider classes may optionally provide the following methods.

*class* ``SomeProvider.get_db_schema_files()``

    This method, if implemented, should return an Iterable of ``(name,
    stream)`` pairs of database schema files. Each file is applied in turn at
    initialisation, and a record is then made in the database so that it is
    not re-applied on the next start.
