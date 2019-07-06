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
    and a ``synapse.module_api.ModuleApi`` object which allows the
    password provider to check if accounts exist and/or create new ones.

Optional methods
----------------

Password auth provider classes may optionally provide the following methods.

*class* ``SomeProvider.get_db_schema_files``\()

    This method, if implemented, should return an Iterable of ``(name,
    stream)`` pairs of database schema files. Each file is applied in turn at
    initialisation, and a record is then made in the database so that it is
    not re-applied on the next start.

``someprovider.get_supported_login_types``\()

    This method, if implemented, should return a ``dict`` mapping from a login
    type identifier (such as ``m.login.password``) to an iterable giving the
    fields which must be provided by the user in the submission to the
    ``/login`` api. These fields are passed in the ``login_dict`` dictionary
    to ``check_auth``.

    For example, if a password auth provider wants to implement a custom login
    type of ``com.example.custom_login``, where the client is expected to pass
    the fields ``secret1`` and ``secret2``, the provider should implement this
    method and return the following dict::

      {"com.example.custom_login": ("secret1", "secret2")}

``someprovider.check_auth``\(*username*, *login_type*, *login_dict*)

    This method is the one that does the real work. If implemented, it will be
    called for each login attempt where the login type matches one of the keys
    returned by ``get_supported_login_types``.

    It is passed the (possibly UNqualified) ``user`` provided by the client,
    the login type, and a dictionary of login secrets passed by the client.

    The method should return a Twisted ``Deferred`` object, which resolves to
    the canonical ``@localpart:domain`` user id if authentication is successful,
    and ``None`` if not.

    Alternatively, the ``Deferred`` can resolve to a ``(str, func)`` tuple, in
    which case the second field is a callback which will be called with the
    result from the ``/login`` call (including ``access_token``, ``device_id``,
    etc.)

``someprovider.check_3pid_auth``\(*medium*, *address*, *password*)

    This method, if implemented, is called when a user attempts to register or
    log in with a third party identifier, such as email. It is passed the
    medium (ex. "email"), an address (ex. "jdoe@example.com") and the user's
    password.

    The method should return a Twisted ``Deferred`` object, which resolves to
    a ``str`` containing the user's (canonical) User ID if authentication was
    successful, and ``None`` if not.

    As with ``check_auth``, the ``Deferred`` may alternatively resolve to a
    ``(user_id, callback)`` tuple.

``someprovider.check_password``\(*user_id*, *password*)

    This method provides a simpler interface than ``get_supported_login_types``
    and ``check_auth`` for password auth providers that just want to provide a
    mechanism for validating ``m.login.password`` logins.

    Iif implemented, it will be called to check logins with an
    ``m.login.password`` login type. It is passed a qualified
    ``@localpart:domain`` user id, and the password provided by the user.

    The method should return a Twisted ``Deferred`` object, which resolves to
    ``True`` if authentication is successful, and ``False`` if not.

``someprovider.on_logged_out``\(*user_id*, *device_id*, *access_token*)

    This method, if implemented, is called when a user logs out. It is passed
    the qualified user ID, the ID of the deactivated device (if any: access
    tokens are occasionally created without an associated device ID), and the
    (now deactivated) access token.

    It may return a Twisted ``Deferred`` object; the logout request will wait
    for the deferred to complete but the result is ignored.
