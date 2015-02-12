Upgrading to v0.7.0
===================

New dependencies are:

- pydenticon
- simplejson
- syutil
- matrix-angular-sdk

To pull in these dependencies in a virtual env, run::

    python synapse/python_dependencies.py | xargs -n 1 pip install

Upgrading to v0.6.0
===================

To pull in new dependencies, run::

    python setup.py develop --user

This update includes a change to the database schema. To upgrade you first need
to upgrade the database by running::

    python scripts/upgrade_db_to_v0.6.0.py <db> <server_name> <signing_key>

Where `<db>` is the location of the database, `<server_name>` is the
server name as specified in the synapse configuration, and `<signing_key>` is
the location of the signing key as specified in the synapse configuration.

This may take some time to complete. Failures of signatures and content hashes
can safely be ignored.


Upgrading to v0.5.1
===================

Depending on precisely when you installed v0.5.0 you may have ended up with
a stale release of the reference matrix webclient installed as a python module.
To uninstall it and ensure you are depending on the latest module, please run::

    $ pip uninstall syweb

Upgrading to v0.5.0
===================

The webclient has been split out into a seperate repository/pacakage in this
release. Before you restart your homeserver you will need to pull in the
webclient package by running::

  python setup.py develop --user

This release completely changes the database schema and so requires upgrading
it before starting the new version of the homeserver.

The script "database-prepare-for-0.5.0.sh" should be used to upgrade the
database. This will save all user information, such as logins and profiles, 
but will otherwise purge the database. This includes messages, which
rooms the home server was a member of and room alias mappings.

If you would like to keep your history, please take a copy of your database
file and ask for help in #matrix:matrix.org. The upgrade process is,
unfortunately, non trivial and requires human intervention to resolve any
resulting conflicts during the upgrade process.

Before running the command the homeserver should be first completely 
shutdown. To run it, simply specify the location of the database, e.g.:

  ./scripts/database-prepare-for-0.5.0.sh "homeserver.db"

Once this has successfully completed it will be safe to restart the 
homeserver. You may notice that the homeserver takes a few seconds longer to 
restart than usual as it reinitializes the database.

On startup of the new version, users can either rejoin remote rooms using room
aliases or by being reinvited. Alternatively, if any other homeserver sends a
message to a room that the homeserver was previously in the local HS will 
automatically rejoin the room.

Upgrading to v0.4.0
===================

This release needs an updated syutil version. Run::

    python setup.py develop

You will also need to upgrade your configuration as the signing key format has
changed. Run::

    python -m synapse.app.homeserver --config-path <CONFIG> --generate-config


Upgrading to v0.3.0
===================

This registration API now closely matches the login API. This introduces a bit
more backwards and forwards between the HS and the client, but this improves
the overall flexibility of the API. You can now GET on /register to retrieve a list
of valid registration flows. Upon choosing one, they are submitted in the same
way as login, e.g::

  {
    type: m.login.password,
    user: foo,
    password: bar
  }

The default HS supports 2 flows, with and without Identity Server email
authentication. Enabling captcha on the HS will add in an extra step to all
flows: ``m.login.recaptcha`` which must be completed before you can transition
to the next stage. There is a new login type: ``m.login.email.identity`` which
contains the ``threepidCreds`` key which were previously sent in the original
register request. For more information on this, see the specification.

Web Client
----------

The VoIP specification has changed between v0.2.0 and v0.3.0. Users should
refresh any browser tabs to get the latest web client code. Users on
v0.2.0 of the web client will not be able to call those on v0.3.0 and
vice versa.


Upgrading to v0.2.0
===================

The home server now requires setting up of SSL config before it can run. To
automatically generate default config use::

    $ python synapse/app/homeserver.py \
        --server-name machine.my.domain.name \
        --bind-port 8448 \
        --config-path homeserver.config \
        --generate-config

This config can be edited if desired, for example to specify a different SSL 
certificate to use. Once done you can run the home server using::

    $ python synapse/app/homeserver.py --config-path homeserver.config

See the README.rst for more information.

Also note that some config options have been renamed, including:

- "host" to "server-name"
- "database" to "database-path"
- "port" to "bind-port" and "unsecure-port"


Upgrading to v0.0.1
===================

This release completely changes the database schema and so requires upgrading
it before starting the new version of the homeserver.

The script "database-prepare-for-0.0.1.sh" should be used to upgrade the
database. This will save all user information, such as logins and profiles, 
but will otherwise purge the database. This includes messages, which
rooms the home server was a member of and room alias mappings.

Before running the command the homeserver should be first completely 
shutdown. To run it, simply specify the location of the database, e.g.:

  ./scripts/database-prepare-for-0.0.1.sh "homeserver.db"

Once this has successfully completed it will be safe to restart the 
homeserver. You may notice that the homeserver takes a few seconds longer to 
restart than usual as it reinitializes the database.

On startup of the new version, users can either rejoin remote rooms using room
aliases or by being reinvited. Alternatively, if any other homeserver sends a
message to a room that the homeserver was previously in the local HS will 
automatically rejoin the room.
