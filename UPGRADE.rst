Upgrading Synapse
=================

Before upgrading check if any special steps are required to upgrade from the
what you currently have installed to current version of synapse. The extra
instructions that may be required are listed later in this document.

1. If synapse was installed in a virtualenv then active that virtualenv before
   upgrading. If synapse is installed in a virtualenv in ``~/.synapse/`` then
   run:

   .. code:: bash

       source ~/.synapse/bin/activate

2. If synapse was installed using pip then upgrade to the latest version by
   running:

   .. code:: bash

       pip install --upgrade --process-dependency-links matrix-synapse

       # restart synapse
       synctl restart


   If synapse was installed using git then upgrade to the latest version by
   running:

   .. code:: bash

       # Pull the latest version of the master branch.
       git pull
       # Update the versions of synapse's python dependencies.
       python synapse/python_dependencies.py | xargs pip install --upgrade

       # restart synapse
       ./synctl restart


To check whether your update was sucessful, you can check the Server header
returned by the Client-Server API:

.. code:: bash

    # replace <host.name> with the hostname of your synapse homeserver.
    # You may need to specify a port (eg, :8448) if your server is not
    # configured on port 443.
    curl -kv https://<host.name>/_matrix/client/versions 2>&1 | grep "Server:"

Upgrading to v0.27.3
====================

This release expands the anonymous usage stats sent if the opt-in
``report_stats`` configuration is set to ``true``. We now capture RSS memory
and cpu use at a very coarse level. This requires administrators to install
the optional ``psutil`` python module.

We would appreciate it if you could assist by ensuring this module is available
and ``report_stats`` is enabled. This will let us see if performance changes to
synapse are having an impact to the general community.

Upgrading to v0.15.0
====================

If you want to use the new URL previewing API (/_matrix/media/r0/preview_url)
then you have to explicitly enable it in the config and update your dependencies
dependencies.  See README.rst for details.


Upgrading to v0.11.0
====================

This release includes the option to send anonymous usage stats to matrix.org,
and requires that administrators explictly opt in or out by setting the
``report_stats`` option to either ``true`` or ``false``.

We would really appreciate it if you could help our project out by reporting
anonymized usage statistics from your homeserver. Only very basic aggregate
data (e.g. number of users) will be reported, but it helps us to track the
growth of the Matrix community, and helps us to make Matrix a success, as well
as to convince other networks that they should peer with us.


Upgrading to v0.9.0
===================

Application services have had a breaking API change in this version.

They can no longer register themselves with a home server using the AS HTTP API. This
decision was made because a compromised application service with free reign to register
any regex in effect grants full read/write access to the home server if a regex of ``.*``
is used. An attack where a compromised AS re-registers itself with ``.*`` was deemed too
big of a security risk to ignore, and so the ability to register with the HS remotely has
been removed.

It has been replaced by specifying a list of application service registrations in
``homeserver.yaml``::

  app_service_config_files: ["registration-01.yaml", "registration-02.yaml"]

Where ``registration-01.yaml`` looks like::

  url: <String>  # e.g. "https://my.application.service.com"
  as_token: <String>
  hs_token: <String>
  sender_localpart: <String>  # This is a new field which denotes the user_id localpart when using the AS token
  namespaces:
    users:
      - exclusive: <Boolean>
        regex: <String>  # e.g. "@prefix_.*"
    aliases:
      - exclusive: <Boolean>
        regex: <String>
    rooms:
      - exclusive: <Boolean>
        regex: <String>

Upgrading to v0.8.0
===================

Servers which use captchas will need to add their public key to::

  static/client/register/register_config.js

    window.matrixRegistrationConfig = {
        recaptcha_public_key: "YOUR_PUBLIC_KEY"
    };

This is required in order to support registration fallback (typically used on
mobile devices).


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
