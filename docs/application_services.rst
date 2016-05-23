Registering an Application Service
==================================

The registration of new application services depends on the homeserver used. 
In synapse, you need to create a new configuration file for your AS and add it
to the list specified under the ``app_service_config_files`` config
option in your synapse config.

For example:

.. code-block:: yaml

  app_service_config_files:
  - /home/matrix/.synapse/<your-AS>.yaml


The format of the AS configuration file is as follows:

..  code-block:: yaml

    url: <base url of AS>
    as_token: <token AS will add to requests to HS>
    hs_token: <token HS will add to requests to AS>
    sender_localpart: <localpart of AS user>
    namespaces:
      users:  # List of users we're interested in
        - exclusive: <bool>
          regex: <regex>
        - ...
      aliases: []  # List of aliases we're interested in
      rooms: [] # List of room ids we're interested in

See the spec_ for further details on how application services work.

.. _spec: https://matrix.org/docs/spec/application_service/unstable.html
