# Registering an Application Service

The registration of new application services depends on the homeserver used. 
In synapse, you need to create a new configuration file for your AS and add it
to the list specified under the `app_service_config_files` config
option in your synapse config.

For example:

```yaml
app_service_config_files:
- /home/matrix/.synapse/<your-AS>.yaml
```

The format of the AS configuration file is as follows:

```yaml
url: <base url of AS>
as_token: <token AS will add to requests to HS>
hs_token: <token HS will add to requests to AS>
sender_localpart: <localpart of AS user>
namespaces:
  users:  # List of users we're interested in
    - exclusive: <bool>
      regex: <regex>
      group_id: <group>
    - ...
  aliases: []  # List of aliases we're interested in
  rooms: [] # List of room ids we're interested in
```

`exclusive`: If enabled, only this application service is allowed to register users in its namespace(s).
`group_id`: All users of this application service are dynamically joined to this group. This is useful for e.g user organisation or flairs.

See the [spec](https://matrix.org/docs/spec/application_service/unstable.html) for further details on how application services work.
