Using the synapse manhole
=========================

The "manhole" allows server administrators to access a Python shell on a running
Synapse installation. This is a very powerful mechanism for administration and
debugging.

**_Security Warning_**

Note that this will give administrative access to synapse to **all users** with
shell access to the server. It should therefore **not** be enabled in
environments where untrusted users have shell access.

## Configuring the manhole

To enable it, first add the `manhole` listener configuration in your
`homeserver.yaml`. You can find information on how to do that 
in the [configuration manual](usage/configuration/config_documentation.md#manhole_settings).
The configuration is slightly different if you're using docker.

#### Docker config

If you are using Docker, set `bind_addresses` to `['0.0.0.0']` as shown:

```yaml
listeners:
  - port: 9000
    bind_addresses: ['0.0.0.0']
    type: manhole
```

When using `docker run` to start the server, you will then need to change the command to the following to include the
`manhole` port forwarding. The `-p 127.0.0.1:9000:9000` below is important: it 
ensures that access to the `manhole` is only possible for local users.

```bash
docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -p 8008:8008 \
    -p 127.0.0.1:9000:9000 \
    matrixdotorg/synapse:latest
```

#### Native config

If you are not using docker, set `bind_addresses` to `['::1', '127.0.0.1']` as shown.
The `bind_addresses` in the example below is important: it ensures that access to the
`manhole` is only possible for local users).

```yaml
listeners:
  - port: 9000
    bind_addresses: ['::1', '127.0.0.1']
    type: manhole
```

### Security settings

The following config options are available:

- `username` - The username for the manhole (defaults to `matrix`)
- `password` - The password for the manhole (defaults to `rabbithole`)
- `ssh_priv_key` - The path to a private SSH key (defaults to a hardcoded value)
- `ssh_pub_key` - The path to a public SSH key (defaults to a hardcoded value)

For example:

```yaml
manhole_settings:
  username: manhole
  password: mypassword
  ssh_priv_key: "/home/synapse/manhole_keys/id_rsa"
  ssh_pub_key: "/home/synapse/manhole_keys/id_rsa.pub"
```


## Accessing synapse manhole

Then restart synapse, and point an ssh client at port 9000 on localhost, using
the username and password configured in `homeserver.yaml` - with the default 
configuration, this would be:

```bash
ssh -p9000 matrix@localhost
```

Then enter the password when prompted (the default is `rabbithole`).

This gives a Python REPL in which `hs` gives access to the
`synapse.server.HomeServer` object - which in turn gives access to many other
parts of the process.

Note that, prior to Synapse 1.41, any call which returns a coroutine will need to be wrapped in `ensureDeferred`.

As a simple example, retrieving an event from the database:

```pycon
>>> from twisted.internet import defer
>>> defer.ensureDeferred(hs.get_datastores().main.get_event('$1416420717069yeQaw:matrix.org'))
<Deferred at 0x7ff253fc6998 current result: <FrozenEvent event_id='$1416420717069yeQaw:matrix.org', type='m.room.create', state_key=''>>
```
