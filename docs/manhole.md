Using the synapse manhole
=========================

The "manhole" allows server administrators to access a Python shell on a running
Synapse installation. This is a very powerful mechanism for administration and
debugging.

To enable it, first uncomment the `manhole` listener configuration in
`homeserver.yaml`:

```yaml
listeners:
  - port: 9000
    bind_addresses: ['::1', '127.0.0.1']
    type: manhole
```

(`bind_addresses` in the above is important: it ensures that access to the
manhole is only possible for local users).

Note that this will give administrative access to synapse to **all users** with
shell access to the server. It should therefore **not** be enabled in
environments where untrusted users have shell access.

Then restart synapse, and point an ssh client at port 9000 on localhost, using
the username `matrix`:

```bash
ssh -p9000 matrix@localhost
```

The password is `rabbithole`.

This gives a Python REPL in which `hs` gives access to the
`synapse.server.HomeServer` object - which in turn gives access to many other
parts of the process.

As a simple example, retrieving an event from the database:

```
>>> hs.get_datastore().get_event('$1416420717069yeQaw:matrix.org')
<Deferred at 0x7ff253fc6998 current result: <FrozenEvent event_id='$1416420717069yeQaw:matrix.org', type='m.room.create', state_key=''>>
```
