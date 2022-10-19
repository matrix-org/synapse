# Synapse demo setup

**DO NOT USE THESE DEMO SERVERS IN PRODUCTION**

Requires you to have a [Synapse development environment setup](https://matrix-org.github.io/synapse/develop/development/contributing_guide.html#4-install-the-dependencies).

The demo setup allows running three federation Synapse servers, with server
names `localhost:8480`, `localhost:8481`, and `localhost:8482`.

You can access them via any Matrix client over HTTP at `localhost:8080`,
`localhost:8081`, and `localhost:8082` or over HTTPS at `localhost:8480`,
`localhost:8481`, and `localhost:8482`.

To enable the servers to communicate, self-signed SSL certificates are generated
and the servers are configured in a highly insecure way, including:

* Not checking certificates over federation.
* Not verifying keys.

The servers are configured to store their data under `demo/8080`, `demo/8081`, and
`demo/8082`. This includes configuration, logs, SQLite databases, and media.

Note that when joining a public room on a different homeserver via "#foo:bar.net",
then you are (in the current implementation) joining a room with room_id "foo".
This means that it won't work if your homeserver already has a room with that
name.

## Using the demo scripts

There's three main scripts with straightforward purposes:

* `start.sh` will start the Synapse servers, generating any missing configuration.
  * This accepts a single parameter `--no-rate-limit` to "disable" rate limits
    (they actually still exist, but are very high).
* `stop.sh` will stop the Synapse servers.
* `clean.sh` will delete the configuration, databases, log files, etc.

To start a completely new set of servers, run:

```sh
./demo/stop.sh; ./demo/clean.sh && ./demo/start.sh
```
