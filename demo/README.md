# Synapse demo setup

**DO NOT USE THESE DEMO SERVERS IN PRODUCTION**

Requires you to have a [Synapse development environment setup](https://matrix-org.github.io/synapse/develop/development/contributing_guide.html#4-install-the-dependencies).

The demo setup allows running three federation Synapse servers on ports 8080,
8081 and 8082, with host names localhost:8080, localhost:8081, localhost:8082,
respectively.

You can access them via any Matrix client, but note that it must be able to talk
HTTP (not HTTPS) to localhost.

To enable the servers to communicate, self-signed SSL certificates are generated
and the servers are configured in a highly insecure way, including:

* Not checking certificates over federation.
* Not verifying keys.

The servers are configured to store their data under `demo/808{1,2,3}`. This
includes logs, SQLite databases, and media.

Note that when joining a public room on a different HS via "#foo:bar.net", then
you are (in the current impl) joining a room with room_id "foo". This means that
it won't work if your HS already has a room with that name.

## Using the demo scripts

There's three main scripts with straightforward purposes, none of the scripts
take additional parameters.

* `start.sh` will start the Synapse servers, generating any missing configuration.
* `stop.sh` will stop the Synapse servers.
* `clean.sh` will delete the configuration, databases, log files, etc.

To start a completely new set of servers, run:

```sh
./demo/stop.sh; ./demo/clean.sh && ./demo/start.sh
```
