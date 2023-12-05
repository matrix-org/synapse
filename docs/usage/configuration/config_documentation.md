# Configuring Synapse

This is intended as a guide to the Synapse configuration. The behavior of a Synapse instance can be modified
through the many configuration settings documented here — each config option is explained,
including what the default is, how to change the default and what sort of behaviour the setting governs.
Also included is an example configuration for each setting. If you don't want to spend a lot of time
thinking about options, the config as generated sets sensible defaults for all values. Do note however that the
database defaults to SQLite, which is not recommended for production usage. You can read more on this subject
[here](../../setup/installation.md#using-postgresql).

## Config Conventions

Configuration options that take a time period can be set using a number
followed by a letter. Letters have the following meanings:

* `s` = second
* `m` = minute
* `h` = hour
* `d` = day
* `w` = week
* `y` = year

For example, setting `redaction_retention_period: 5m` would remove redacted
messages from the database after 5 minutes, rather than 5 months.

In addition, configuration options referring to size use the following suffixes:

* `K` = KiB, or 1024 bytes
* `M` = MiB, or 1,048,576 bytes
* `G` = GiB, or 1,073,741,824 bytes
* `T` = TiB, or 1,099,511,627,776 bytes

For example, setting `max_avatar_size: 10M` means that Synapse will not accept files larger than 10,485,760 bytes
for a user avatar.

## Config Validation

The configuration file can be validated with the following command:
```bash
python -m synapse.config read <config key to print> -c <path to config>
```

To validate the entire file, omit `read <config key to print>`:
```bash
python -m synapse.config -c <path to config>
```

To see how to set other options, check the help reference:
```bash
python -m synapse.config --help
```

### YAML
The configuration file is a [YAML](https://yaml.org/) file, which means that certain syntax rules
apply if you want your config file to be read properly. A few helpful things to know:
* `#` before any option in the config will comment out that setting and either a default (if available) will
   be applied or Synapse will ignore the setting. Thus, in example #1 below, the setting will be read and
   applied, but in example #2 the setting will not be read and a default will be applied.

   Example #1:
   ```yaml
   pid_file: DATADIR/homeserver.pid
   ```
   Example #2:
   ```yaml
   #pid_file: DATADIR/homeserver.pid
   ```
* Indentation matters! The indentation before a setting
  will determine whether a given setting is read as part of another
  setting, or considered on its own. Thus, in example #1, the `enabled` setting
  is read as a sub-option of the `presence` setting, and will be properly applied.

  However, the lack of indentation before the `enabled` setting in example #2 means
  that when reading the config, Synapse will consider both `presence` and `enabled` as
  different settings. In this case, `presence` has no value, and thus a default applied, and `enabled`
  is an option that Synapse doesn't recognize and thus ignores.

  Example #1:
  ```yaml
  presence:
    enabled: false
  ```
  Example #2:
  ```yaml
  presence:
  enabled: false
  ```
  In this manual, all top-level settings (ones with no indentation) are identified
  at the beginning of their section (i.e. "### `example_setting`") and
  the sub-options, if any, are identified and listed in the body of the section.
  In addition, each setting has an example of its usage, with the proper indentation
  shown.

## Modules

Server admins can expand Synapse's functionality with external modules.

See [here](../../modules/index.md) for more
documentation on how to configure or create custom modules for Synapse.


---
### `modules`

Use the `module` sub-option to add modules under this option to extend functionality.
The `module` setting then has a sub-option, `config`, which can be used to define some configuration
for the `module`.

Defaults to none.

Example configuration:
```yaml
modules:
  - module: my_super_module.MySuperClass
    config:
      do_thing: true
  - module: my_other_super_module.SomeClass
    config: {}
```
---
## Server

Define your homeserver name and other base options.

---
### `server_name`

This sets the public-facing domain of the server.

The `server_name` name will appear at the end of usernames and room addresses
created on your server. For example if the `server_name` was example.com,
usernames on your server would be in the format `@user:example.com`

In most cases you should avoid using a matrix specific subdomain such as
matrix.example.com or synapse.example.com as the `server_name` for the same
reasons you wouldn't use user@email.example.com as your email address.
See [here](../../delegate.md)
for information on how to host Synapse on a subdomain while preserving
a clean `server_name`.

The `server_name` cannot be changed later so it is important to
configure this correctly before you start Synapse. It should be all
lowercase and may contain an explicit port.

There is no default for this option.

Example configuration #1:
```yaml
server_name: matrix.org
```
Example configuration #2:
```yaml
server_name: localhost:8080
```
---
### `pid_file`

When running Synapse as a daemon, the file to store the pid in. Defaults to none.

Example configuration:
```yaml
pid_file: DATADIR/homeserver.pid
```
---
### `web_client_location`

The absolute URL to the web client which `/` will redirect to. Defaults to none.

Example configuration:
```yaml
web_client_location: https://riot.example.com/
```
---
### `public_baseurl`

The public-facing base URL that clients use to access this Homeserver (not
including _matrix/...). This is the same URL a user might enter into the
'Custom Homeserver URL' field on their client. If you use Synapse with a
reverse proxy, this should be the URL to reach Synapse via the proxy.
Otherwise, it should be the URL to reach Synapse's client HTTP listener (see
['listeners'](#listeners) below).

Defaults to `https://<server_name>/`.

Example configuration:
```yaml
public_baseurl: https://example.com/
```
---
### `serve_server_wellknown`

By default, other servers will try to reach our server on port 8448, which can
be inconvenient in some environments.

Provided `https://<server_name>/` on port 443 is routed to Synapse, this
option configures Synapse to serve a file at `https://<server_name>/.well-known/matrix/server`.
This will tell other servers to send traffic to port 443 instead.

This option currently defaults to false.

See [Delegation of incoming federation traffic](../../delegate.md) for more
information.

Example configuration:
```yaml
serve_server_wellknown: true
```
---
### `extra_well_known_client_content `

This option allows server runners to add arbitrary key-value pairs to the [client-facing `.well-known` response](https://spec.matrix.org/latest/client-server-api/#well-known-uri).
Note that the `public_baseurl` config option must be provided for Synapse to serve a response to `/.well-known/matrix/client` at all.

If this option is provided, it parses the given yaml to json and
serves it on `/.well-known/matrix/client` endpoint
alongside the standard properties.

*Added in Synapse 1.62.0.*

Example configuration:
```yaml
extra_well_known_client_content :
  option1: value1
  option2: value2
```
---
### `soft_file_limit`

Set the soft limit on the number of file descriptors synapse can use.
Zero is used to indicate synapse should set the soft limit to the hard limit.
Defaults to 0.

Example configuration:
```yaml
soft_file_limit: 3
```
---
### `presence`

Presence tracking allows users to see the state (e.g online/offline)
of other local and remote users. Set the `enabled` sub-option to false to
disable presence tracking on this homeserver. Defaults to true.
This option replaces the previous top-level 'use_presence' option.

Example configuration:
```yaml
presence:
  enabled: false
```

`enabled` can also be set to a special value of "untracked" which ignores updates
received via clients and federation, while still accepting updates from the
[module API](../../modules/index.md).

*The "untracked" option was added in Synapse 1.96.0.*

---
### `require_auth_for_profile_requests`

Whether to require authentication to retrieve profile data (avatars, display names) of other
users through the client API. Defaults to false. Note that profile data is also available
via the federation API, unless `allow_profile_lookup_over_federation` is set to false.

Example configuration:
```yaml
require_auth_for_profile_requests: true
```
---
### `limit_profile_requests_to_users_who_share_rooms`

Use this option to require a user to share a room with another user in order
to retrieve their profile information. Only checked on Client-Server
requests. Profile requests from other servers should be checked by the
requesting server. Defaults to false.

Example configuration:
```yaml
limit_profile_requests_to_users_who_share_rooms: true
```
---
### `include_profile_data_on_invite`

Use this option to prevent a user's profile data from being retrieved and
displayed in a room until they have joined it. By default, a user's
profile data is included in an invite event, regardless of the values
of the above two settings, and whether or not the users share a server.
Defaults to true.

Example configuration:
```yaml
include_profile_data_on_invite: false
```
---
### `allow_public_rooms_without_auth`

If set to true, removes the need for authentication to access the server's
public rooms directory through the client API, meaning that anyone can
query the room directory. Defaults to false.

Example configuration:
```yaml
allow_public_rooms_without_auth: true
```
---
### `allow_public_rooms_over_federation`

If set to true, allows any other homeserver to fetch the server's public
rooms directory via federation. Defaults to false.

Example configuration:
```yaml
allow_public_rooms_over_federation: true
```
---
### `default_room_version`

The default room version for newly created rooms on this server.

Known room versions are listed [here](https://spec.matrix.org/latest/rooms/#complete-list-of-room-versions)

For example, for room version 1, `default_room_version` should be set
to "1".

Currently defaults to ["10"](https://spec.matrix.org/v1.5/rooms/v10/).

_Changed in Synapse 1.76:_ the default version room version was increased from [9](https://spec.matrix.org/v1.5/rooms/v9/) to [10](https://spec.matrix.org/v1.5/rooms/v10/).

Example configuration:
```yaml
default_room_version: "8"
```
---
### `gc_thresholds`

The garbage collection threshold parameters to pass to `gc.set_threshold`, if defined.
Defaults to none.

Example configuration:
```yaml
gc_thresholds: [700, 10, 10]
```
---
### `gc_min_interval`

The minimum time in seconds between each GC for a generation, regardless of
the GC thresholds. This ensures that we don't do GC too frequently. A value of `[1s, 10s, 30s]`
indicates that a second must pass between consecutive generation 0 GCs, etc.

Defaults to `[1s, 10s, 30s]`.

Example configuration:
```yaml
gc_min_interval: [0.5s, 30s, 1m]
```
---
### `filter_timeline_limit`

Set the limit on the returned events in the timeline in the get
and sync operations. Defaults to 100. A value of -1 means no upper limit.


Example configuration:
```yaml
filter_timeline_limit: 5000
```
---
### `block_non_admin_invites`

Whether room invites to users on this server should be blocked
(except those sent by local server admins). Defaults to false.

Example configuration:
```yaml
block_non_admin_invites: true
```
---
### `enable_search`

If set to false, new messages will not be indexed for searching and users
will receive errors when searching for messages. Defaults to true.

Example configuration:
```yaml
enable_search: false
```
---
### `ip_range_blacklist`

This option prevents outgoing requests from being sent to the specified blacklisted IP address
CIDR ranges. If this option is not specified then it defaults to private IP
address ranges (see the example below).

The blacklist applies to the outbound requests for federation, identity servers,
push servers, and for checking key validity for third-party invite events.

(0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
listed here, since they correspond to unroutable addresses.)

This option replaces `federation_ip_range_blacklist` in Synapse v1.25.0.

Note: The value is ignored when an HTTP proxy is in use.

Example configuration:
```yaml
ip_range_blacklist:
  - '127.0.0.0/8'
  - '10.0.0.0/8'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - '100.64.0.0/10'
  - '192.0.0.0/24'
  - '169.254.0.0/16'
  - '192.88.99.0/24'
  - '198.18.0.0/15'
  - '192.0.2.0/24'
  - '198.51.100.0/24'
  - '203.0.113.0/24'
  - '224.0.0.0/4'
  - '::1/128'
  - 'fe80::/10'
  - 'fc00::/7'
  - '2001:db8::/32'
  - 'ff00::/8'
  - 'fec0::/10'
```
---
### `ip_range_whitelist`

List of IP address CIDR ranges that should be allowed for federation,
identity servers, push servers, and for checking key validity for
third-party invite events. This is useful for specifying exceptions to
wide-ranging blacklisted target IP ranges - e.g. for communication with
a push server only visible in your network.

This whitelist overrides `ip_range_blacklist` and defaults to an empty
list.

Example configuration:
```yaml
ip_range_whitelist:
   - '192.168.1.1'
```
---
### `listeners`

List of ports that Synapse should listen on, their purpose and their
configuration.

Sub-options for each listener include:

* `port`: the TCP port to bind to.

* `tag`: An alias for the port in the logger name. If set the tag is logged instead
of the port. Default to `None`, is optional and only valid for listener with `type: http`.
See the docs [request log format](../administration/request_log.md).

* `bind_addresses`: a list of local addresses to listen on. The default is
       'all local interfaces'.

* `type`: the type of listener. Normally `http`, but other valid options are:

   * `manhole`: (see the docs [here](../../manhole.md)),

   * `metrics`: (see the docs [here](../../metrics-howto.md)),

* `tls`: set to true to enable TLS for this listener. Will use the TLS key/cert specified in tls_private_key_path / tls_certificate_path.

* `x_forwarded`: Only valid for an 'http' listener. Set to true to use the X-Forwarded-For header as the client IP. Useful when Synapse is
   behind a [reverse-proxy](../../reverse_proxy.md).

* `request_id_header`: The header extracted from each incoming request that is
   used as the basis for the request ID. The request ID is used in
   [logs](../administration/request_log.md#request-log-format) and tracing to
   correlate and match up requests. When unset, Synapse will automatically
   generate sequential request IDs. This option is useful when Synapse is behind
   a [reverse-proxy](../../reverse_proxy.md).

   _Added in Synapse 1.68.0._

* `resources`: Only valid for an 'http' listener. A list of resources to host
   on this port. Sub-options for each resource are:

   * `names`: a list of names of HTTP resources. See below for a list of valid resource names.

   * `compress`: set to true to enable gzip compression on HTTP bodies for this resource. This is currently only supported with the
     `client`, `consent`, `metrics` and `federation` resources.

* `additional_resources`: Only valid for an 'http' listener. A map of
   additional endpoints which should be loaded via dynamic modules.

Unix socket support (_Added in Synapse 1.89.0_):
* `path`: A path and filename for a Unix socket. Make sure it is located in a
  directory with read and write permissions, and that it already exists (the directory
  will not be created). Defaults to `None`.
  * **Note**: The use of both `path` and `port` options for the same `listener` is not
    compatible.
  * The `x_forwarded` option defaults to true  when using Unix sockets and can be omitted.
  * Other options that would not make sense to use with a UNIX socket, such as 
    `bind_addresses` and `tls` will be ignored and can be removed.
* `mode`: The file permissions to set on the UNIX socket. Defaults to `666`
* **Note:** Must be set as `type: http` (does not support `metrics` and `manhole`). 
  Also make sure that `metrics` is not included in `resources` -> `names`


Valid resource names are:

* `client`: the client-server API (/_matrix/client), and the synapse admin API (/_synapse/admin). Also implies `media` and `static`.

* `consent`: user consent forms (/_matrix/consent). See [here](../../consent_tracking.md) for more.

* `federation`: the server-server API (/_matrix/federation). Also implies `media`, `keys`, `openid`

* `keys`: the key discovery API (/_matrix/key).

* `media`: the media API (/_matrix/media).

* `metrics`: the metrics interface. See [here](../../metrics-howto.md). (Not compatible with Unix sockets)

* `openid`: OpenID authentication. See [here](../../openid.md).

* `replication`: the HTTP replication API (/_synapse/replication). See [here](../../workers.md).

* `static`: static resources under synapse/static (/_matrix/static). (Mostly useful for 'fallback authentication'.)

* `health`: the [health check endpoint](../../reverse_proxy.md#health-check-endpoint). This endpoint
  is by default active for all other resources and does not have to be activated separately.
  This is only useful if you want to use the health endpoint explicitly on a dedicated port or
  for [workers](../../workers.md) and containers without listener e.g.
  [application services](../../workers.md#notifying-application-services).

Example configuration #1:
```yaml
listeners:
  # TLS-enabled listener: for when matrix traffic is sent directly to synapse.
  #
  # (Note that you will also need to give Synapse a TLS key and certificate: see the TLS section
  # below.)
  #
  - port: 8448
    type: http
    tls: true
    resources:
      - names: [client, federation]
```
Example configuration #2:
```yaml
listeners:
  # Insecure HTTP listener: for when matrix traffic passes through a reverse proxy
  # that unwraps TLS.
  #
  # If you plan to use a reverse proxy, please see
  # https://matrix-org.github.io/synapse/latest/reverse_proxy.html.
  #
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['::1', '127.0.0.1']

    resources:
      - names: [client, federation]
        compress: false

    # example additional_resources:
    additional_resources:
      "/_matrix/my/custom/endpoint":
        module: my_module.CustomRequestHandler
        config: {}

  # Turn on the twisted ssh manhole service on localhost on the given
  # port.
  - port: 9000
    bind_addresses: ['::1', '127.0.0.1']
    type: manhole
```
Example configuration #3:
```yaml
listeners:
  # Unix socket listener: Ideal for Synapse deployments behind a reverse proxy, offering
  # lightweight interprocess communication without TCP/IP overhead, avoid port
  # conflicts, and providing enhanced security through system file permissions.
  #
  # Note that x_forwarded will default to true, when using a UNIX socket. Please see
  # https://matrix-org.github.io/synapse/latest/reverse_proxy.html.
  #
  - path: /run/synapse/main_public.sock
    type: http
    resources:
      - names: [client, federation]
```

---
### `manhole_settings`

Connection settings for the manhole. You can find more information
on the manhole [here](../../manhole.md). Manhole sub-options include:
* `username` : the username for the manhole. This defaults to 'matrix'.
* `password`: The password for the manhole. This defaults to 'rabbithole'.
* `ssh_priv_key_path` and `ssh_pub_key_path`: The private and public SSH key pair used to encrypt the manhole traffic.
  If these are left unset, then hardcoded and non-secret keys are used,
  which could allow traffic to be intercepted if sent over a public network.

Example configuration:
```yaml
manhole_settings:
  username: manhole
  password: mypassword
  ssh_priv_key_path: CONFDIR/id_rsa
  ssh_pub_key_path: CONFDIR/id_rsa.pub
```
---
### `dummy_events_threshold`

Forward extremities can build up in a room due to networking delays between
homeservers. Once this happens in a large room, calculation of the state of
that room can become quite expensive. To mitigate this, once the number of
forward extremities reaches a given threshold, Synapse will send an
`org.matrix.dummy_event` event, which will reduce the forward extremities
in the room.

This setting defines the threshold (i.e. number of forward extremities in the room) at which dummy events are sent.
The default value is 10.

Example configuration:
```yaml
dummy_events_threshold: 5
```
---
### `delete_stale_devices_after`

An optional duration. If set, Synapse will run a daily background task to log out and
delete any device that hasn't been accessed for more than the specified amount of time.

Defaults to no duration, which means devices are never pruned.

**Note:** This task will always run on the main process, regardless of the value of
`run_background_tasks_on`. This is due to workers currently not having the ability to
delete devices.

Example configuration:
```yaml
delete_stale_devices_after: 1y
```
---
### `email`

Configuration for sending emails from Synapse.

Server admins can configure custom templates for email content. See
[here](../../templates.md) for more information.

This setting has the following sub-options:
* `smtp_host`: The hostname of the outgoing SMTP server to use. Defaults to 'localhost'.
* `smtp_port`: The port on the mail server for outgoing SMTP. Defaults to 465 if `force_tls` is true, else 25.

  _Changed in Synapse 1.64.0:_ the default port is now aware of `force_tls`.
* `smtp_user` and `smtp_pass`: Username/password for authentication to the SMTP server. By default, no
   authentication is attempted.
* `force_tls`: By default, Synapse connects over plain text and then optionally upgrades
   to TLS via STARTTLS. If this option is set to true, TLS is used from the start (Implicit TLS),
   and the option `require_transport_security` is ignored.
   It is recommended to enable this if supported by your mail server.

  _New in Synapse 1.64.0._
* `require_transport_security`: Set to true to require TLS transport security for SMTP.
   By default, Synapse will connect over plain text, and will then switch to
   TLS via STARTTLS *if the SMTP server supports it*. If this option is set,
   Synapse will refuse to connect unless the server supports STARTTLS.
* `enable_tls`: By default, if the server supports TLS, it will be used, and the server
   must present a certificate that is valid for 'smtp_host'. If this option
   is set to false, TLS will not be used.
* `notif_from`: defines the "From" address to use when sending emails.
    It must be set if email sending is enabled. The placeholder '%(app)s' will be replaced by the application name,
    which is normally set in `app_name`, but may be overridden by the
    Matrix client application. Note that the placeholder must be written '%(app)s', including the
    trailing 's'.
* `app_name`: `app_name` defines the default value for '%(app)s' in `notif_from` and email
   subjects. It defaults to 'Matrix'.
* `enable_notifs`: Set to true to enable sending emails for messages that the user
   has missed. Disabled by default.
* `notif_for_new_users`: Set to false to disable automatic subscription to email
   notifications for new users. Enabled by default.
* `client_base_url`: Custom URL for client links within the email notifications. By default
   links will be based on "https://matrix.to". (This setting used to be called `riot_base_url`;
   the old name is still supported for backwards-compatibility but is now deprecated.)
* `validation_token_lifetime`: Configures the time that a validation email will expire after sending.
   Defaults to 1h.
* `invite_client_location`: The web client location to direct users to during an invite. This is passed
   to the identity server as the `org.matrix.web_client_location` key. Defaults
   to unset, giving no guidance to the identity server.
* `subjects`: Subjects to use when sending emails from Synapse. The placeholder '%(app)s' will
   be replaced with the value of the `app_name` setting, or by a value dictated by the Matrix client application.
   In addition, each subject can use the following placeholders: '%(person)s', which will be replaced by the displayname
   of the user(s) that sent the message(s), e.g. "Alice and Bob", and '%(room)s', which will be replaced by the name of the room the
   message(s) have been sent to, e.g. "My super room". In addition, emails related to account administration will
   can use the '%(server_name)s' placeholder, which will be replaced by the value of the
   `server_name` setting in your Synapse configuration.

   Here is a list of subjects for notification emails that can be set:
     * `message_from_person_in_room`: Subject to use to notify about one message from one or more user(s) in a
        room which has a name. Defaults to "[%(app)s] You have a message on %(app)s from %(person)s in the %(room)s room..."
     * `message_from_person`: Subject to use to notify about one message from one or more user(s) in a
        room which doesn't have a name. Defaults to "[%(app)s] You have a message on %(app)s from %(person)s..."
     * `messages_from_person`: Subject to use to notify about multiple messages from one or more users in
        a room which doesn't have a name. Defaults to "[%(app)s] You have messages on %(app)s from %(person)s..."
     * `messages_in_room`: Subject to use to notify about multiple messages in a room which has a
        name. Defaults to "[%(app)s] You have messages on %(app)s in the %(room)s room..."
     * `messages_in_room_and_others`: Subject to use to notify about multiple messages in multiple rooms.
        Defaults to "[%(app)s] You have messages on %(app)s in the %(room)s room and others..."
     * `messages_from_person_and_others`: Subject to use to notify about multiple messages from multiple persons in
        multiple rooms. This is similar to the setting above except it's used when
        the room in which the notification was triggered has no name. Defaults to
        "[%(app)s] You have messages on %(app)s from %(person)s and others..."
     * `invite_from_person_to_room`: Subject to use to notify about an invite to a room which has a name.
        Defaults to  "[%(app)s] %(person)s has invited you to join the %(room)s room on %(app)s..."
     * `invite_from_person`: Subject to use to notify about an invite to a room which doesn't have a
        name. Defaults to "[%(app)s] %(person)s has invited you to chat on %(app)s..."
     * `password_reset`: Subject to use when sending a password reset email. Defaults to "[%(server_name)s] Password reset"
     * `email_validation`: Subject to use when sending a verification email to assert an address's
        ownership. Defaults to "[%(server_name)s] Validate your email"

Example configuration:

```yaml
email:
  smtp_host: mail.server
  smtp_port: 587
  smtp_user: "exampleusername"
  smtp_pass: "examplepassword"
  force_tls: true
  require_transport_security: true
  enable_tls: false
  notif_from: "Your Friendly %(app)s homeserver <noreply@example.com>"
  app_name: my_branded_matrix_server
  enable_notifs: true
  notif_for_new_users: false
  client_base_url: "http://localhost/riot"
  validation_token_lifetime: 15m
  invite_client_location: https://app.element.io

  subjects:
    message_from_person_in_room: "[%(app)s] You have a message on %(app)s from %(person)s in the %(room)s room..."
    message_from_person: "[%(app)s] You have a message on %(app)s from %(person)s..."
    messages_from_person: "[%(app)s] You have messages on %(app)s from %(person)s..."
    messages_in_room: "[%(app)s] You have messages on %(app)s in the %(room)s room..."
    messages_in_room_and_others: "[%(app)s] You have messages on %(app)s in the %(room)s room and others..."
    messages_from_person_and_others: "[%(app)s] You have messages on %(app)s from %(person)s and others..."
    invite_from_person_to_room: "[%(app)s] %(person)s has invited you to join the %(room)s room on %(app)s..."
    invite_from_person: "[%(app)s] %(person)s has invited you to chat on %(app)s..."
    password_reset: "[%(server_name)s] Password reset"
    email_validation: "[%(server_name)s] Validate your email"
```

## Homeserver blocking
Useful options for Synapse admins.

---

### `admin_contact`

How to reach the server admin, used in `ResourceLimitError`. Defaults to none.

Example configuration:
```yaml
admin_contact: 'mailto:admin@server.com'
```
---
### `hs_disabled` and `hs_disabled_message`

Blocks users from connecting to the homeserver and provides a human-readable reason
why the connection was blocked. Defaults to false.

Example configuration:
```yaml
hs_disabled: true
hs_disabled_message: 'Reason for why the HS is blocked'
```
---
### `limit_usage_by_mau`

This option disables/enables monthly active user blocking. Used in cases where the admin or
server owner wants to limit to the number of monthly active users. When enabled and a limit is
reached the server returns a `ResourceLimitError` with error type `Codes.RESOURCE_LIMIT_EXCEEDED`.
Defaults to false. If this is enabled, a value for `max_mau_value` must also be set.

See [Monthly Active Users](../administration/monthly_active_users.md) for details on how to configure MAU.

Example configuration:
```yaml
limit_usage_by_mau: true
```
---
### `max_mau_value`

This option sets the hard limit of monthly active users above which the server will start
blocking user actions if `limit_usage_by_mau` is enabled. Defaults to 0.

Example configuration:
```yaml
max_mau_value: 50
```
---
### `mau_trial_days`

The option `mau_trial_days` is a means to add a grace period for active users. It
means that users must be active for the specified number of days before they
can be considered active and guards against the case where lots of users
sign up in a short space of time never to return after their initial
session. Defaults to 0.

Example configuration:
```yaml
mau_trial_days: 5
```
---
### `mau_appservice_trial_days`

The option `mau_appservice_trial_days` is similar to `mau_trial_days`, but applies a different
trial number if the user was registered by an appservice. A value
of 0 means no trial days are applied. Appservices not listed in this dictionary
use the value of `mau_trial_days` instead.

Example configuration:
```yaml
mau_appservice_trial_days:
  my_appservice_id: 3
  another_appservice_id: 6
```
---
### `mau_limit_alerting`

The option `mau_limit_alerting` is a means of limiting client-side alerting
should the mau limit be reached. This is useful for small instances
where the admin has 5 mau seats (say) for 5 specific people and no
interest increasing the mau limit further. Defaults to true, which
means that alerting is enabled.

Example configuration:
```yaml
mau_limit_alerting: false
```
---
### `mau_stats_only`

If enabled, the metrics for the number of monthly active users will
be populated, however no one will be limited based on these numbers. If `limit_usage_by_mau`
is true, this is implied to be true. Defaults to false.

Example configuration:
```yaml
mau_stats_only: true
```
---
### `mau_limit_reserved_threepids`

Sometimes the server admin will want to ensure certain accounts are
never blocked by mau checking. These accounts are specified by this option.
Defaults to none. Add accounts by specifying the `medium` and `address` of the
reserved threepid (3rd party identifier).

Example configuration:
```yaml
mau_limit_reserved_threepids:
  - medium: 'email'
    address: 'reserved_user@example.com'
```
---
### `server_context`

This option is used by phonehome stats to group together related servers.
Defaults to none.

Example configuration:
```yaml
server_context: context
```
---
### `limit_remote_rooms`

When this option is enabled, the room "complexity" will be checked before a user
joins a new remote room. If it is above the complexity limit, the server will
disallow joining, or will instantly leave. This is useful for homeservers that are
resource-constrained. Options for this setting include:
* `enabled`: whether this check is enabled. Defaults to false.
* `complexity`: the limit above which rooms cannot be joined. The default is 1.0.
* `complexity_error`: override the error which is returned when the room is too complex with a
   custom message.
* `admins_can_join`: allow server admins to join complex rooms. Default is false.

Room complexity is an arbitrary measure based on factors such as the number of
users in the room.

Example configuration:
```yaml
limit_remote_rooms:
  enabled: true
  complexity: 0.5
  complexity_error: "I can't let you do that, Dave."
  admins_can_join: true
```
---
### `require_membership_for_aliases`

Whether to require a user to be in the room to add an alias to it.
Defaults to true.

Example configuration:
```yaml
require_membership_for_aliases: false
```
---
### `allow_per_room_profiles`

Whether to allow per-room membership profiles through the sending of membership
events with profile information that differs from the target's global profile.
Defaults to true.

Example configuration:
```yaml
allow_per_room_profiles: false
```
---
### `max_avatar_size`

The largest permissible file size in bytes for a user avatar. Defaults to no restriction.
Use M for MB and K for KB.

Note that user avatar changes will not work if this is set without using Synapse's media repository.

Example configuration:
```yaml
max_avatar_size: 10M
```
---
### `allowed_avatar_mimetypes`

The MIME types allowed for user avatars. Defaults to no restriction.

Note that user avatar changes will not work if this is set without
using Synapse's media repository.

Example configuration:
```yaml
allowed_avatar_mimetypes: ["image/png", "image/jpeg", "image/gif"]
```
---
### `redaction_retention_period`

How long to keep redacted events in unredacted form in the database. After
this period redacted events get replaced with their redacted form in the DB.

Synapse will check whether the rentention period has concluded for redacted
events every 5 minutes. Thus, even if this option is set to `0`, Synapse may
still take up to 5 minutes to purge redacted events from the database.

Defaults to `7d`. Set to `null` to disable.

Example configuration:
```yaml
redaction_retention_period: 28d
```
---
### `forgotten_room_retention_period`

How long to keep locally forgotten rooms before purging them from the DB.

Defaults to `null`, meaning it's disabled.

Example configuration:
```yaml
forgotten_room_retention_period: 28d
```
---
### `user_ips_max_age`

How long to track users' last seen time and IPs in the database.

Defaults to `28d`. Set to `null` to disable clearing out of old rows.

Example configuration:
```yaml
user_ips_max_age: 14d
```
---
### `request_token_inhibit_3pid_errors`

Inhibits the `/requestToken` endpoints from returning an error that might leak
information about whether an e-mail address is in use or not on this
homeserver. Defaults to false.
Note that for some endpoints the error situation is the e-mail already being
used, and for others the error is entering the e-mail being unused.
If this option is enabled, instead of returning an error, these endpoints will
act as if no error happened and return a fake session ID ('sid') to clients.

Example configuration:
```yaml
request_token_inhibit_3pid_errors: true
```
---
### `next_link_domain_whitelist`

A list of domains that the domain portion of `next_link` parameters
must match.

This parameter is optionally provided by clients while requesting
validation of an email or phone number, and maps to a link that
users will be automatically redirected to after validation
succeeds. Clients can make use this parameter to aid the validation
process.

The whitelist is applied whether the homeserver or an identity server is handling validation.

The default value is no whitelist functionality; all domains are
allowed. Setting this value to an empty list will instead disallow
all domains.

Example configuration:
```yaml
next_link_domain_whitelist: ["matrix.org"]
```
---
### `templates` and `custom_template_directory`

These options define templates to use when generating email or HTML page contents.
The `custom_template_directory` determines which directory Synapse will try to
find template files in to use to generate email or HTML page contents.
If not set, or a file is not found within the template directory, a default
template from within the Synapse package will be used.

See [here](../../templates.md) for more
information about using custom templates.

Example configuration:
```yaml
templates:
  custom_template_directory: /path/to/custom/templates/
```
---
### `retention`

This option and the associated options determine message retention policy at the
server level.

Room admins and mods can define a retention period for their rooms using the
`m.room.retention` state event, and server admins can cap this period by setting
the `allowed_lifetime_min` and `allowed_lifetime_max` config options.

If this feature is enabled, Synapse will regularly look for and purge events
which are older than the room's maximum retention period. Synapse will also
filter events received over federation so that events that should have been
purged are ignored and not stored again.

The message retention policies feature is disabled by default. You can read more
about this feature [here](../../message_retention_policies.md).

This setting has the following sub-options:
* `default_policy`: Default retention policy. If set, Synapse will apply it to rooms that lack the
   'm.room.retention' state event. This option is further specified by the
   `min_lifetime` and `max_lifetime` sub-options associated with it. Note that the
    value of `min_lifetime` doesn't matter much because Synapse doesn't take it into account yet.

* `allowed_lifetime_min` and `allowed_lifetime_max`: Retention policy limits. If
   set, and the state of a room contains a `m.room.retention` event in its state
   which contains a `min_lifetime` or a `max_lifetime` that's out of these bounds,
   Synapse will cap the room's policy to these limits when running purge jobs.

* `purge_jobs` and the associated `shortest_max_lifetime` and `longest_max_lifetime` sub-options:
   Server admins can define the settings of the background jobs purging the
   events whose lifetime has expired under the `purge_jobs` section.

  If no configuration is provided for this option, a single job will be set up to delete
  expired events in every room daily.

  Each job's configuration defines which range of message lifetimes the job
  takes care of. For example, if `shortest_max_lifetime` is '2d' and
  `longest_max_lifetime` is '3d', the job will handle purging expired events in
  rooms whose state defines a `max_lifetime` that's both higher than 2 days, and
  lower than or equal to 3 days. Both the minimum and the maximum value of a
  range are optional, e.g. a job with no `shortest_max_lifetime` and a
  `longest_max_lifetime` of '3d' will handle every room with a retention policy
  whose `max_lifetime` is lower than or equal to three days.

  The rationale for this per-job configuration is that some rooms might have a
  retention policy with a low `max_lifetime`, where history needs to be purged
  of outdated messages on a more frequent basis than for the rest of the rooms
  (e.g. every 12h), but not want that purge to be performed by a job that's
  iterating over every room it knows, which could be heavy on the server.

  If any purge job is configured, it is strongly recommended to have at least
  a single job with neither `shortest_max_lifetime` nor `longest_max_lifetime`
  set, or one job without `shortest_max_lifetime` and one job without
  `longest_max_lifetime` set. Otherwise some rooms might be ignored, even if
  `allowed_lifetime_min` and `allowed_lifetime_max` are set, because capping a
  room's policy to these values is done after the policies are retrieved from
  Synapse's database (which is done using the range specified in a purge job's
  configuration).

Example configuration:
```yaml
retention:
  enabled: true
  default_policy:
    min_lifetime: 1d
    max_lifetime: 1y
  allowed_lifetime_min: 1d
  allowed_lifetime_max: 1y
  purge_jobs:
    - longest_max_lifetime: 3d
      interval: 12h
    - shortest_max_lifetime: 3d
      interval: 1d
```
---
## TLS

Options related to TLS.

---
### `tls_certificate_path`

This option specifies a PEM-encoded X509 certificate for TLS.
This certificate, as of Synapse 1.0, will need to be a valid and verifiable
certificate, signed by a recognised Certificate Authority. Defaults to none.

Be sure to use a `.pem` file that includes the full certificate chain including
any intermediate certificates (for instance, if using certbot, use
`fullchain.pem` as your certificate, not `cert.pem`).

Example configuration:
```yaml
tls_certificate_path: "CONFDIR/SERVERNAME.tls.crt"
```
---
### `tls_private_key_path`

PEM-encoded private key for TLS. Defaults to none.

Example configuration:
```yaml
tls_private_key_path: "CONFDIR/SERVERNAME.tls.key"
```
---
### `federation_verify_certificates`
Whether to verify TLS server certificates for outbound federation requests.

Defaults to true. To disable certificate verification, set the option to false.

Example configuration:
```yaml
federation_verify_certificates: false
```
---
### `federation_client_minimum_tls_version`

The minimum TLS version that will be used for outbound federation requests.

Defaults to `"1"`. Configurable to `"1"`, `"1.1"`, `"1.2"`, or `"1.3"`. Note
that setting this value higher than `"1.2"` will prevent federation to most
of the public Matrix network: only configure it to `"1.3"` if you have an
entirely private federation setup and you can ensure TLS 1.3 support.

Example configuration:
```yaml
federation_client_minimum_tls_version: "1.2"
```
---
### `federation_certificate_verification_whitelist`

Skip federation certificate verification on a given whitelist
of domains.

This setting should only be used in very specific cases, such as
federation over Tor hidden services and similar. For private networks
of homeservers, you likely want to use a private CA instead.

Only effective if `federation_verify_certificates` is `true`.

Example configuration:
```yaml
federation_certificate_verification_whitelist:
  - lon.example.com
  - "*.domain.com"
  - "*.onion"
```
---
### `federation_custom_ca_list`

List of custom certificate authorities for federation traffic.

This setting should only normally be used within a private network of
homeservers.

Note that this list will replace those that are provided by your
operating environment. Certificates must be in PEM format.

Example configuration:
```yaml
federation_custom_ca_list:
  - myCA1.pem
  - myCA2.pem
  - myCA3.pem
```
---
## Federation

Options related to federation.

---
### `federation_domain_whitelist`

Restrict federation to the given whitelist of domains.
N.B. we recommend also firewalling your federation listener to limit
inbound federation traffic as early as possible, rather than relying
purely on this application-layer restriction.  If not specified, the
default is to whitelist everything.

Note: this does not stop a server from joining rooms that servers not on the
whitelist are in. As such, this option is really only useful to establish a
"private federation", where a group of servers all whitelist each other and have
the same whitelist.

Example configuration:
```yaml
federation_domain_whitelist:
  - lon.example.com
  - nyc.example.com
  - syd.example.com
```
---
### `federation_metrics_domains`

Report prometheus metrics on the age of PDUs being sent to and received from
the given domains. This can be used to give an idea of "delay" on inbound
and outbound federation, though be aware that any delay can be due to problems
at either end or with the intermediate network.

By default, no domains are monitored in this way.

Example configuration:
```yaml
federation_metrics_domains:
  - matrix.org
  - example.com
```
---
### `allow_profile_lookup_over_federation`

Set to false to disable profile lookup over federation. By default, the
Federation API allows other homeservers to obtain profile data of any user
on this homeserver.

Example configuration:
```yaml
allow_profile_lookup_over_federation: false
```
---
### `allow_device_name_lookup_over_federation`

Set this option to true to allow device display name lookup over federation. By default, the
Federation API prevents other homeservers from obtaining the display names of any user devices
on this homeserver.

Example configuration:
```yaml
allow_device_name_lookup_over_federation: true
```
---
### `federation`

The federation section defines some sub-options related to federation.

The following options are related to configuring timeout and retry logic for one request,
independently of the others.
Short retry algorithm is used when something or someone will wait for the request to have an
answer, while long retry is used for requests that happen in the background,
like sending a federation transaction.

* `client_timeout`: timeout for the federation requests. Default to 60s.
* `max_short_retry_delay`: maximum delay to be used for the short retry algo. Default to 2s.
* `max_long_retry_delay`: maximum delay to be used for the short retry algo. Default to 60s.
* `max_short_retries`: maximum number of retries for the short retry algo. Default to 3 attempts.
* `max_long_retries`: maximum number of retries for the long retry algo. Default to 10 attempts.

The following options control the retry logic when communicating with a specific homeserver destination.
Unlike the previous configuration options, these values apply across all requests
for a given destination and the state of the backoff is stored in the database.

* `destination_min_retry_interval`: the initial backoff, after the first request fails. Defaults to 10m.
* `destination_retry_multiplier`: how much we multiply the backoff by after each subsequent fail. Defaults to 2.
* `destination_max_retry_interval`: a cap on the backoff. Defaults to a week.

Example configuration:
```yaml
federation:
  client_timeout: 180s
  max_short_retry_delay: 7s
  max_long_retry_delay: 100s
  max_short_retries: 5
  max_long_retries: 20
  destination_min_retry_interval: 30s
  destination_retry_multiplier: 5
  destination_max_retry_interval: 12h
```
---
## Caching

Options related to caching.

---
### `event_cache_size`

The number of events to cache in memory. Defaults to 10K. Like other caches,
this is affected by `caches.global_factor` (see below).

Note that this option is not part of the `caches` section.

Example configuration:
```yaml
event_cache_size: 15K
```
---
### `caches` and associated values

A cache 'factor' is a multiplier that can be applied to each of
Synapse's caches in order to increase or decrease the maximum
number of entries that can be stored.

`caches` can be configured through the following sub-options:

* `global_factor`: Controls the global cache factor, which is the default cache factor
  for all caches if a specific factor for that cache is not otherwise
  set.

  This can also be set by the `SYNAPSE_CACHE_FACTOR` environment
  variable. Setting by environment variable takes priority over
  setting through the config file.

  Defaults to 0.5, which will halve the size of all caches.

* `per_cache_factors`: A dictionary of cache name to cache factor for that individual
   cache. Overrides the global cache factor for a given cache.

   These can also be set through environment variables comprised
   of `SYNAPSE_CACHE_FACTOR_` + the name of the cache in capital
   letters and underscores. Setting by environment variable
   takes priority over setting through the config file.
   Ex. `SYNAPSE_CACHE_FACTOR_GET_USERS_WHO_SHARE_ROOM_WITH_USER=2.0`

   Some caches have '*' and other characters that are not
   alphanumeric or underscores. These caches can be named with or
   without the special characters stripped. For example, to specify
   the cache factor for `*stateGroupCache*` via an environment
   variable would be `SYNAPSE_CACHE_FACTOR_STATEGROUPCACHE=2.0`.

* `expire_caches`: Controls whether cache entries are evicted after a specified time
   period. Defaults to true. Set to false to disable this feature. Note that never expiring
   caches may result in excessive memory usage.

* `cache_entry_ttl`: If `expire_caches` is enabled, this flag controls how long an entry can
  be in a cache without having been accessed before being evicted.
  Defaults to 30m.

* `sync_response_cache_duration`: Controls how long the results of a /sync request are
  cached for after a successful response is returned. A higher duration can help clients
  with intermittent connections, at the cost of higher memory usage.
  A value of zero means that sync responses are not cached.
  Defaults to 2m.

  *Changed in Synapse 1.62.0*: The default was changed from 0 to 2m.

* `cache_autotuning` and its sub-options `max_cache_memory_usage`, `target_cache_memory_usage`, and
   `min_cache_ttl` work in conjunction with each other to maintain a balance between cache memory
   usage and cache entry availability. You must be using [jemalloc](../administration/admin_faq.md#help-synapse-is-slow-and-eats-all-my-ramcpu)
   to utilize this option, and all three of the options must be specified for this feature to work. This option
   defaults to off, enable it by providing values for the sub-options listed below. Please note that the feature will not work
   and may cause unstable behavior (such as excessive emptying of caches or exceptions) if all of the values are not provided.
   Please see the [Config Conventions](#config-conventions) for information on how to specify memory size and cache expiry
   durations.
     * `max_cache_memory_usage` sets a ceiling on how much memory the cache can use before caches begin to be continuously evicted.
        They will continue to be evicted until the memory usage drops below the `target_memory_usage`, set in
        the setting below, or until the `min_cache_ttl` is hit. There is no default value for this option.
     * `target_cache_memory_usage` sets a rough target for the desired memory usage of the caches. There is no default value
        for this option.
     * `min_cache_ttl` sets a limit under which newer cache entries are not evicted and is only applied when
        caches are actively being evicted/`max_cache_memory_usage` has been exceeded. This is to protect hot caches
        from being emptied while Synapse is evicting due to memory. There is no default value for this option.

Example configuration:
```yaml
event_cache_size: 15K
caches:
  global_factor: 1.0
  per_cache_factors:
    get_users_who_share_room_with_user: 2.0
  sync_response_cache_duration: 2m
  cache_autotuning:
    max_cache_memory_usage: 1024M
    target_cache_memory_usage: 758M
    min_cache_ttl: 5m
```

### Reloading cache factors

The cache factors (i.e. `caches.global_factor` and `caches.per_cache_factors`)  may be reloaded at any time by sending a
[`SIGHUP`](https://en.wikipedia.org/wiki/SIGHUP) signal to Synapse using e.g.

```commandline
kill -HUP [PID_OF_SYNAPSE_PROCESS]
```

If you are running multiple workers, you must individually update the worker
config file and send this signal to each worker process.

If you're using the [example systemd service](https://github.com/matrix-org/synapse/blob/develop/contrib/systemd/matrix-synapse.service)
file in Synapse's `contrib` directory, you can send a `SIGHUP` signal by using
`systemctl reload matrix-synapse`.

---
## Database
Config options related to database settings.

---
### `database`

The `database` setting defines the database that synapse uses to store all of
its data.

Associated sub-options:

* `name`: this option specifies the database engine to use: either `sqlite3` (for SQLite)
  or `psycopg2` (for PostgreSQL). If no name is specified Synapse will default to SQLite.

* `txn_limit` gives the maximum number of transactions to run per connection
  before reconnecting. Defaults to 0, which means no limit.

* `allow_unsafe_locale` is an option specific to Postgres. Under the default behavior, Synapse will refuse to
  start if the postgres db is set to a non-C locale. You can override this behavior (which is *not* recommended)
  by setting `allow_unsafe_locale` to true. Note that doing so may corrupt your database. You can find more information
  [here](../../postgres.md#fixing-incorrect-collate-or-ctype) and [here](https://wiki.postgresql.org/wiki/Locale_data_changes).

* `args` gives options which are passed through to the database engine,
  except for options starting with `cp_`, which are used to configure the Twisted
  connection pool. For a reference to valid arguments, see:
    * for [sqlite](https://docs.python.org/3/library/sqlite3.html#sqlite3.connect)
    * for [postgres](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-PARAMKEYWORDS)
    * for [the connection pool](https://docs.twistedmatrix.com/en/stable/api/twisted.enterprise.adbapi.ConnectionPool.html#__init__)

For more information on using Synapse with Postgres,
see [here](../../postgres.md).

Example SQLite configuration:
```yaml
database:
  name: sqlite3
  args:
    database: /path/to/homeserver.db
```

Example Postgres configuration:
```yaml
database:
  name: psycopg2
  txn_limit: 10000
  args:
    user: synapse_user
    password: secretpassword
    dbname: synapse
    host: localhost
    port: 5432
    cp_min: 5
    cp_max: 10
```
---
### `databases`

The `databases` option allows specifying a mapping between certain database tables and
database host details, spreading the load of a single Synapse instance across multiple
database backends. This is often referred to as "database sharding". This option is only
supported for PostgreSQL database backends.

**Important note:** This is a supported option, but is not currently used in production by the
Matrix.org Foundation. Proceed with caution and always make backups.

`databases` is a dictionary of arbitrarily-named database entries. Each entry is equivalent
to the value of the `database` homeserver config option (see above), with the addition of
a `data_stores` key. `data_stores` is an array of strings that specifies the data store(s)
(a defined label for a set of tables) that should be stored on the associated database
backend entry.

The currently defined values for `data_stores` are:

* `"state"`: Database that relates to state groups will be stored in this database.

  Specifically, that means the following tables:
  * `state_groups`
  * `state_group_edges`
  * `state_groups_state`

  And the following sequences:
  * `state_groups_seq_id`

* `"main"`: All other database tables and sequences.

All databases will end up with additional tables used for tracking database schema migrations
and any pending background updates. Synapse will create these automatically on startup when checking for
and/or performing database schema migrations.

To migrate an existing database configuration (e.g. all tables on a single database) to a different
configuration (e.g. the "main" data store on one database, and "state" on another), do the following:

1. Take a backup of your existing database. Things can and do go wrong and database corruption is no joke!
2. Ensure all pending database migrations have been applied and background updates have run. The simplest
   way to do this is to use the `update_synapse_database` script supplied with your Synapse installation.

   ```sh
   update_synapse_database --database-config homeserver.yaml --run-background-updates
   ```

3. Copy over the necessary tables and sequences from one database to the other. Tables relating to database
   migrations, schemas, schema versions and background updates should **not** be copied.

   As an example, say that you'd like to split out the "state" data store from an existing database which
   currently contains all data stores.

   Simply copy the tables and sequences defined above for the "state" datastore from the existing database
   to the secondary database. As noted above, additional tables will be created in the secondary database
   when Synapse is started.

4. Modify/create the `databases` option in your `homeserver.yaml` to match the desired database configuration.
5. Start Synapse. Check that it starts up successfully and that things generally seem to be working.
6. Drop the old tables that were copied in step 3.

Only one of the options `database` or `databases` may be specified in your config, but not both.

Example configuration:

```yaml
databases:
  basement_box:
    name: psycopg2
    txn_limit: 10000
    data_stores: ["main"]
    args:
      user: synapse_user
      password: secretpassword
      dbname: synapse_main
      host: localhost
      port: 5432
      cp_min: 5
      cp_max: 10

  my_other_database:
    name: psycopg2
    txn_limit: 10000
    data_stores: ["state"]
    args:
      user: synapse_user
      password: secretpassword
      dbname: synapse_state
      host: localhost
      port: 5432
      cp_min: 5
      cp_max: 10
```
---
## Logging
Config options related to logging.

---
### `log_config`

This option specifies a yaml python logging config file as described
[here](https://docs.python.org/3/library/logging.config.html#configuration-dictionary-schema).

Example configuration:
```yaml
log_config: "CONFDIR/SERVERNAME.log.config"
```
---
## Ratelimiting
Options related to ratelimiting in Synapse.

Each ratelimiting configuration is made of two parameters:
   - `per_second`: number of requests a client can send per second.
   - `burst_count`: number of requests a client can send before being throttled.
---
### `rc_message`


Ratelimiting settings for client messaging.

This is a ratelimiting option for messages that ratelimits sending based on the account the client
is using. It defaults to: `per_second: 0.2`, `burst_count: 10`.

Example configuration:
```yaml
rc_message:
  per_second: 0.5
  burst_count: 15
```
---
### `rc_registration`

This option ratelimits registration requests based on the client's IP address.
It defaults to `per_second: 0.17`, `burst_count: 3`.

Example configuration:
```yaml
rc_registration:
  per_second: 0.15
  burst_count: 2
```
---
### `rc_registration_token_validity`

This option checks the validity of registration tokens that ratelimits requests based on
the client's IP address.
Defaults to `per_second: 0.1`, `burst_count: 5`.

Example configuration:
```yaml
rc_registration_token_validity:
  per_second: 0.3
  burst_count: 6
```
---
### `rc_login`

This option specifies several limits for login:
* `address` ratelimits login requests based on the client's IP
      address. Defaults to `per_second: 0.003`, `burst_count: 5`.

* `account` ratelimits login requests based on the account the
  client is attempting to log into. Defaults to `per_second: 0.003`,
  `burst_count: 5`.

* `failed_attempts` ratelimits login requests based on the account the
  client is attempting to log into, based on the amount of failed login
  attempts for this account. Defaults to `per_second: 0.17`, `burst_count: 3`.

Example configuration:
```yaml
rc_login:
  address:
    per_second: 0.15
    burst_count: 5
  account:
    per_second: 0.18
    burst_count: 4
  failed_attempts:
    per_second: 0.19
    burst_count: 7
```
---
### `rc_admin_redaction`

This option sets ratelimiting redactions by room admins. If this is not explicitly
set then it uses the same ratelimiting as per `rc_message`. This is useful
to allow room admins to deal with abuse quickly.

Example configuration:
```yaml
rc_admin_redaction:
  per_second: 1
  burst_count: 50
```
---
### `rc_joins`

This option allows for ratelimiting number of rooms a user can join. This setting has the following sub-options:

* `local`: ratelimits when users are joining rooms the server is already in.
   Defaults to `per_second: 0.1`, `burst_count: 10`.

* `remote`: ratelimits when users are trying to join rooms not on the server (which
  can be more computationally expensive than restricting locally). Defaults to
  `per_second: 0.01`, `burst_count: 10`

Example configuration:
```yaml
rc_joins:
  local:
    per_second: 0.2
    burst_count: 15
  remote:
    per_second: 0.03
    burst_count: 12
```
---
### `rc_joins_per_room`

This option allows admins to ratelimit joins to a room based on the number of recent
joins (local or remote) to that room. It is intended to mitigate mass-join spam
waves which target multiple homeservers.

By default, one join is permitted to a room every second, with an accumulating
buffer of up to ten instantaneous joins.

Example configuration (default values):
```yaml
rc_joins_per_room:
  per_second: 1
  burst_count: 10
```

_Added in Synapse 1.64.0._

---
### `rc_3pid_validation`

This option ratelimits how often a user or IP can attempt to validate a 3PID.
Defaults to `per_second: 0.003`, `burst_count: 5`.

Example configuration:
```yaml
rc_3pid_validation:
  per_second: 0.003
  burst_count: 5
```
---
### `rc_invites`

This option sets ratelimiting how often invites can be sent in a room or to a
specific user. `per_room` defaults to `per_second: 0.3`, `burst_count: 10` and
`per_user` defaults to `per_second: 0.003`, `burst_count: 5`.

Client requests that invite user(s) when [creating a
room](https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3createroom)
will count against the `rc_invites.per_room` limit, whereas
client requests to [invite a single user to a
room](https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidinvite)
will count against both the `rc_invites.per_user` and `rc_invites.per_room` limits.

Federation requests to invite a user will count against the `rc_invites.per_user`
limit only, as Synapse presumes ratelimiting by room will be done by the sending server.

The `rc_invites.per_user` limit applies to the *receiver* of the invite, rather than the
sender, meaning that a `rc_invite.per_user.burst_count` of 5 mandates that a single user
cannot *receive* more than a burst of 5 invites at a time.

In contrast, the `rc_invites.per_issuer` limit applies to the *issuer* of the invite, meaning that a `rc_invite.per_issuer.burst_count` of 5 mandates that single user cannot *send* more than a burst of 5 invites at a time.

_Changed in version 1.63:_ added the `per_issuer` limit.

Example configuration:
```yaml
rc_invites:
  per_room:
    per_second: 0.5
    burst_count: 5
  per_user:
    per_second: 0.004
    burst_count: 3
  per_issuer:
    per_second: 0.5
    burst_count: 5
```

---
### `rc_third_party_invite`

This option ratelimits 3PID invites (i.e. invites sent to a third-party ID
such as an email address or a phone number) based on the account that's
sending the invite. Defaults to `per_second: 0.2`, `burst_count: 10`.

Example configuration:
```yaml
rc_third_party_invite:
  per_second: 0.2
  burst_count: 10
```
---
### `rc_media_create`

This option ratelimits creation of MXC URIs via the `/_matrix/media/v1/create`
endpoint based on the account that's creating the media. Defaults to
`per_second: 10`, `burst_count: 50`.

Example configuration:
```yaml
rc_media_create:
  per_second: 10
  burst_count: 50
```
---
### `rc_federation`

Defines limits on federation requests.

The `rc_federation` configuration has the following sub-options:
* `window_size`: window size in milliseconds. Defaults to 1000.
* `sleep_limit`: number of federation requests from a single server in
   a window before the server will delay processing the request. Defaults to 10.
* `sleep_delay`: duration in milliseconds to delay processing events
   from remote servers by if they go over the sleep limit. Defaults to 500.
* `reject_limit`: maximum number of concurrent federation requests
   allowed from a single server. Defaults to 50.
* `concurrent`: number of federation requests to concurrently process
   from a single server. Defaults to 3.

Example configuration:
```yaml
rc_federation:
  window_size: 750
  sleep_limit: 15
  sleep_delay: 400
  reject_limit: 40
  concurrent: 5
```
---
### `federation_rr_transactions_per_room_per_second`

Sets outgoing federation transaction frequency for sending read-receipts,
per-room.

If we end up trying to send out more read-receipts, they will get buffered up
into fewer transactions. Defaults to 50.

Example configuration:
```yaml
federation_rr_transactions_per_room_per_second: 40
```
---
## Media Store
Config options related to Synapse's media store.

---
### `enable_media_repo`

Enable the media store service in the Synapse master. Defaults to true.
Set to false if you are using a separate media store worker.

Example configuration:
```yaml
enable_media_repo: false
```
---
### `media_store_path`

Directory where uploaded images and attachments are stored.

Example configuration:
```yaml
media_store_path: "DATADIR/media_store"
```
---
### `max_pending_media_uploads`

How many *pending media uploads* can a given user have? A pending media upload
is a created MXC URI that (a) is not expired (the `unused_expires_at` timestamp
has not passed) and (b) the media has not yet been uploaded for. Defaults to 5.

Example configuration:
```yaml
max_pending_media_uploads: 5
```
---
### `unused_expiration_time`

How long to wait in milliseconds before expiring created media IDs. Defaults to
"24h"

Example configuration:
```yaml
unused_expiration_time: "1h"
```
---
### `media_storage_providers`

Media storage providers allow media to be stored in different
locations. Defaults to none. Associated sub-options are:
* `module`: type of resource, e.g. `file_system`.
* `store_local`: whether to store newly uploaded local files
* `store_remote`: whether to store newly downloaded local files
* `store_synchronous`: whether to wait for successful storage for local uploads
* `config`: sets a path to the resource through the `directory` option

Example configuration:
```yaml
media_storage_providers:
  - module: file_system
    store_local: false
    store_remote: false
    store_synchronous: false
    config:
       directory: /mnt/some/other/directory
```
---
### `max_upload_size`

The largest allowed upload size in bytes.

If you are using a reverse proxy you may also need to set this value in
your reverse proxy's config. Defaults to 50M. Notably Nginx has a small max body size by default.
See [here](../../reverse_proxy.md) for more on using a reverse proxy with Synapse.

Example configuration:
```yaml
max_upload_size: 60M
```
---
### `max_image_pixels`

Maximum number of pixels that will be thumbnailed. Defaults to 32M.

Example configuration:
```yaml
max_image_pixels: 35M
```
---
### `prevent_media_downloads_from`

A list of domains to never download media from. Media from these
domains that is already downloaded will not be deleted, but will be
inaccessible to users. This option does not affect admin APIs trying
to download/operate on media.

This will not prevent the listed domains from accessing media themselves.
It simply prevents users on this server from downloading media originating
from the listed servers.

This will have no effect on media originating from the local server.
This only affects media downloaded from other Matrix servers, to
block domains from URL previews see [`url_preview_url_blacklist`](#url_preview_url_blacklist).

Defaults to an empty list (nothing blocked).

Example configuration:
```yaml
prevent_media_downloads_from:
  - evil.example.org
  - evil2.example.org
```
---
### `dynamic_thumbnails`

Whether to generate new thumbnails on the fly to precisely match
the resolution requested by the client. If true then whenever
a new resolution is requested by the client the server will
generate a new thumbnail. If false the server will pick a thumbnail
from a precalculated list. Defaults to false.

Example configuration:
```yaml
dynamic_thumbnails: true
```
---
### `thumbnail_sizes`

List of thumbnails to precalculate when an image is uploaded. Associated sub-options are:
* `width`
* `height`
* `method`: i.e. `crop`, `scale`, etc.

Example configuration:
```yaml
thumbnail_sizes:
  - width: 32
    height: 32
    method: crop
  - width: 96
    height: 96
    method: crop
  - width: 320
    height: 240
    method: scale
  - width: 640
    height: 480
    method: scale
  - width: 800
    height: 600
    method: scale
```
---
### `media_retention`

Controls whether local media and entries in the remote media cache
(media that is downloaded from other homeservers) should be removed
under certain conditions, typically for the purpose of saving space.

Purging media files will be the carried out by the media worker
(that is, the worker that has the `enable_media_repo` homeserver config
option set to 'true'). This may be the main process.

The `media_retention.local_media_lifetime` and
`media_retention.remote_media_lifetime` config options control whether
media will be purged if it has not been accessed in a given amount of
time. Note that media is 'accessed' when loaded in a room in a client, or
otherwise downloaded by a local or remote user. If the media has never
been accessed, the media's creation time is used instead. Both thumbnails
and the original media will be removed. If either of these options are unset,
then media of that type will not be purged.

Local or cached remote media that has been
[quarantined](../../admin_api/media_admin_api.md#quarantining-media-in-a-room)
will not be deleted. Similarly, local media that has been marked as
[protected from quarantine](../../admin_api/media_admin_api.md#protecting-media-from-being-quarantined)
will not be deleted.

Example configuration:
```yaml
media_retention:
    local_media_lifetime: 90d
    remote_media_lifetime: 14d
```
---
### `url_preview_enabled`

This setting determines whether the preview URL API is enabled.
It is disabled by default. Set to true to enable. If enabled you must specify a
`url_preview_ip_range_blacklist` blacklist.

Example configuration:
```yaml
url_preview_enabled: true
```
---
### `url_preview_ip_range_blacklist`

List of IP address CIDR ranges that the URL preview spider is denied
from accessing.  There are no defaults: you must explicitly
specify a list for URL previewing to work.  You should specify any
internal services in your network that you do not want synapse to try
to connect to, otherwise anyone in any Matrix room could cause your
synapse to issue arbitrary GET requests to your internal services,
causing serious security issues.

(0.0.0.0 and :: are always blacklisted, whether or not they are explicitly
listed here, since they correspond to unroutable addresses.)

This must be specified if `url_preview_enabled` is set. It is recommended that
you use the following example list as a starting point.

Note: The value is ignored when an HTTP proxy is in use.

Example configuration:
```yaml
url_preview_ip_range_blacklist:
  - '127.0.0.0/8'
  - '10.0.0.0/8'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - '100.64.0.0/10'
  - '192.0.0.0/24'
  - '169.254.0.0/16'
  - '192.88.99.0/24'
  - '198.18.0.0/15'
  - '192.0.2.0/24'
  - '198.51.100.0/24'
  - '203.0.113.0/24'
  - '224.0.0.0/4'
  - '::1/128'
  - 'fe80::/10'
  - 'fc00::/7'
  - '2001:db8::/32'
  - 'ff00::/8'
  - 'fec0::/10'
```
---
### `url_preview_ip_range_whitelist`

This option sets a list of IP address CIDR ranges that the URL preview spider is allowed
to access even if they are specified in `url_preview_ip_range_blacklist`.
This is useful for specifying exceptions to wide-ranging blacklisted
target IP ranges - e.g. for enabling URL previews for a specific private
website only visible in your network. Defaults to none.

Example configuration:
```yaml
url_preview_ip_range_whitelist:
   - '192.168.1.1'
```
---
### `url_preview_url_blacklist`

Optional list of URL matches that the URL preview spider is
denied from accessing.  You should use `url_preview_ip_range_blacklist`
in preference to this, otherwise someone could define a public DNS
entry that points to a private IP address and circumvent the blacklist.
This is more useful if you know there is an entire shape of URL that
you know that will never want synapse to try to spider.

Each list entry is a dictionary of url component attributes as returned
by urlparse.urlsplit as applied to the absolute form of the URL.  See
[here](https://docs.python.org/2/library/urlparse.html#urlparse.urlsplit) for more
information. Some examples are:

* `username`
* `netloc`
* `scheme`
* `path`

The values of the dictionary are treated as a filename match pattern
applied to that component of URLs, unless they start with a ^ in which
case they are treated as a regular expression match.  If all the
specified component matches for a given list item succeed, the URL is
blacklisted.

Example configuration:
```yaml
url_preview_url_blacklist:
  # blacklist any URL with a username in its URI
  - username: '*'

  # blacklist all *.google.com URLs
  - netloc: 'google.com'
  - netloc: '*.google.com'

  # blacklist all plain HTTP URLs
  - scheme: 'http'

  # blacklist http(s)://www.acme.com/foo
  - netloc: 'www.acme.com'
    path: '/foo'

  # blacklist any URL with a literal IPv4 address
  - netloc: '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
```
---
### `max_spider_size`

The largest allowed URL preview spidering size in bytes. Defaults to 10M.

Example configuration:
```yaml
max_spider_size: 8M
```
---
### `url_preview_accept_language`

A list of values for the Accept-Language HTTP header used when
downloading webpages during URL preview generation. This allows
Synapse to specify the preferred languages that URL previews should
be in when communicating with remote servers.

Each value is a IETF language tag; a 2-3 letter identifier for a
language, optionally followed by subtags separated by '-', specifying
a country or region variant.

Multiple values can be provided, and a weight can be added to each by
using quality value syntax (;q=). '*' translates to any language.

Defaults to "en".

Example configuration:
```yaml
 url_preview_accept_language:
   - 'en-UK'
   - 'en-US;q=0.9'
   - 'fr;q=0.8'
   - '*;q=0.7'
```
---
### `oembed`

oEmbed allows for easier embedding content from a website. It can be
used for generating URLs previews of services which support it. A default list of oEmbed providers
is included with Synapse. Set `disable_default_providers` to true to disable using
these default oEmbed URLs. Use `additional_providers` to specify additional files with oEmbed configuration (each
should be in the form of providers.json). By default this list is empty.

Example configuration:
```yaml
oembed:
  disable_default_providers: true
  additional_providers:
    - oembed/my_providers.json
```
---
## Captcha

See [here](../../CAPTCHA_SETUP.md) for full details on setting up captcha.

---
### `recaptcha_public_key`

This homeserver's ReCAPTCHA public key. Must be specified if
[`enable_registration_captcha`](#enable_registration_captcha) is enabled.

Example configuration:
```yaml
recaptcha_public_key: "YOUR_PUBLIC_KEY"
```
---
### `recaptcha_private_key`

This homeserver's ReCAPTCHA private key. Must be specified if
[`enable_registration_captcha`](#enable_registration_captcha) is
enabled.

Example configuration:
```yaml
recaptcha_private_key: "YOUR_PRIVATE_KEY"
```
---
### `enable_registration_captcha`

Set to `true` to require users to complete a CAPTCHA test when registering an account.
Requires a valid ReCaptcha public/private key.
Defaults to `false`.

Note that [`enable_registration`](#enable_registration) must also be set to allow account registration.

Example configuration:
```yaml
enable_registration_captcha: true
```
---
### `recaptcha_siteverify_api`

The API endpoint to use for verifying `m.login.recaptcha` responses.
Defaults to `https://www.recaptcha.net/recaptcha/api/siteverify`.

Example configuration:
```yaml
recaptcha_siteverify_api: "https://my.recaptcha.site"
```
---
## TURN
Options related to adding a TURN server to Synapse.

---
### `turn_uris`

The public URIs of the TURN server to give to clients.

Example configuration:
```yaml
turn_uris: [turn:example.org]
```
---
### `turn_shared_secret`

The shared secret used to compute passwords for the TURN server.

Example configuration:
```yaml
turn_shared_secret: "YOUR_SHARED_SECRET"
```
---
### `turn_username` and `turn_password`

The Username and password if the TURN server needs them and does not use a token.

Example configuration:
```yaml
turn_username: "TURNSERVER_USERNAME"
turn_password: "TURNSERVER_PASSWORD"
```
---
### `turn_user_lifetime`

How long generated TURN credentials last. Defaults to 1h.

Example configuration:
```yaml
turn_user_lifetime: 2h
```
---
### `turn_allow_guests`

Whether guests should be allowed to use the TURN server. This defaults to true, otherwise
VoIP will be unreliable for guests. However, it does introduce a slight security risk as
it allows users to connect to arbitrary endpoints without having first signed up for a valid account (e.g. by passing a CAPTCHA).

Example configuration:
```yaml
turn_allow_guests: false
```
---
## Registration ##

Registration can be rate-limited using the parameters in the [Ratelimiting](#ratelimiting) section of this manual.

---
### `enable_registration`

Enable registration for new users. Defaults to `false`.

It is highly recommended that if you enable registration, you set one or more
or the following options, to avoid abuse of your server by "bots":

 * [`enable_registration_captcha`](#enable_registration_captcha)
 * [`registrations_require_3pid`](#registrations_require_3pid)
 * [`registration_requires_token`](#registration_requires_token)

(In order to enable registration without any verification, you must also set
[`enable_registration_without_verification`](#enable_registration_without_verification).)

Note that even if this setting is disabled, new accounts can still be created
via the admin API if
[`registration_shared_secret`](#registration_shared_secret) is set.

Example configuration:
```yaml
enable_registration: true
```
---
### `enable_registration_without_verification`

Enable registration without email or captcha verification. Note: this option is *not* recommended,
as registration without verification is a known vector for spam and abuse. Defaults to `false`. Has no effect
unless [`enable_registration`](#enable_registration) is also enabled.

Example configuration:
```yaml
enable_registration_without_verification: true
```
---
### `registrations_require_3pid`

If this is set, users must provide all of the specified types of 3PID when registering an account.

Note that [`enable_registration`](#enable_registration) must also be set to allow account registration.

Example configuration:
```yaml
registrations_require_3pid:
  - email
  - msisdn
```
---
### `disable_msisdn_registration`

Explicitly disable asking for MSISDNs from the registration
flow (overrides `registrations_require_3pid` if MSISDNs are set as required).

Example configuration:
```yaml
disable_msisdn_registration: true
```
---
### `allowed_local_3pids`

Mandate that users are only allowed to associate certain formats of
3PIDs with accounts on this server, as specified by the `medium` and `pattern` sub-options.

Example configuration:
```yaml
allowed_local_3pids:
  - medium: email
    pattern: '^[^@]+@matrix\.org$'
  - medium: email
    pattern: '^[^@]+@vector\.im$'
  - medium: msisdn
    pattern: '\+44'
```
---
### `enable_3pid_lookup`

Enable 3PIDs lookup requests to identity servers from this server. Defaults to true.

Example configuration:
```yaml
enable_3pid_lookup: false
```
---
### `registration_requires_token`

Require users to submit a token during registration.
Tokens can be managed using the admin [API](../administration/admin_api/registration_tokens.md).
Disabling this option will not delete any tokens previously generated.
Defaults to `false`. Set to `true` to enable.


Note that [`enable_registration`](#enable_registration) must also be set to allow account registration.

Example configuration:
```yaml
registration_requires_token: true
```
---
### `registration_shared_secret`

If set, allows registration of standard or admin accounts by anyone who has the
shared secret, even if [`enable_registration`](#enable_registration) is not
set.

This is primarily intended for use with the `register_new_matrix_user` script
(see [Registering a user](../../setup/installation.md#registering-a-user));
however, the interface is [documented](../../admin_api/register_api.html).

See also [`registration_shared_secret_path`](#registration_shared_secret_path).

Example configuration:
```yaml
registration_shared_secret: <PRIVATE STRING>
```

---
### `registration_shared_secret_path`

An alternative to [`registration_shared_secret`](#registration_shared_secret):
allows the shared secret to be specified in an external file.

The file should be a plain text file, containing only the shared secret.

If this file does not exist, Synapse will create a new shared
secret on startup and store it in this file.

Example configuration:
```yaml
registration_shared_secret_path: /path/to/secrets/file
```

_Added in Synapse 1.67.0._

---
### `bcrypt_rounds`

Set the number of bcrypt rounds used to generate password hash.
Larger numbers increase the work factor needed to generate the hash.
The default number is 12 (which equates to 2^12 rounds).
N.B. that increasing this will exponentially increase the time required
to register or login - e.g. 24 => 2^24 rounds which will take >20 mins.
Example configuration:
```yaml
bcrypt_rounds: 14
```
---
### `allow_guest_access`

Allows users to register as guests without a password/email/etc, and
participate in rooms hosted on this server which have been made
accessible to anonymous users. Defaults to false.

Example configuration:
```yaml
allow_guest_access: true
```
---
### `default_identity_server`

The identity server which we suggest that clients should use when users log
in on this server.

(By default, no suggestion is made, so it is left up to the client.
This setting is ignored unless `public_baseurl` is also explicitly set.)

Example configuration:
```yaml
default_identity_server: https://matrix.org
```
---
### `account_threepid_delegates`

Delegate verification of phone numbers to an identity server.

When a user wishes to add a phone number to their account, we need to verify that they
actually own that phone number, which requires sending them a text message (SMS).
Currently Synapse does not support sending those texts itself and instead delegates the
task to an identity server. The base URI for the identity server to be used is
specified by the `account_threepid_delegates.msisdn` option.

If this is left unspecified, Synapse will not allow users to add phone numbers to
their account.

(Servers handling the these requests must answer the `/requestToken` endpoints defined
by the Matrix Identity Service API
[specification](https://matrix.org/docs/spec/identity_service/latest).)

*Deprecated in Synapse 1.64.0*: The `email` option is deprecated.

*Removed in Synapse 1.66.0*: The `email` option has been removed.
If present, Synapse will report a configuration error on startup.

Example configuration:
```yaml
account_threepid_delegates:
    msisdn: http://localhost:8090  # Delegate SMS sending to this local process
```
---
### `enable_set_displayname`

Whether users are allowed to change their displayname after it has
been initially set. Useful when provisioning users based on the
contents of a third-party directory.

Does not apply to server administrators. Defaults to true.

Example configuration:
```yaml
enable_set_displayname: false
```
---
### `enable_set_avatar_url`

Whether users are allowed to change their avatar after it has been
initially set. Useful when provisioning users based on the contents
of a third-party directory.

Does not apply to server administrators. Defaults to true.

Example configuration:
```yaml
enable_set_avatar_url: false
```
---
### `enable_3pid_changes`

Whether users can change the third-party IDs associated with their accounts
(email address and msisdn).

Defaults to true.

Example configuration:
```yaml
enable_3pid_changes: false
```
---
### `auto_join_rooms`

Users who register on this homeserver will automatically be joined
to the rooms listed under this option.

By default, any room aliases included in this list will be created
as a publicly joinable room when the first user registers for the
homeserver. If the room already exists, make certain it is a publicly joinable
room, i.e. the join rule of the room must be set to 'public'. You can find more options
relating to auto-joining rooms below.

As Spaces are just rooms under the hood, Space aliases may also be
used.

Example configuration:
```yaml
auto_join_rooms:
  - "#exampleroom:example.com"
  - "#anotherexampleroom:example.com"
```
---
### `autocreate_auto_join_rooms`

Where `auto_join_rooms` are specified, setting this flag ensures that
the rooms exist by creating them when the first user on the
homeserver registers. This option will not create Spaces.

By default the auto-created rooms are publicly joinable from any federated
server. Use the `autocreate_auto_join_rooms_federated` and
`autocreate_auto_join_room_preset` settings to customise this behaviour.

Setting to false means that if the rooms are not manually created,
users cannot be auto-joined since they do not exist.

Defaults to true.

Example configuration:
```yaml
autocreate_auto_join_rooms: false
```
---
### `autocreate_auto_join_rooms_federated`

Whether the rooms listed in `auto_join_rooms` that are auto-created are available
via federation. Only has an effect if `autocreate_auto_join_rooms` is true.

Note that whether a room is federated cannot be modified after
creation.

Defaults to true: the room will be joinable from other servers.
Set to false to prevent users from other homeservers from
joining these rooms.

Example configuration:
```yaml
autocreate_auto_join_rooms_federated: false
```
---
### `autocreate_auto_join_room_preset`

The room preset to use when auto-creating one of `auto_join_rooms`. Only has an
effect if `autocreate_auto_join_rooms` is true.

Possible values for this option are:
* "public_chat": the room is joinable by anyone, including
  federated servers if `autocreate_auto_join_rooms_federated` is true (the default).
* "private_chat": an invitation is required to join these rooms.
* "trusted_private_chat": an invitation is required to join this room and the invitee is
  assigned a power level of 100 upon joining the room.

If a value of "private_chat" or "trusted_private_chat" is used then
`auto_join_mxid_localpart` must also be configured.

Defaults to "public_chat".

Example configuration:
```yaml
autocreate_auto_join_room_preset: private_chat
```
---
### `auto_join_mxid_localpart`

The local part of the user id which is used to create `auto_join_rooms` if
`autocreate_auto_join_rooms` is true. If this is not provided then the
initial user account that registers will be used to create the rooms.

The user id is also used to invite new users to any auto-join rooms which
are set to invite-only.

It *must* be configured if `autocreate_auto_join_room_preset` is set to
"private_chat" or "trusted_private_chat".

Note that this must be specified in order for new users to be correctly
invited to any auto-join rooms which have been set to invite-only (either
at the time of creation or subsequently).

Note that, if the room already exists, this user must be joined and
have the appropriate permissions to invite new members.

Example configuration:
```yaml
auto_join_mxid_localpart: system
```
---
### `auto_join_rooms_for_guests`

When `auto_join_rooms` is specified, setting this flag to false prevents
guest accounts from being automatically joined to the rooms.

Defaults to true.

Example configuration:
```yaml
auto_join_rooms_for_guests: false
```
---
### `inhibit_user_in_use_error`

Whether to inhibit errors raised when registering a new account if the user ID
already exists. If turned on, requests to `/register/available` will always
show a user ID as available, and Synapse won't raise an error when starting
a registration with a user ID that already exists. However, Synapse will still
raise an error if the registration completes and the username conflicts.

Defaults to false.

Example configuration:
```yaml
inhibit_user_in_use_error: true
```
---
## User session management
---
### `session_lifetime`

Time that a user's session remains valid for, after they log in.

Note that this is not currently compatible with guest logins.

Note also that this is calculated at login time: changes are not applied retrospectively to users who have already
logged in.

By default, this is infinite.

Example configuration:
```yaml
session_lifetime: 24h
```
---
### `refresh_access_token_lifetime`

Time that an access token remains valid for, if the session is using refresh tokens.

For more information about refresh tokens, please see the [manual](user_authentication/refresh_tokens.md).

Note that this only applies to clients which advertise support for refresh tokens.

Note also that this is calculated at login time and refresh time: changes are not applied to
existing sessions until they are refreshed.

By default, this is 5 minutes.

Example configuration:
```yaml
refreshable_access_token_lifetime: 10m
```
---
### `refresh_token_lifetime: 24h`

Time that a refresh token remains valid for (provided that it is not
exchanged for another one first).
This option can be used to automatically log-out inactive sessions.
Please see the manual for more information.

Note also that this is calculated at login time and refresh time:
changes are not applied to existing sessions until they are refreshed.

By default, this is infinite.

Example configuration:
```yaml
refresh_token_lifetime: 24h
```
---
### `nonrefreshable_access_token_lifetime`

Time that an access token remains valid for, if the session is NOT
using refresh tokens.

Please note that not all clients support refresh tokens, so setting
this to a short value may be inconvenient for some users who will
then be logged out frequently.

Note also that this is calculated at login time: changes are not applied
retrospectively to existing sessions for users that have already logged in.

By default, this is infinite.

Example configuration:
```yaml
nonrefreshable_access_token_lifetime: 24h
```
---
### `ui_auth`

The amount of time to allow a user-interactive authentication session to be active.

This defaults to 0, meaning the user is queried for their credentials
before every action, but this can be overridden to allow a single
validation to be re-used.  This weakens the protections afforded by
the user-interactive authentication process, by allowing for multiple
(and potentially different) operations to use the same validation session.

This is ignored for potentially "dangerous" operations (including
deactivating an account, modifying an account password, adding a 3PID,
and minting additional login tokens).

Use the `session_timeout` sub-option here to change the time allowed for credential validation.

Example configuration:
```yaml
ui_auth:
    session_timeout: "15s"
```
---
### `login_via_existing_session`

Matrix supports the ability of an existing session to mint a login token for
another client.

Synapse disables this by default as it has security ramifications -- a malicious
client could use the mechanism to spawn more than one session.

The duration of time the generated token is valid for can be configured with the
`token_timeout` sub-option.

User-interactive authentication is required when this is enabled unless the
`require_ui_auth` sub-option is set to `False`.

Example configuration:
```yaml
login_via_existing_session:
    enabled: true
    require_ui_auth: false
    token_timeout: "5m"
```
---
## Metrics
Config options related to metrics.

---
### `enable_metrics`

Set to true to enable collection and rendering of performance metrics.
Defaults to false.

Example configuration:
```yaml
enable_metrics: true
```
---
### `sentry`

Use this option to enable sentry integration. Provide the DSN assigned to you by sentry
with the `dsn` setting.

NOTE: While attempts are made to ensure that the logs don't contain
any sensitive information, this cannot be guaranteed. By enabling
this option the sentry server may therefore receive sensitive
information, and it in turn may then disseminate sensitive information
through insecure notification channels if so configured.

Example configuration:
```yaml
sentry:
    dsn: "..."
```
---
### `metrics_flags`

Flags to enable Prometheus metrics which are not suitable to be
enabled by default, either for performance reasons or limited use.
Currently the only option is `known_servers`, which publishes
`synapse_federation_known_servers`, a gauge of the number of
servers this homeserver knows about, including itself. May cause
performance problems on large homeservers.

Example configuration:
```yaml
metrics_flags:
    known_servers: true
```
---
### `report_stats`

Whether or not to report homeserver usage statistics. This is originally
set when generating the config. Set this option to true or false to change the current
behavior. See
[Reporting Homeserver Usage Statistics](../administration/monitoring/reporting_homeserver_usage_statistics.md)
for information on what data is reported.

Statistics will be reported 5 minutes after Synapse starts, and then every 3 hours
after that.

Example configuration:
```yaml
report_stats: true
```
---
### `report_stats_endpoint`

The endpoint to report homeserver usage statistics to.
Defaults to https://matrix.org/report-usage-stats/push

Example configuration:
```yaml
report_stats_endpoint: https://example.com/report-usage-stats/push
```
---
## API Configuration
Config settings related to the client/server API

---
### `room_prejoin_state`

This setting controls the state that is shared with users upon receiving an
invite to a room, or in reply to a knock on a room. By default, the following
state events are shared with users:

- `m.room.join_rules`
- `m.room.canonical_alias`
- `m.room.avatar`
- `m.room.encryption`
- `m.room.name`
- `m.room.create`
- `m.room.topic`

To change the default behavior, use the following sub-options:
* `disable_default_event_types`: boolean. Set to `true` to disable the above
  defaults. If this is enabled, only the event types listed in
  `additional_event_types` are shared. Defaults to `false`.
* `additional_event_types`: A list of additional state events to include in the
  events to be shared. By default, this list is empty (so only the default event
  types are shared).

  Each entry in this list should be either a single string or a list of two
  strings.
  * A standalone string `t` represents all events with type `t` (i.e.
    with no restrictions on state keys).
  * A pair of strings `[t, s]` represents a single event with type `t` and
    state key `s`. The same type can appear in two entries with different state
    keys: in this situation, both state keys are included in prejoin state.

Example configuration:
```yaml
room_prejoin_state:
   disable_default_event_types: false
   additional_event_types:
     # Share all events of type `org.example.custom.event.typeA`
     - org.example.custom.event.typeA
     # Share only events of type `org.example.custom.event.typeB` whose
     # state_key is "foo"
     - ["org.example.custom.event.typeB", "foo"]
     # Share only events of type `org.example.custom.event.typeC` whose
     # state_key is "bar" or "baz"
     - ["org.example.custom.event.typeC", "bar"]
     - ["org.example.custom.event.typeC", "baz"]
```

*Changed in Synapse 1.74:* admins can filter the events in prejoin state based
on their state key.

---
### `track_puppeted_user_ips`

We record the IP address of clients used to access the API for various
reasons, including displaying it to the user in the "Where you're signed in"
dialog.

By default, when puppeting another user via the admin API, the client IP
address is recorded against the user who created the access token (ie, the
admin user), and *not* the puppeted user.

Set this option to true to also record the IP address against the puppeted
user. (This also means that the puppeted user will count as an "active" user
for the purpose of monthly active user tracking - see `limit_usage_by_mau` etc
above.)

Example configuration:
```yaml
track_puppeted_user_ips: true
```
---
### `app_service_config_files`

A list of application service config files to use.

Example configuration:
```yaml
app_service_config_files:
  - app_service_1.yaml
  - app_service_2.yaml
```
---
### `track_appservice_user_ips`

Defaults to false. Set to true to enable tracking of application service IP addresses.
Implicitly enables MAU tracking for application service users.

Example configuration:
```yaml
track_appservice_user_ips: true
```
---
### `use_appservice_legacy_authorization`

Whether to send the application service access tokens via the `access_token` query parameter
per older versions of the Matrix specification. Defaults to false. Set to true to enable sending
access tokens via a query parameter.

**Enabling this option is considered insecure and is not recommended. **

Example configuration:
```yaml
use_appservice_legacy_authorization: true 
```

---
### `macaroon_secret_key`

A secret which is used to sign
- access token for guest users,
- short-term login token used during SSO logins (OIDC or SAML2) and
- token used for unsubscribing from email notifications.

If none is specified, the `registration_shared_secret` is used, if one is given;
otherwise, a secret key is derived from the signing key.

Example configuration:
```yaml
macaroon_secret_key: <PRIVATE STRING>
```
---
### `form_secret`

A secret which is used to calculate HMACs for form values, to stop
falsification of values. Must be specified for the User Consent
forms to work.

Example configuration:
```yaml
form_secret: <PRIVATE STRING>
```
---
## Signing Keys
Config options relating to signing keys

---
### `signing_key_path`

Path to the signing key to sign events and federation requests with.

*New in Synapse 1.67*: If this file does not exist, Synapse will create a new signing
key on startup and store it in this file.

Example configuration:
```yaml
signing_key_path: "CONFDIR/SERVERNAME.signing.key"
```
---
### `old_signing_keys`

The keys that the server used to sign messages with but won't use
to sign new messages. For each key, `key` should be the base64-encoded public key, and
`expired_ts`should be the time (in milliseconds since the unix epoch) that
it was last used.

It is possible to build an entry from an old `signing.key` file using the
`export_signing_key` script which is provided with synapse.

Example configuration:
```yaml
old_signing_keys:
  "ed25519:id": { key: "base64string", expired_ts: 123456789123 }
```
---
### `key_refresh_interval`

How long key response published by this server is valid for.
Used to set the `valid_until_ts` in `/key/v2` APIs.
Determines how quickly servers will query to check which keys
are still valid. Defaults to 1d.

Example configuration:
```yaml
key_refresh_interval: 2d
```
---
### `trusted_key_servers`

The trusted servers to download signing keys from.

When we need to fetch a signing key, each server is tried in parallel.

Normally, the connection to the key server is validated via TLS certificates.
Additional security can be provided by configuring a `verify key`, which
will make synapse check that the response is signed by that key.

This setting supersedes an older setting named `perspectives`. The old format
is still supported for backwards-compatibility, but it is deprecated.

`trusted_key_servers` defaults to matrix.org, but using it will generate a
warning on start-up. To suppress this warning, set
`suppress_key_server_warning` to true.

If the use of a trusted key server has to be deactivated, e.g. in a private
federation or for privacy reasons, this can be realised by setting
an empty array (`trusted_key_servers: []`). Then Synapse will request the keys
directly from the server that owns the keys. If Synapse does not get keys directly
from the server, the events of this server will be rejected.

Options for each entry in the list include:
* `server_name`: the name of the server. Required.
* `verify_keys`: an optional map from key id to base64-encoded public key.
   If specified, we will check that the response is signed by at least
   one of the given keys.
* `accept_keys_insecurely`: a boolean. Normally, if `verify_keys` is unset,
   and `federation_verify_certificates` is not `true`, synapse will refuse
   to start, because this would allow anyone who can spoof DNS responses
   to masquerade as the trusted key server. If you know what you are doing
   and are sure that your network environment provides a secure connection
   to the key server, you can set this to `true` to override this behaviour.

Example configuration #1:
```yaml
trusted_key_servers:
  - server_name: "my_trusted_server.example.com"
    verify_keys:
      "ed25519:auto": "abcdefghijklmnopqrstuvwxyzabcdefghijklmopqr"
  - server_name: "my_other_trusted_server.example.com"
```
Example configuration #2:
```yaml
trusted_key_servers:
  - server_name: "matrix.org"
```
---
### `suppress_key_server_warning`

Set the following to true to disable the warning that is emitted when the
`trusted_key_servers` include 'matrix.org'. See above.

Example configuration:
```yaml
suppress_key_server_warning: true
```
---
### `key_server_signing_keys_path`

The signing keys to use when acting as a trusted key server. If not specified
defaults to the server signing key.

Can contain multiple keys, one per line.

Example configuration:
```yaml
key_server_signing_keys_path: "key_server_signing_keys.key"
```
---
## Single sign-on integration

The following settings can be used to make Synapse use a single sign-on
provider for authentication, instead of its internal password database.

You will probably also want to set the following options to `false` to
disable the regular login/registration flows:
   * [`enable_registration`](#enable_registration)
   * [`password_config.enabled`](#password_config)

---
### `saml2_config`

Enable SAML2 for registration and login. Uses pysaml2. To learn more about pysaml and
to find a full list options for configuring pysaml, read the docs [here](https://pysaml2.readthedocs.io/en/latest/).

At least one of `sp_config` or `config_path` must be set in this section to
enable SAML login. You can either put your entire pysaml config inline using the `sp_config`
option, or you can specify a path to a psyaml config file with the sub-option `config_path`.
This setting has the following sub-options:

* `idp_name`: A user-facing name for this identity provider, which is used to
   offer the user a choice of login mechanisms.
* `idp_icon`: An optional icon for this identity provider, which is presented
   by clients and Synapse's own IdP picker page. If given, must be an
   MXC URI of the format `mxc://<server-name>/<media-id>`. (An easy way to
   obtain such an MXC URI is to upload an image to an (unencrypted) room
   and then copy the "url" from the source of the event.)
* `idp_brand`: An optional brand for this identity provider, allowing clients
   to style the login flow according to the identity provider in question.
   See the [spec](https://spec.matrix.org/latest/) for possible options here.
* `sp_config`: the configuration for the pysaml2 Service Provider. See pysaml2 docs for format of config.
   Default values will be used for the `entityid` and `service` settings,
   so it is not normally necessary to specify them unless you need to
   override them. Here are a few useful sub-options for configuring pysaml:
   * `metadata`: Point this to the IdP's metadata. You must provide either a local
      file via the `local` attribute or (preferably) a URL via the
      `remote` attribute.
   * `accepted_time_diff: 3`: Allowed clock difference in seconds between the homeserver and IdP.
      Defaults to 0.
   * `service`: By default, the user has to go to our login page first. If you'd like
     to allow IdP-initiated login, set `allow_unsolicited` to true under `sp` in the `service`
     section.
* `config_path`: specify a separate pysaml2 configuration file thusly:
  `config_path: "CONFDIR/sp_conf.py"`
* `saml_session_lifetime`: The lifetime of a SAML session. This defines how long a user has to
   complete the authentication process, if `allow_unsolicited` is unset. The default is 15 minutes.
* `user_mapping_provider`: Using this option, an external module can be provided as a
   custom solution to mapping attributes returned from a saml provider onto a matrix user. The
   `user_mapping_provider` has the following attributes:
  * `module`: The custom module's class.
  * `config`: Custom configuration values for the module. Use the values provided in the
     example if you are using the built-in user_mapping_provider, or provide your own
     config values for a custom class if you are using one. This section will be passed as a Python
     dictionary to the module's `parse_config` method. The built-in provider takes the following two
     options:
      * `mxid_source_attribute`: The SAML attribute (after mapping via the attribute maps) to use
          to derive the Matrix ID from. It is 'uid' by default. Note: This used to be configured by the
          `saml2_config.mxid_source_attribute option`. If that is still defined, its value will be used instead.
      * `mxid_mapping`: The mapping system to use for mapping the saml attribute onto a
         matrix ID. Options include: `hexencode` (which maps unpermitted characters to '=xx')
         and `dotreplace` (which replaces unpermitted characters with '.').
         The default is `hexencode`. Note: This used to be configured by the
         `saml2_config.mxid_mapping option`. If that is still defined, its value will be used instead.
* `grandfathered_mxid_source_attribute`: In previous versions of synapse, the mapping from SAML attribute to
   MXID was always calculated dynamically rather than stored in a table. For backwards- compatibility, we will look for `user_ids`
   matching such a pattern before creating a new account. This setting controls the SAML attribute which will be used for this
   backwards-compatibility lookup. Typically it should be 'uid', but if the attribute maps are changed, it may be necessary to change it.
   The default is 'uid'.
* `attribute_requirements`: It is possible to configure Synapse to only allow logins if SAML attributes
    match particular values. The requirements can be listed under
   `attribute_requirements` as shown in the example. All of the listed attributes must
    match for the login to be permitted.
* `idp_entityid`: If the metadata XML contains multiple IdP entities then the `idp_entityid`
   option must be set to the entity to redirect users to.
   Most deployments only have a single IdP entity and so should omit this option.


Once SAML support is enabled, a metadata file will be exposed at
`https://<server>:<port>/_synapse/client/saml2/metadata.xml`, which you may be able to
use to configure your SAML IdP with. Alternatively, you can manually configure
the IdP to use an ACS location of
`https://<server>:<port>/_synapse/client/saml2/authn_response`.

Example configuration:
```yaml
saml2_config:
  sp_config:
    metadata:
      local: ["saml2/idp.xml"]
      remote:
        - url: https://our_idp/metadata.xml
    accepted_time_diff: 3

    service:
      sp:
        allow_unsolicited: true

    # The examples below are just used to generate our metadata xml, and you
    # may well not need them, depending on your setup. Alternatively you
    # may need a whole lot more detail - see the pysaml2 docs!
    description: ["My awesome SP", "en"]
    name: ["Test SP", "en"]

    ui_info:
      display_name:
        - lang: en
          text: "Display Name is the descriptive name of your service."
      description:
        - lang: en
          text: "Description should be a short paragraph explaining the purpose of the service."
      information_url:
        - lang: en
          text: "https://example.com/terms-of-service"
      privacy_statement_url:
        - lang: en
          text: "https://example.com/privacy-policy"
      keywords:
        - lang: en
          text: ["Matrix", "Element"]
      logo:
        - lang: en
          text: "https://example.com/logo.svg"
          width: "200"
          height: "80"

    organization:
      name: Example com
      display_name:
        - ["Example co", "en"]
      url: "http://example.com"

    contact_person:
      - given_name: Bob
        sur_name: "the Sysadmin"
        email_address": ["admin@example.com"]
        contact_type": technical

  saml_session_lifetime: 5m

  user_mapping_provider:
    # Below options are intended for the built-in provider, they should be
    # changed if using a custom module.
    config:
      mxid_source_attribute: displayName
      mxid_mapping: dotreplace

  grandfathered_mxid_source_attribute: upn

  attribute_requirements:
    - attribute: userGroup
      value: "staff"
    - attribute: department
      value: "sales"

  idp_entityid: 'https://our_idp/entityid'
```
---
### `oidc_providers`

List of OpenID Connect (OIDC) / OAuth 2.0 identity providers, for registration
and login. See [here](../../openid.md)
for information on how to configure these options.

For backwards compatibility, it is also possible to configure a single OIDC
provider via an `oidc_config` setting. This is now deprecated and admins are
advised to migrate to the `oidc_providers` format. (When doing that migration,
use `oidc` for the `idp_id` to ensure that existing users continue to be
recognised.)

Options for each entry include:
* `idp_id`: a unique identifier for this identity provider. Used internally
   by Synapse; should be a single word such as 'github'.
   Note that, if this is changed, users authenticating via that provider
   will no longer be recognised as the same user!
   (Use "oidc" here if you are migrating from an old `oidc_config` configuration.)

* `idp_name`: A user-facing name for this identity provider, which is used to
   offer the user a choice of login mechanisms.

* `idp_icon`: An optional icon for this identity provider, which is presented
   by clients and Synapse's own IdP picker page. If given, must be an
   MXC URI of the format `mxc://<server-name>/<media-id>`. (An easy way to
   obtain such an MXC URI is to upload an image to an (unencrypted) room
   and then copy the "url" from the source of the event.)

* `idp_brand`: An optional brand for this identity provider, allowing clients
   to style the login flow according to the identity provider in question.
   See the [spec](https://spec.matrix.org/latest/) for possible options here.

* `discover`: set to false to disable the use of the OIDC discovery mechanism
  to discover endpoints. Defaults to true.

* `issuer`: Required. The OIDC issuer. Used to validate tokens and (if discovery
   is enabled) to discover the provider's endpoints.

* `client_id`: Required. oauth2 client id to use.

* `client_secret`: oauth2 client secret to use. May be omitted if
  `client_secret_jwt_key` is given, or if `client_auth_method` is 'none'.
  Must be omitted if `client_secret_path` is specified.

* `client_secret_path`: path to the oauth2 client secret to use. With that
   it's not necessary to leak secrets into the config file itself.
   Mutually exclusive with `client_secret`. Can be omitted if
   `client_secret_jwt_key` is specified.

   *Added in Synapse 1.91.0.*

* `client_secret_jwt_key`: Alternative to client_secret: details of a key used
   to create a JSON Web Token to be used as an OAuth2 client secret. If
   given, must be a dictionary with the following properties:

  * `key`: a pem-encoded signing key. Must be a suitable key for the
    algorithm specified. Required unless `key_file` is given.

  * `key_file`: the path to file containing a pem-encoded signing key file.
     Required unless `key` is given.

  * `jwt_header`: a dictionary giving properties to include in the JWT
     header. Must include the key `alg`, giving the algorithm used to
     sign the JWT, such as "ES256", using the JWA identifiers in
     RFC7518.

  * `jwt_payload`: an optional dictionary giving properties to include in
    the JWT payload. Normally this should include an `iss` key.

* `client_auth_method`: auth method to use when exchanging the token. Valid
   values are `client_secret_basic` (default), `client_secret_post` and
   `none`.

* `pkce_method`: Whether to use proof key for code exchange when requesting
   and exchanging the token. Valid values are: `auto`, `always`, or `never`. Defaults
   to `auto`, which uses PKCE if supported during metadata discovery. Set to `always`
   to force enable PKCE or `never` to force disable PKCE.

* `scopes`: list of scopes to request. This should normally include the "openid"
   scope. Defaults to `["openid"]`.

* `authorization_endpoint`: the oauth2 authorization endpoint. Required if
   provider discovery is disabled.

* `token_endpoint`: the oauth2 token endpoint. Required if provider discovery is
   disabled.

* `userinfo_endpoint`: the OIDC userinfo endpoint. Required if discovery is
   disabled and the 'openid' scope is not requested.

* `jwks_uri`: URI where to fetch the JWKS. Required if discovery is disabled and
   the 'openid' scope is used.

* `skip_verification`: set to 'true' to skip metadata verification. Use this if
   you are connecting to a provider that is not OpenID Connect compliant.
   Defaults to false. Avoid this in production.

* `user_profile_method`: Whether to fetch the user profile from the userinfo
   endpoint, or to rely on the data returned in the id_token from the `token_endpoint`.
   Valid values are: `auto` or `userinfo_endpoint`.
   Defaults to `auto`, which uses the userinfo endpoint if `openid` is
   not included in `scopes`. Set to `userinfo_endpoint` to always use the
   userinfo endpoint.

* `allow_existing_users`: set to true to allow a user logging in via OIDC to
   match a pre-existing account instead of failing. This could be used if
   switching from password logins to OIDC. Defaults to false.

* `enable_registration`: set to 'false' to disable automatic registration of new
   users. This allows the OIDC SSO flow to be limited to sign in only, rather than
   automatically registering users that have a valid SSO login but do not have
   a pre-registered account. Defaults to true.

* `user_mapping_provider`: Configuration for how attributes returned from a OIDC
   provider are mapped onto a matrix user. This setting has the following
   sub-properties:

     * `module`: The class name of a custom mapping module. Default is
       `synapse.handlers.oidc.JinjaOidcMappingProvider`.
        See [OpenID Mapping Providers](../../sso_mapping_providers.md#openid-mapping-providers)
        for information on implementing a custom mapping provider.

     * `config`: Configuration for the mapping provider module. This section will
        be passed as a Python dictionary to the user mapping provider
        module's `parse_config` method.

        For the default provider, the following settings are available:

       * `subject_template`: Jinja2 template for a unique identifier for the user.
         Defaults to `{{ user.sub }}`, which OpenID Connect compliant providers should provide.

         This replaces and overrides `subject_claim`.

       * `subject_claim`: name of the claim containing a unique identifier
         for the user. Defaults to 'sub', which OpenID Connect
         compliant providers should provide.

         *Deprecated in Synapse v1.75.0.*

       * `picture_template`: Jinja2 template for an url for the user's profile picture.
         Defaults to `{{ user.picture }}`, which OpenID Connect compliant providers should
         provide and has to refer to a direct image file such as PNG, JPEG, or GIF image file.

         This replaces and overrides `picture_claim`.

         Currently only supported in monolithic (single-process) server configurations
         where the media repository runs within the Synapse process.

       * `picture_claim`: name of the claim containing an url for the user's profile picture.
         Defaults to 'picture', which OpenID Connect compliant providers should provide
         and has to refer to a direct image file such as PNG, JPEG, or GIF image file.

         Currently only supported in monolithic (single-process) server configurations
         where the media repository runs within the Synapse process.

         *Deprecated in Synapse v1.75.0.*

       * `localpart_template`: Jinja2 template for the localpart of the MXID.
          If this is not set, the user will be prompted to choose their
          own username (see the documentation for the `sso_auth_account_details.html`
          template). This template can use the `localpart_from_email` filter.

       * `confirm_localpart`: Whether to prompt the user to validate (or
          change) the generated localpart (see the documentation for the
          'sso_auth_account_details.html' template), instead of
          registering the account right away.

       * `display_name_template`: Jinja2 template for the display name to set
          on first login. If unset, no displayname will be set.

       * `email_template`: Jinja2 template for the email address of the user.
          If unset, no email address will be added to the account.

       * `extra_attributes`: a map of Jinja2 templates for extra attributes
          to send back to the client during login. Note that these are non-standard and clients will ignore them
          without modifications.

     When rendering, the Jinja2 templates are given a 'user' variable,
     which is set to the claims returned by the UserInfo Endpoint and/or
     in the ID Token.

* `backchannel_logout_enabled`: set to `true` to process OIDC Back-Channel Logout notifications.
  Those notifications are expected to be received on `/_synapse/client/oidc/backchannel_logout`.
  Defaults to `false`.

* `backchannel_logout_ignore_sub`: by default, the OIDC Back-Channel Logout feature checks that the
  `sub` claim matches the subject claim received during login. This check can be disabled by setting
  this to `true`. Defaults to `false`.

  You might want to disable this if the `subject_claim` returned by the mapping provider is not `sub`.

It is possible to configure Synapse to only allow logins if certain attributes
match particular values in the OIDC userinfo. The requirements can be listed under
`attribute_requirements` as shown here:
```yaml
attribute_requirements:
     - attribute: family_name
       value: "Stephensson"
     - attribute: groups
       value: "admin"
```
All of the listed attributes must match for the login to be permitted. Additional attributes can be added to
userinfo by expanding the `scopes` section of the OIDC config to retrieve
additional information from the OIDC provider.

If the OIDC claim is a list, then the attribute must match any value in the list.
Otherwise, it must exactly match the value of the claim. Using the example
above, the `family_name` claim MUST be "Stephensson", but the `groups`
claim MUST contain "admin".

Example configuration:
```yaml
oidc_providers:
  # Generic example
  #
  - idp_id: my_idp
    idp_name: "My OpenID provider"
    idp_icon: "mxc://example.com/mediaid"
    discover: false
    issuer: "https://accounts.example.com/"
    client_id: "provided-by-your-issuer"
    client_secret: "provided-by-your-issuer"
    client_auth_method: client_secret_post
    scopes: ["openid", "profile"]
    authorization_endpoint: "https://accounts.example.com/oauth2/auth"
    token_endpoint: "https://accounts.example.com/oauth2/token"
    userinfo_endpoint: "https://accounts.example.com/userinfo"
    jwks_uri: "https://accounts.example.com/.well-known/jwks.json"
    skip_verification: true
    enable_registration: true
    user_mapping_provider:
      config:
        subject_claim: "id"
        localpart_template: "{{ user.login }}"
        display_name_template: "{{ user.name }}"
        email_template: "{{ user.email }}"
    attribute_requirements:
      - attribute: userGroup
        value: "synapseUsers"
```
---
### `cas_config`

Enable Central Authentication Service (CAS) for registration and login.
Has the following sub-options:
* `enabled`: Set this to true to enable authorization against a CAS server.
   Defaults to false.
* `idp_name`: A user-facing name for this identity provider, which is used to
   offer the user a choice of login mechanisms.
* `idp_icon`: An optional icon for this identity provider, which is presented
   by clients and Synapse's own IdP picker page. If given, must be an
   MXC URI of the format `mxc://<server-name>/<media-id>`. (An easy way to
   obtain such an MXC URI is to upload an image to an (unencrypted) room
   and then copy the "url" from the source of the event.)
* `idp_brand`: An optional brand for this identity provider, allowing clients
   to style the login flow according to the identity provider in question.
   See the [spec](https://spec.matrix.org/latest/) for possible options here.
* `server_url`: The URL of the CAS authorization endpoint.
* `protocol_version`: The CAS protocol version, defaults to none (version 3 is required if you want to use "required_attributes").
* `displayname_attribute`: The attribute of the CAS response to use as the display name.
   If no name is given here, no displayname will be set.
* `required_attributes`:  It is possible to configure Synapse to only allow logins if CAS attributes
   match particular values. All of the keys given below must exist
   and the values must match the given value. Alternately if the given value
   is `None` then any value is allowed (the attribute just must exist).
   All of the listed attributes must match for the login to be permitted.
* `enable_registration`: set to 'false' to disable automatic registration of new
   users. This allows the CAS SSO flow to be limited to sign in only, rather than
   automatically registering users that have a valid SSO login but do not have
   a pre-registered account. Defaults to true.

   *Added in Synapse 1.93.0.*

Example configuration:
```yaml
cas_config:
  enabled: true
  server_url: "https://cas-server.com"
  protocol_version: 3
  displayname_attribute: name
  required_attributes:
    userGroup: "staff"
    department: None
  enable_registration: true
```
---
### `sso`

Additional settings to use with single-sign on systems such as OpenID Connect,
SAML2 and CAS.

Server admins can configure custom templates for pages related to SSO. See
[here](../../templates.md) for more information.

Options include:
* `client_whitelist`: A list of client URLs which are whitelisted so that the user does not
   have to confirm giving access to their account to the URL. Any client
   whose URL starts with an entry in the following list will not be subject
   to an additional confirmation step after the SSO login is completed.
   WARNING: An entry such as "https://my.client" is insecure, because it
   will also match "https://my.client.evil.site", exposing your users to
   phishing attacks from evil.site. To avoid this, include a slash after the
   hostname: "https://my.client/".
   The login fallback page (used by clients that don't natively support the
   required login flows) is whitelisted in addition to any URLs in this list.
   By default, this list contains only the login fallback page.
* `update_profile_information`: Use this setting to keep a user's profile fields in sync with information from
   the identity provider. Currently only syncing the displayname is supported. Fields
   are checked on every SSO login, and are updated if necessary.
   Note that enabling this option will override user profile information,
   regardless of whether users have opted-out of syncing that
   information when first signing in. Defaults to false.


Example configuration:
```yaml
sso:
    client_whitelist:
      - https://riot.im/develop
      - https://my.custom.client/
    update_profile_information: true
```
---
### `jwt_config`

JSON web token integration. The following settings can be used to make
Synapse JSON web tokens for authentication, instead of its internal
password database.

Each JSON Web Token needs to contain a "sub" (subject) claim, which is
used as the localpart of the mxid.

Additionally, the expiration time ("exp"), not before time ("nbf"),
and issued at ("iat") claims are validated if present.

Note that this is a non-standard login type and client support is
expected to be non-existent.

See [here](../../jwt.md) for more.

Additional sub-options for this setting include:
* `enabled`: Set to true to enable authorization using JSON web
   tokens. Defaults to false.
* `secret`: This is either the private shared secret or the public key used to
   decode the contents of the JSON web token. Required if `enabled` is set to true.
* `algorithm`: The algorithm used to sign (or HMAC) the JSON web token.
   Supported algorithms are listed
   [here (section JWS)](https://docs.authlib.org/en/latest/specs/rfc7518.html).
   Required if `enabled` is set to true.
* `subject_claim`: Name of the claim containing a unique identifier for the user.
   Optional, defaults to `sub`.
* `issuer`: The issuer to validate the "iss" claim against. Optional. If provided the
   "iss" claim will be required and validated for all JSON web tokens.
* `audiences`: A list of audiences to validate the "aud" claim against. Optional.
   If provided the "aud" claim will be required and validated for all JSON web tokens.
   Note that if the "aud" claim is included in a JSON web token then
   validation will fail without configuring audiences.

Example configuration:
```yaml
jwt_config:
    enabled: true
    secret: "provided-by-your-issuer"
    algorithm: "provided-by-your-issuer"
    subject_claim: "name_of_claim"
    issuer: "provided-by-your-issuer"
    audiences:
        - "provided-by-your-issuer"
```
---
### `password_config`

Use this setting to enable password-based logins.

This setting has the following sub-options:
* `enabled`: Defaults to true.
   Set to false to disable password authentication.
   Set to `only_for_reauth` to allow users with existing passwords to use them
   to log in and reauthenticate, whilst preventing new users from setting passwords.
* `localdb_enabled`: Set to false to disable authentication against the local password
   database. This is ignored if `enabled` is false, and is only useful
   if you have other `password_providers`. Defaults to true.
* `pepper`: Set the value here to a secret random string for extra security.
   DO NOT CHANGE THIS AFTER INITIAL SETUP!
* `policy`: Define and enforce a password policy, such as minimum lengths for passwords, etc.
   Each parameter is optional. This is an implementation of MSC2000. Parameters are as follows:
   * `enabled`: Defaults to false. Set to true to enable.
   * `minimum_length`: Minimum accepted length for a password. Defaults to 0.
   * `require_digit`: Whether a password must contain at least one digit.
      Defaults to false.
   * `require_symbol`: Whether a password must contain at least one symbol.
      A symbol is any character that's not a number or a letter. Defaults to false.
   * `require_lowercase`: Whether a password must contain at least one lowercase letter.
      Defaults to false.
   * `require_uppercase`: Whether a password must contain at least one uppercase letter.
      Defaults to false.


Example configuration:
```yaml
password_config:
   enabled: false
   localdb_enabled: false
   pepper: "EVEN_MORE_SECRET"

   policy:
      enabled: true
      minimum_length: 15
      require_digit: true
      require_symbol: true
      require_lowercase: true
      require_uppercase: true
```
---
## Push
Configuration settings related to push notifications

---
### `push`

This setting defines options for push notifications.

This option has a number of sub-options. They are as follows:
* `enabled`: Enables or disables push notification calculation. Note, disabling this will also
   stop unread counts being calculated for rooms. This mode of operation is intended
   for homeservers which may only have bots or appservice users connected, or are otherwise
   not interested in push/unread counters. This is enabled by default.
* `include_content`: Clients requesting push notifications can either have the body of
   the message sent in the notification poke along with other details
   like the sender, or just the event ID and room ID (`event_id_only`).
   If clients choose the to have the body sent, this option controls whether the
   notification request includes the content of the event (other details
   like the sender are still included). If `event_id_only` is enabled, it
   has no effect.
   For modern android devices the notification content will still appear
   because it is loaded by the app. iPhone, however will send a
   notification saying only that a message arrived and who it came from.
   Defaults to true. Set to false to only include the event ID and room ID in push notification payloads.
* `group_unread_count_by_room: false`: When a push notification is received, an unread count is also sent.
   This number can either be calculated as the number of unread messages  for the user, or the number of *rooms* the
   user has unread messages in. Defaults to true, meaning push clients will see the number of
   rooms with unread messages in them. Set to false to instead send the number
   of unread messages.
* `jitter_delay`: Delays push notifications by a random amount up to the given
  duration. Useful for mitigating timing attacks. Optional, defaults to no
  delay. _Added in Synapse 1.84.0._

Example configuration:
```yaml
push:
  enabled: true
  include_content: false
  group_unread_count_by_room: false
  jitter_delay: "10s"
```
---
## Rooms
Config options relating to rooms.

---
### `encryption_enabled_by_default_for_room_type`

Controls whether locally-created rooms should be end-to-end encrypted by
default.

Possible options are "all", "invite", and "off". They are defined as:

* "all": any locally-created room
* "invite": any room created with the `private_chat` or `trusted_private_chat`
   room creation presets
* "off": this option will take no effect

The default value is "off".

Note that this option will only affect rooms created after it is set. It
will also not affect rooms created by other servers.

Example configuration:
```yaml
encryption_enabled_by_default_for_room_type: invite
```
---
### `user_directory`

This setting defines options related to the user directory.

This option has the following sub-options:
* `enabled`:  Defines whether users can search the user directory. If false then
   empty responses are returned to all queries. Defaults to true.
* `search_all_users`: Defines whether to search all users visible to your HS at the time the search is performed. If set to true, will return all users who share a room with the user from the homeserver.
   If false, search results will only contain users
    visible in public rooms and users sharing a room with the requester.
    Defaults to false.

    NB. If you set this to true, and the last time the user_directory search
    indexes were (re)built was before Synapse 1.44, you'll have to
    rebuild the indexes in order to search through all known users.

    These indexes are built the first time Synapse starts; admins can
    manually trigger a rebuild via the API following the instructions
    [for running background updates](../administration/admin_api/background_updates.md#run),
    set to true to return search results containing all known users, even if that
    user does not share a room with the requester.
* `prefer_local_users`: Defines whether to prefer local users in search query results.
   If set to true, local users are more likely to appear above remote users when searching the
   user directory. Defaults to false.
* `show_locked_users`: Defines whether to show locked users in search query results. Defaults to false.

Example configuration:
```yaml
user_directory:
    enabled: false
    search_all_users: true
    prefer_local_users: true
    show_locked_users: true
```
---
### `user_consent`

For detailed instructions on user consent configuration, see [here](../../consent_tracking.md).

Parts of this section are required if enabling the `consent` resource under
[`listeners`](#listeners), in particular `template_dir` and `version`.

* `template_dir`: gives the location of the templates for the HTML forms.
  This directory should contain one subdirectory per language (eg, `en`, `fr`),
  and each language directory should contain the policy document (named as
  <version>.html) and a success page (success.html).

* `version`: specifies the 'current' version of the policy document. It defines
   the version to be served by the consent resource if there is no 'v'
   parameter.

* `server_notice_content`: if enabled, will send a user a "Server Notice"
   asking them to consent to the privacy policy. The [`server_notices` section](#server_notices)
   must also be configured for this to work. Notices will *not* be sent to
   guest users unless `send_server_notice_to_guests` is set to true.

* `block_events_error`, if set, will block any attempts to send events
   until the user consents to the privacy policy. The value of the setting is
   used as the text of the error.

* `require_at_registration`, if enabled, will add a step to the registration
   process, similar to how captcha works. Users will be required to accept the
   policy before their account is created.

* `policy_name` is the display name of the policy users will see when registering
   for an account. Has no effect unless `require_at_registration` is enabled.
   Defaults to "Privacy Policy".

Example configuration:
```yaml
user_consent:
  template_dir: res/templates/privacy
  version: 1.0
  server_notice_content:
    msgtype: m.text
    body: >-
      To continue using this homeserver you must review and agree to the
      terms and conditions at %(consent_uri)s
  send_server_notice_to_guests: true
  block_events_error: >-
    To continue using this homeserver you must review and agree to the
    terms and conditions at %(consent_uri)s
  require_at_registration: false
  policy_name: Privacy Policy
```
---
### `stats`

Settings for local room and user statistics collection. See [here](../../room_and_user_statistics.md)
for more.

* `enabled`: Set to false to disable room and user statistics. Note that doing
   so may cause certain features (such as the room directory) not to work
   correctly. Defaults to true.

Example configuration:
```yaml
stats:
  enabled: false
```
---
### `server_notices`

Use this setting to enable a room which can be used to send notices
from the server to users. It is a special room which users cannot leave; notices
in the room come from a special "notices" user id.

If you use this setting, you *must* define the `system_mxid_localpart`
sub-setting, which defines the id of the user which will be used to send the
notices.

Sub-options for this setting include:
* `system_mxid_display_name`: set the display name of the "notices" user
* `system_mxid_avatar_url`: set the avatar for the "notices" user
* `room_name`: set the room name of the server notices room
* `auto_join`: boolean. If true, the user will be automatically joined to the room instead of being invited.
  Defaults to false. _Added in Synapse 1.98.0._

Example configuration:
```yaml
server_notices:
  system_mxid_localpart: notices
  system_mxid_display_name: "Server Notices"
  system_mxid_avatar_url: "mxc://server.com/oumMVlgDnLYFaPVkExemNVVZ"
  room_name: "Server Notices"
  auto_join: true
```
---
### `enable_room_list_search`

Set to false to disable searching the public room list. When disabled
blocks searching local and remote room lists for local and remote
users by always returning an empty list for all queries. Defaults to true.

Example configuration:
```yaml
enable_room_list_search: false
```
---
### `alias_creation_rules`

The `alias_creation_rules` option allows server admins to prevent unwanted
alias creation on this server.

This setting is an optional list of 0 or more rules. By default, no list is
provided, meaning that all alias creations are permitted.

Otherwise, requests to create aliases are matched against each rule in order.
The first rule that matches decides if the request is allowed or denied. If no 
rule matches, the request is denied. In particular, this means that configuring
an empty list of rules will deny every alias creation request.

Each rule is a YAML object containing four fields, each of which is an optional string:

* `user_id`: a glob pattern that matches against the creator of the alias.
* `alias`: a glob pattern that matches against the alias being created.
* `room_id`: a glob pattern that matches against the room ID the alias is being pointed at.
* `action`: either `allow` or `deny`. What to do with the request if the rule matches. Defaults to `allow`.

Each of the glob patterns is optional, defaulting to `*` ("match anything").
Note that the patterns match against fully qualified IDs, e.g. against 
`@alice:example.com`, `#room:example.com` and `!abcdefghijk:example.com` instead
of `alice`, `room` and `abcedgghijk`.

Example configuration:

```yaml
# No rule list specified. All alias creations are allowed.
# This is the default behaviour.
alias_creation_rules:
```

```yaml
# A list of one rule which allows everything.
# This has the same effect as the previous example.
alias_creation_rules:
  - "action": "allow"
```

```yaml
# An empty list of rules. All alias creations are denied.
alias_creation_rules: []
```

```yaml
# A list of one rule which denies everything.
# This has the same effect as the previous example.
alias_creation_rules:
  - "action": "deny"
```

```yaml
# Prevent a specific user from creating aliases.
# Allow other users to create any alias
alias_creation_rules:
  - user_id: "@bad_user:example.com"
    action: deny
    
  - action: allow
```

```yaml
# Prevent aliases being created which point to a specific room.
alias_creation_rules:
  - room_id: "!forbiddenRoom:example.com"
    action: deny

  - action: allow
```

---
### `room_list_publication_rules`

The `room_list_publication_rules` option allows server admins to prevent
unwanted entries from being published in the public room list.

The format of this option is the same as that for
[`alias_creation_rules`](#alias_creation_rules): an optional list of 0 or more
rules. By default, no list is provided, meaning that all rooms may be
published to the room list.

Otherwise, requests to publish a room are matched against each rule in order.
The first rule that matches decides if the request is allowed or denied. If no
rule matches, the request is denied. In particular, this means that configuring
an empty list of rules will deny every alias creation request.

Each rule is a YAML object containing four fields, each of which is an optional string:

* `user_id`: a glob pattern that matches against the user publishing the room.
* `alias`: a glob pattern that matches against one of published room's aliases.
  - If the room has no aliases, the alias match fails unless `alias` is unspecified or `*`.
  - If the room has exactly one alias, the alias match succeeds if the `alias` pattern matches that alias.
  - If the room has two or more aliases, the alias match succeeds if the pattern matches at least one of the aliases.
* `room_id`: a glob pattern that matches against the room ID of the room being published.
* `action`: either `allow` or `deny`. What to do with the request if the rule matches. Defaults to `allow`.

Each of the glob patterns is optional, defaulting to `*` ("match anything").
Note that the patterns match against fully qualified IDs, e.g. against
`@alice:example.com`, `#room:example.com` and `!abcdefghijk:example.com` instead
of `alice`, `room` and `abcedgghijk`.


Example configuration:

```yaml
# No rule list specified. Anyone may publish any room to the public list.
# This is the default behaviour.
room_list_publication_rules:
```

```yaml
# A list of one rule which allows everything.
# This has the same effect as the previous example.
room_list_publication_rules:
  - "action": "allow"
```

```yaml
# An empty list of rules. No-one may publish to the room list.
room_list_publication_rules: []
```

```yaml
# A list of one rule which denies everything.
# This has the same effect as the previous example.
room_list_publication_rules:
  - "action": "deny"
```

```yaml
# Prevent a specific user from publishing rooms.
# Allow other users to publish anything.
room_list_publication_rules:
  - user_id: "@bad_user:example.com"
    action: deny
    
  - action: allow
```

```yaml
# Prevent publication of a specific room.
room_list_publication_rules:
  - room_id: "!forbiddenRoom:example.com"
    action: deny

  - action: allow
```

```yaml
# Prevent publication of rooms with at least one alias containing the word "potato".
room_list_publication_rules:
  - alias: "#*potato*:example.com"
    action: deny

  - action: allow
```

---
### `default_power_level_content_override`

The `default_power_level_content_override` option controls the default power
levels for rooms.

Useful if you know that your users need special permissions in rooms
that they create (e.g. to send particular types of state events without
needing an elevated power level).  This takes the same shape as the
`power_level_content_override` parameter in the /createRoom API, but
is applied before that parameter.

Note that each key provided inside a preset (for example `events` in the example
below) will overwrite all existing defaults inside that key. So in the example
below, newly-created private_chat rooms will have no rules for any event types
except `com.example.foo`.

Example configuration:
```yaml
default_power_level_content_override:
   private_chat: { "events": { "com.example.foo" : 0 } }
   trusted_private_chat: null
   public_chat: null
```
---
### `forget_rooms_on_leave`

Set to true to automatically forget rooms for users when they leave them, either
normally or via a kick or ban. Defaults to false.

Example configuration:
```yaml
forget_rooms_on_leave: false
```
---
### `exclude_rooms_from_sync`
A list of rooms to exclude from sync responses. This is useful for server
administrators wishing to group users into a room without these users being able
to see it from their client.

By default, no room is excluded.

Example configuration:
```yaml
exclude_rooms_from_sync:
    - !foo:example.com
```

---
## Opentracing
Configuration options related to Opentracing support.

---
### `opentracing`

These settings enable and configure opentracing, which implements distributed tracing.
This allows you to observe the causal chains of events across servers
including requests, key lookups etc., across any server running
synapse or any other services which support opentracing
(specifically those implemented with Jaeger).

Sub-options include:
* `enabled`: whether tracing is enabled. Set to true to enable. Disabled by default.
* `homeserver_whitelist`: The list of homeservers we wish to send and receive span contexts and span baggage.
   See [here](../../opentracing.md) for more.
   This is a list of regexes which are matched against the `server_name` of the homeserver.
   By default, it is empty, so no servers are matched.
* `force_tracing_for_users`: # A list of the matrix IDs of users whose requests will always be traced,
   even if the tracing system would otherwise drop the traces due to probabilistic sampling.
    By default, the list is empty.
* `jaeger_config`: Jaeger can be configured to sample traces at different rates.
   All configuration options provided by Jaeger can be set here. Jaeger's configuration is
   mostly related to trace sampling which is documented [here](https://www.jaegertracing.io/docs/latest/sampling/).

Example configuration:
```yaml
opentracing:
    enabled: true
    homeserver_whitelist:
      - ".*"
    force_tracing_for_users:
      - "@user1:server_name"
      - "@user2:server_name"

    jaeger_config:
      sampler:
        type: const
        param: 1
      logging:
        false
```
---
## Coordinating workers
Configuration options related to workers which belong in the main config file
(usually called `homeserver.yaml`).
A Synapse deployment can scale horizontally by running multiple Synapse processes
called _workers_. Incoming requests are distributed between workers to handle higher
loads. Some workers are privileged and can accept requests from other workers.

As a result, the worker configuration is divided into two parts.

1. The first part (in this section of the manual) defines which shardable tasks
   are delegated to privileged workers. This allows unprivileged workers to make
   requests to a privileged worker to act on their behalf.
1. [The second part](#individual-worker-configuration)
   controls the behaviour of individual workers in isolation.

For guidance on setting up workers, see the [worker documentation](../../workers.md).

---
### `worker_replication_secret`

A shared secret used by the replication APIs on the main process to authenticate
HTTP requests from workers.

The default, this value is omitted (equivalently `null`), which means that
traffic between the workers and the main process is not authenticated.

Example configuration:
```yaml
worker_replication_secret: "secret_secret"
```
---
### `start_pushers`

Unnecessary to set if using [`pusher_instances`](#pusher_instances) with [`generic_workers`](../../workers.md#synapseappgeneric_worker).

Controls sending of push notifications on the main process. Set to `false`
if using a [pusher worker](../../workers.md#synapseapppusher). Defaults to `true`.

Example configuration:
```yaml
start_pushers: false
```
---
### `pusher_instances`

It is possible to scale the processes that handle sending push notifications to [sygnal](https://github.com/matrix-org/sygnal)
and email by running a [`generic_worker`](../../workers.md#synapseappgeneric_worker) and adding it's [`worker_name`](#worker_name) to
a `pusher_instances` map. Doing so will remove handling of this function from the main
process. Multiple workers can be added to this map, in which case the work is balanced
across them. Ensure the main process and all pusher workers are restarted after changing
this option.

Example configuration for a single worker:
```yaml
pusher_instances:
  - pusher_worker1
```
And for multiple workers:
```yaml
pusher_instances:
  - pusher_worker1
  - pusher_worker2
```

---
### `send_federation`

Unnecessary to set if using [`federation_sender_instances`](#federation_sender_instances) with [`generic_workers`](../../workers.md#synapseappgeneric_worker).

Controls sending of outbound federation transactions on the main process.
Set to `false` if using a [federation sender worker](../../workers.md#synapseappfederation_sender).
Defaults to `true`.

Example configuration:
```yaml
send_federation: false
```
---
### `federation_sender_instances`

It is possible to scale the processes that handle sending outbound federation requests
by running a [`generic_worker`](../../workers.md#synapseappgeneric_worker) and adding it's [`worker_name`](#worker_name) to
a `federation_sender_instances` map. Doing so will remove handling of this function from
the main process. Multiple workers can be added to this map, in which case the work is
balanced across them.

This configuration setting must be shared between all workers handling federation
sending, and if changed all federation sender workers must be stopped at the same time
and then started, to ensure that all instances are running with the same config (otherwise
events may be dropped).

Example configuration for a single worker:
```yaml
federation_sender_instances:
  - federation_sender1
```
And for multiple workers:
```yaml
federation_sender_instances:
  - federation_sender1
  - federation_sender2
```
---
### `instance_map`

When using workers this should be a map from [`worker_name`](#worker_name) to the HTTP
replication listener of the worker, if configured, and to the main process. Each worker
declared under [`stream_writers`](../../workers.md#stream-writers) and
[`outbound_federation_restricted_to`](#outbound_federation_restricted_to) needs a HTTP
replication listener, and that listener should be included in the `instance_map`. The
main process also needs an entry on the `instance_map`, and it should be listed under
`main` **if even one other worker exists**. Ensure the port matches with what is
declared inside the `listener` block for a `replication` listener.


Example configuration:
```yaml
instance_map:
  main:
    host: localhost
    port: 8030
  worker1:
    host: localhost
    port: 8034
```
Example configuration(#2, for UNIX sockets):
```yaml
instance_map:
  main:
    path: /run/synapse/main_replication.sock
  worker1:
    path: /run/synapse/worker1_replication.sock
```
---
### `stream_writers`

Experimental: When using workers you can define which workers should
handle writing to streams such as event persistence and typing notifications.
Any worker specified here must also be in the [`instance_map`](#instance_map).

See the list of available streams in the
[worker documentation](../../workers.md#stream-writers).

Example configuration:
```yaml
stream_writers:
  events: worker1
  typing: worker1
```
---
### `outbound_federation_restricted_to`

When using workers, you can restrict outbound federation traffic to only go through a
specific subset of workers. Any worker specified here must also be in the
[`instance_map`](#instance_map).
[`worker_replication_secret`](#worker_replication_secret) must also be configured to
authorize inter-worker communication.

```yaml
outbound_federation_restricted_to:
  - federation_sender1
  - federation_sender2
```

Also see the [worker
documentation](../../workers.md#restrict-outbound-federation-traffic-to-a-specific-set-of-workers)
for more info.

_Added in Synapse 1.89.0._

---
### `run_background_tasks_on`

The [worker](../../workers.md#background-tasks) that is used to run
background tasks (e.g. cleaning up expired data). If not provided this
defaults to the main process.

Example configuration:
```yaml
run_background_tasks_on: worker1
```
---
### `update_user_directory_from_worker`

The [worker](../../workers.md#updating-the-user-directory) that is used to
update the user directory. If not provided this defaults to the main process.

Example configuration:
```yaml
update_user_directory_from_worker: worker1
```

_Added in Synapse 1.59.0._

---
### `notify_appservices_from_worker`

The [worker](../../workers.md#notifying-application-services) that is used to
send output traffic to Application Services. If not provided this defaults
to the main process.

Example configuration:
```yaml
notify_appservices_from_worker: worker1
```

_Added in Synapse 1.59.0._

---
### `media_instance_running_background_jobs`

The [worker](../../workers.md#synapseappmedia_repository) that is used to run
background tasks for media repository. If running multiple media repositories
you must configure a single instance to run the background tasks. If not provided
this defaults to the main process or your single `media_repository` worker.

Example configuration:
```yaml
media_instance_running_background_jobs: worker1
```

_Added in Synapse 1.16.0._

---
### `redis`

Configuration for Redis when using workers. This *must* be enabled when using workers.
This setting has the following sub-options:
* `enabled`: whether to use Redis support. Defaults to false.
* `host` and `port`: Optional host and port to use to connect to redis. Defaults to
   localhost and 6379
* `path`: The full path to a local Unix socket file. **If this is used, `host` and
 `port` are ignored.** Defaults to `/tmp/redis.sock'
* `password`: Optional password if configured on the Redis instance.
* `dbid`: Optional redis dbid if needs to connect to specific redis logical db.
* `use_tls`: Whether to use tls connection. Defaults to false.
* `certificate_file`: Optional path to the certificate file
* `private_key_file`: Optional path to the private key file
* `ca_file`: Optional path to the CA certificate file. Use this one or:
* `ca_path`: Optional path to the folder containing the CA certificate file

  _Added in Synapse 1.78.0._

  _Changed in Synapse 1.84.0: Added use\_tls, certificate\_file, private\_key\_file, ca\_file and ca\_path attributes_

  _Changed in Synapse 1.85.0: Added path option to use a local Unix socket_

Example configuration:
```yaml
redis:
  enabled: true
  host: localhost
  port: 6379
  password: <secret_password>
  dbid: <dbid>
  #use_tls: True
  #certificate_file: <path_to_the_certificate_file>
  #private_key_file: <path_to_the_private_key_file>
  #ca_file: <path_to_the_ca_certificate_file>
```
---
## Individual worker configuration
These options configure an individual worker, in its worker configuration file.
They should be not be provided when configuring the main process.

Note also the configuration above for
[coordinating a cluster of workers](#coordinating-workers).

For guidance on setting up workers, see the [worker documentation](../../workers.md).

---
### `worker_app`

The type of worker. The currently available worker applications are listed
in [worker documentation](../../workers.md#available-worker-applications).

The most common worker is the
[`synapse.app.generic_worker`](../../workers.md#synapseappgeneric_worker).

Example configuration:
```yaml
worker_app: synapse.app.generic_worker
```
---
### `worker_name`

A unique name for the worker. The worker needs a name to be addressed in
further parameters and identification in log files. We strongly recommend
giving each worker a unique `worker_name`.

Example configuration:
```yaml
worker_name: generic_worker1
```
---
### `worker_listeners`

A worker can handle HTTP requests. To do so, a `worker_listeners` option
must be declared, in the same way as the [`listeners` option](#listeners)
in the shared config.

Workers declared in [`stream_writers`](#stream_writers) and [`instance_map`](#instance_map)
 will need to include a `replication` listener here, in order to accept internal HTTP 
requests from other workers.

Example configuration:
```yaml
worker_listeners:
  - type: http
    port: 8083
    resources:
      - names: [client, federation]
```
Example configuration(#2, using UNIX sockets with a `replication` listener):
```yaml
worker_listeners:
  - type: http
    path: /run/synapse/worker_replication.sock
    resources:
      - names: [replication]
  - type: http
    path: /run/synapse/worker_public.sock
    resources:
      - names: [client, federation]
```
---
### `worker_manhole`

A worker may have a listener for [`manhole`](../../manhole.md).
It allows server administrators to access a Python shell on the worker.

Example configuration:
```yaml
worker_manhole: 9000
```

This is a short form for:
```yaml
worker_listeners:
  - port: 9000
    bind_addresses: ['127.0.0.1']
    type: manhole
```

It needs also an additional [`manhole_settings`](#manhole_settings) configuration.

---
### `worker_daemonize`

Specifies whether the worker should be started as a daemon process.
If Synapse is being managed by [systemd](../../systemd-with-workers/), this option
must be omitted or set to `false`.

Defaults to `false`.

Example configuration:
```yaml
worker_daemonize: true
```
---
### `worker_pid_file`

When running a worker as a daemon, we need a place to store the
[PID](https://en.wikipedia.org/wiki/Process_identifier) of the worker.
This option defines the location of that "pid file".

This option is required if `worker_daemonize` is `true` and ignored
otherwise. It has no default.

See also the [`pid_file` option](#pid_file) option for the main Synapse process.

Example configuration:
```yaml
worker_pid_file: DATADIR/generic_worker1.pid
```
---
### `worker_log_config`

This option specifies a yaml python logging config file as described
[here](https://docs.python.org/3/library/logging.config.html#configuration-dictionary-schema).
See also the [`log_config` option](#log_config) option for the main Synapse process.

Example configuration:
```yaml
worker_log_config: /etc/matrix-synapse/generic-worker-log.yaml
```
---
## Background Updates
Configuration settings related to background updates.

---
### `background_updates`

Background updates are database updates that are run in the background in batches.
The duration, minimum batch size, default batch size, whether to sleep between batches and if so, how long to
sleep can all be configured. This is helpful to speed up or slow down the updates.
This setting has the following sub-options:
* `background_update_duration_ms`: How long in milliseconds to run a batch of background updates for. Defaults to 100.
   Set a different time to change the default.
* `sleep_enabled`: Whether to sleep between updates. Defaults to true. Set to false to change the default.
* `sleep_duration_ms`: If sleeping between updates, how long in milliseconds to sleep for. Defaults to 1000.
   Set a duration to change the default.
* `min_batch_size`: Minimum size a batch of background updates can be. Must be greater than 0. Defaults to 1.
   Set a size to change the default.
* `default_batch_size`: The batch size to use for the first iteration of a new background update. The default is 100.
   Set a size to change the default.

Example configuration:
```yaml
background_updates:
    background_update_duration_ms: 500
    sleep_enabled: false
    sleep_duration_ms: 300
    min_batch_size: 10
    default_batch_size: 50
```
