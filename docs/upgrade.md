# Upgrading Synapse

Before upgrading check if any special steps are required to upgrade from
the version you currently have installed to the current version of
Synapse. The extra instructions that may be required are listed later in
this document.

-   Check that your versions of Python and PostgreSQL are still
    supported.

    Synapse follows upstream lifecycles for [Python](https://endoflife.date/python) and
    [PostgreSQL](https://endoflife.date/postgresql), and removes support for versions
    which are no longer maintained.

    The website <https://endoflife.date> also offers convenient
    summaries.

-   If Synapse was installed using [prebuilt packages](setup/installation.md#prebuilt-packages),
    you will need to follow the normal process for upgrading those packages.

-   If Synapse was installed using pip then upgrade to the latest
    version by running:

    ```bash
    pip install --upgrade matrix-synapse
    ```

-   If Synapse was installed from source, then:

    1.  Obtain the latest version of the source code. Git users can run
        `git pull` to do this.

    2.  If you're running Synapse in a virtualenv, make sure to activate it before
        upgrading. For example, if Synapse is installed in a virtualenv in `~/synapse/env` then
        run:

        ```bash
        source ~/synapse/env/bin/activate
        pip install --upgrade .
        ```
        Include any relevant extras between square brackets, e.g. `pip install --upgrade ".[postgres,oidc]"`.

    3.  If you're using `poetry` to manage a Synapse installation, run:
        ```bash
        poetry install
        ```
        Include any relevant extras with `--extras`, e.g. `poetry install --extras postgres --extras oidc`.
        It's probably easiest to run `poetry install --extras all`.

    4.  Restart Synapse:

        ```bash
        synctl restart
        ```

To check whether your update was successful, you can check the running
server version with:

```bash
# you may need to replace 'localhost:8008' if synapse is not configured
# to listen on port 8008.

curl http://localhost:8008/_synapse/admin/v1/server_version
```

## Rolling back to older versions

Rolling back to previous releases can be difficult, due to database
schema changes between releases. Where we have been able to test the
rollback process, this will be noted below.

In general, you will need to undo any changes made during the upgrade
process, for example:

-   pip:

    ```bash
    source env/bin/activate
    # replace `1.3.0` accordingly:
    pip install matrix-synapse==1.3.0
    ```

-   Debian:

    ```bash
    # replace `1.3.0` and `stretch` accordingly:
    wget https://packages.matrix.org/debian/pool/main/m/matrix-synapse-py3/matrix-synapse-py3_1.3.0+stretch1_amd64.deb
    dpkg -i matrix-synapse-py3_1.3.0+stretch1_amd64.deb
    ```

Generally Synapse database schemas are compatible across multiple versions, once
a version of Synapse is deployed you may not be able to rollback automatically.
The following table gives the version ranges and the earliest version they can
be rolled back to. E.g. Synapse versions v1.58.0 through v1.61.1 can be rolled
back safely to v1.57.0, but starting with v1.62.0 it is only safe to rollback to
v1.61.0.

<!-- REPLACE_WITH_SCHEMA_VERSIONS -->

# Upgrading to v1.93.0

## Minimum supported Rust version
The minimum supported Rust version has been increased from v1.60.0 to v1.61.0.
Users building from source will need to ensure their `rustc` version is up to
date.


# Upgrading to v1.90.0

## App service query parameter authorization is now a configuration option

Synapse v1.81.0 deprecated application service authorization via query parameters as this is
considered insecure - and from Synapse v1.71.0 forwards the application service token has also been sent via 
[the `Authorization` header](https://spec.matrix.org/v1.6/application-service-api/#authorization)], making the insecure
query parameter authorization redundant. Since removing the ability to continue to use query parameters could break 
backwards compatibility it has now been put behind a configuration option, `use_appservice_legacy_authorization`.  
This option defaults to false, but can be activated by adding 
```yaml
use_appservice_legacy_authorization: true 
```
to your configuration.

# Upgrading to v1.89.0

## Removal of unspecced `user` property for `/register`

Application services can no longer call `/register` with a `user` property to create new users.
The standard `username` property should be used instead. See the
[Application Service specification](https://spec.matrix.org/v1.7/application-service-api/#server-admin-style-permissions)
for more information.

# Upgrading to v1.88.0

## Minimum supported Python version

The minimum supported Python version has been increased from v3.7 to v3.8.
You will need Python 3.8 to run Synapse v1.88.0 (due out July 18th, 2023).

If you use current versions of the Matrix.org-distributed Debian
packages or Docker images, no action is required.

## Removal of `worker_replication_*` settings

As mentioned previously in [Upgrading to v1.84.0](#upgrading-to-v1840), the following deprecated settings
are being removed in this release of Synapse:

* [`worker_replication_host`](https://matrix-org.github.io/synapse/v1.86/usage/configuration/config_documentation.html#worker_replication_host)
* [`worker_replication_http_port`](https://matrix-org.github.io/synapse/v1.86/usage/configuration/config_documentation.html#worker_replication_http_port)
* [`worker_replication_http_tls`](https://matrix-org.github.io/synapse/v1.86/usage/configuration/config_documentation.html#worker_replication_http_tls)

Please ensure that you have migrated to using `main` on your shared configuration's `instance_map`
(or create one if necessary). This is required if you have ***any*** workers at all;
administrators of single-process (monolith) installations don't need to do anything.

For an illustrative example, please see [Upgrading to v1.84.0](#upgrading-to-v1840) below.


# Upgrading to v1.86.0

## Minimum supported Rust version

The minimum supported Rust version has been increased from v1.58.1 to v1.60.0.
Users building from source will need to ensure their `rustc` version is up to
date.


# Upgrading to v1.85.0

## Application service registration with "user" property deprecation

Application services should ensure they call the `/register` endpoint with a
`username` property. The legacy `user` property is considered deprecated and
should no longer be included.

A future version of Synapse (v1.88.0 or later) will remove support for legacy
application service login.

# Upgrading to v1.84.0

## Deprecation of `worker_replication_*` configuration settings

When using workers,

* `worker_replication_host`
* `worker_replication_http_port`
* `worker_replication_http_tls`
 
should now be removed from individual worker YAML configurations and the main process should instead be added to the `instance_map`
in the shared YAML configuration, using the name `main`.

The old `worker_replication_*` settings are now considered deprecated and are expected to be removed in Synapse v1.88.0.


### Example change

#### Before:

Shared YAML
```yaml
instance_map:
  generic_worker1:
    host: localhost
    port: 5678
    tls: false
```

Worker YAML
```yaml
worker_app: synapse.app.generic_worker
worker_name: generic_worker1

worker_replication_host: localhost
worker_replication_http_port: 3456
worker_replication_http_tls: false

worker_listeners:
  - type: http
    port: 1234
    resources:
      - names: [client, federation]
  - type: http
    port: 5678
    resources:
      - names: [replication]

worker_log_config: /etc/matrix-synapse/generic-worker-log.yaml
```


#### After:

Shared YAML
```yaml
instance_map:
  main:
    host: localhost
    port: 3456
    tls: false
  generic_worker1:
    host: localhost
    port: 5678
    tls: false
```

Worker YAML
```yaml
worker_app: synapse.app.generic_worker
worker_name: generic_worker1

worker_listeners:
  - type: http
    port: 1234
    resources:
      - names: [client, federation]
  - type: http
    port: 5678
    resources:
      - names: [replication]

worker_log_config: /etc/matrix-synapse/generic-worker-log.yaml

```
Notes: 
* `tls` is optional but mirrors the functionality of `worker_replication_http_tls`


# Upgrading to v1.81.0

## Application service path & authentication deprecations

Synapse now attempts the versioned appservice paths before falling back to the
[legacy paths](https://spec.matrix.org/v1.6/application-service-api/#legacy-routes).
Usage of the legacy routes should be considered deprecated.

Additionally, Synapse has supported sending the application service access token
via [the `Authorization` header](https://spec.matrix.org/v1.6/application-service-api/#authorization)
since v1.70.0. For backwards compatibility it is *also* sent as the `access_token`
query parameter. This is insecure and should be considered deprecated.

A future version of Synapse (v1.88.0 or later) will remove support for legacy
application service routes and query parameter authorization.

# Upgrading to v1.80.0

## Reporting events error code change

Before this update, the
[`POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`](https://spec.matrix.org/v1.6/client-server-api/#post_matrixclientv3roomsroomidreporteventid)
endpoint would return a `403` if a user attempted to report an event that they did not have access to.
This endpoint will now return a `404` in this case instead.

Clients that implement event reporting should check that their error handling code will handle this
change.

# Upgrading to v1.79.0

## The `on_threepid_bind` module callback method has been deprecated

Synapse v1.79.0 deprecates the
[`on_threepid_bind`](modules/third_party_rules_callbacks.md#on_threepid_bind)
"third-party rules" Synapse module callback method in favour of a new module method,
[`on_add_user_third_party_identifier`](modules/third_party_rules_callbacks.md#on_add_user_third_party_identifier).
`on_threepid_bind` will be removed in a future version of Synapse. You should check whether any Synapse
modules in use in your deployment are making use of `on_threepid_bind`, and update them where possible.

The arguments and functionality of the new method are the same.

The justification behind the name change is that the old method's name, `on_threepid_bind`, was
misleading. A user is considered to "bind" their third-party ID to their Matrix ID only if they
do so via an [identity server](https://spec.matrix.org/latest/identity-service-api/)
(so that users on other homeservers may find them). But this method was not called in that case -
it was only called when a user added a third-party identifier on the local homeserver.

Module developers may also be interested in the related
[`on_remove_user_third_party_identifier`](modules/third_party_rules_callbacks.md#on_remove_user_third_party_identifier)
module callback method that was also added in Synapse v1.79.0. This new method is called when a
user removes a third-party identifier from their account.

# Upgrading to v1.78.0

## Deprecate the `/_synapse/admin/v1/media/<server_name>/delete` admin API

Synapse 1.78.0 replaces the `/_synapse/admin/v1/media/<server_name>/delete`
admin API with an identical endpoint at `/_synapse/admin/v1/media/delete`. Please
update your tooling to use the new endpoint. The deprecated version will be removed
in a future release.

# Upgrading to v1.76.0

## Faster joins are enabled by default

When joining a room for the first time, Synapse 1.76.0 will request a partial join from the other server by default. Previously, server admins had to opt-in to this using an experimental config flag.

Server admins can opt out of this feature for the time being by setting

```yaml
experimental:
    faster_joins: false
```

in their server config.

## Changes to the account data replication streams

Synapse has changed the format of the account data and devices replication
streams (between workers). This is a forwards- and backwards-incompatible
change: v1.75 workers cannot process account data replicated by v1.76 workers,
and vice versa.

Once all workers are upgraded to v1.76 (or downgraded to v1.75), account data
and device replication will resume as normal.

## Minimum version of Poetry is now 1.3.2

The minimum supported version of Poetry is now 1.3.2 (previously 1.2.0, [since 
Synapse 1.67](#upgrading-to-v1670)). If you have used `poetry install` to 
install Synapse from a source checkout, you should upgrade poetry: see its
[installation instructions](https://python-poetry.org/docs/#installation).
For all other installation methods, no acction is required.

# Upgrading to v1.74.0

## Unicode support in user search

This version introduces optional support for an [improved user search dealing with Unicode characters](https://github.com/matrix-org/synapse/pull/14464).

If you want to take advantage of this feature you need to install PyICU,
the ICU native dependency and its development headers
so that PyICU can build since no prebuilt wheels are available.

You can follow [the PyICU documentation](https://pypi.org/project/PyICU/) to do so,
and then do `pip install matrix-synapse[user-search]` for a PyPI install.

Docker images and Debian packages need nothing specific as they already
include or specify ICU as an explicit dependency.


## User directory rebuild

Synapse 1.74 queues a background update
[to rebuild the user directory](https://github.com/matrix-org/synapse/pull/14643),
in order to fix missing or erroneous entries.

When this update begins, the user directory will be cleared out and rebuilt from
scratch. User directory lookups will be incomplete until the rebuild completes.
Admins can monitor the rebuild's progress by using the
[Background update Admin API](usage/administration/admin_api/background_updates.md#status).

# Upgrading to v1.73.0

## Legacy Prometheus metric names have now been removed

Synapse v1.69.0 included the deprecation of legacy Prometheus metric names
and offered an option to disable them.
Synapse v1.71.0 disabled legacy Prometheus metric names by default.

This version, v1.73.0, removes those legacy Prometheus metric names entirely.
This also means that the `enable_legacy_metrics` configuration option has been
removed; it will no longer be possible to re-enable the legacy metric names.

If you use metrics and have not yet updated your Grafana dashboard(s),
Prometheus console(s) or alerting rule(s), please consider doing so when upgrading
to this version.
Note that the included Grafana dashboard was updated in v1.72.0 to correct some
metric names which were missed when legacy metrics were disabled by default.

See [v1.69.0: Deprecation of legacy Prometheus metric names](#deprecation-of-legacy-prometheus-metric-names)
for more context.


# Upgrading to v1.72.0

## Dropping support for PostgreSQL 10

In line with our [deprecation policy](deprecation_policy.md), we've dropped
support for PostgreSQL 10, as it is no longer supported upstream.

This release of Synapse requires PostgreSQL 11+.


# Upgrading to v1.71.0

## Removal of the `generate_short_term_login_token` module API method

As announced with the release of [Synapse 1.69.0](#deprecation-of-the-generate_short_term_login_token-module-api-method), the deprecated `generate_short_term_login_token` module method has been removed.

Modules relying on it can instead use the `create_login_token` method.


## Changes to the events received by application services (interest)

To align with spec (changed in
[MSC3905](https://github.com/matrix-org/matrix-spec-proposals/pull/3905)), Synapse now
only considers local users to be interesting. In other words, the `users` namespace
regex is only be applied against local users of the homeserver.

Please note, this probably doesn't affect the expected behavior of your application
service, since an interesting local user in a room still means all messages in the room
(from local or remote users) will still be considered interesting. And matching a room
with the `rooms` or `aliases` namespace regex will still consider all events sent in the
room to be interesting to the application service.

If one of your application service's `users` regex was intending to match a remote user,
this will no longer match as you expect. The behavioral mismatch between matching all
local users and some remote users is why the spec was changed/clarified and this
caveat is no longer supported.


## Legacy Prometheus metric names are now disabled by default

Synapse v1.71.0 disables legacy Prometheus metric names by default.
For administrators that still rely on them and have not yet had chance to update their
uses of the metrics, it's still possible to specify `enable_legacy_metrics: true` in
the configuration to re-enable them temporarily.

Synapse v1.73.0 will **remove legacy metric names altogether** and at that point,
it will no longer be possible to re-enable them.

If you do not use metrics or you have already updated your Grafana dashboard(s),
Prometheus console(s) and alerting rule(s), there is no action needed.

See [v1.69.0: Deprecation of legacy Prometheus metric names](#deprecation-of-legacy-prometheus-metric-names).


# Upgrading to v1.69.0

## Changes to the receipts replication streams

Synapse now includes information indicating if a receipt applies to a thread when
replicating it to other workers. This is a forwards- and backwards-incompatible
change: v1.68 and workers cannot process receipts replicated by v1.69 workers, and
vice versa.

Once all workers are upgraded to v1.69 (or downgraded to v1.68), receipts
replication will resume as normal.


## Deprecation of legacy Prometheus metric names

In current versions of Synapse, some Prometheus metrics are emitted under two different names,
with one of the names being older but non-compliant with OpenMetrics and Prometheus conventions
and one of the names being newer but compliant.

Synapse v1.71.0 will turn the old metric names off *by default*.
For administrators that still rely on them and have not had chance to update their
uses of the metrics, it's possible to specify `enable_legacy_metrics: true` in
the configuration to re-enable them temporarily.

Synapse v1.73.0 will **remove legacy metric names altogether** and it will no longer
be possible to re-enable them.

The Grafana dashboard, Prometheus recording rules and Prometheus Consoles included
in the `contrib` directory in the Synapse repository have been updated to no longer
rely on the legacy names. These can be used on a current version of Synapse
because current versions of Synapse emit both old and new names.

You may need to update your alerting rules or any other rules that depend on
the names of Prometheus metrics.
If you want to test your changes before legacy names are disabled by default,
you may specify `enable_legacy_metrics: false` in your homeserver configuration.

A list of affected metrics is available on the [Metrics How-to page](https://matrix-org.github.io/synapse/v1.69/metrics-howto.html?highlight=metrics%20deprecated#renaming-of-metrics--deprecation-of-old-names-in-12).


## Deprecation of the `generate_short_term_login_token` module API method

The following method of the module API has been deprecated, and is scheduled to
be remove in v1.71.0:

```python
def generate_short_term_login_token(
    self,
    user_id: str,
    duration_in_ms: int = (2 * 60 * 1000),
    auth_provider_id: str = "",
    auth_provider_session_id: Optional[str] = None,
) -> str:
    ...
```

It has been replaced by an asynchronous equivalent:

```python
async def create_login_token(
    self,
    user_id: str,
    duration_in_ms: int = (2 * 60 * 1000),
    auth_provider_id: Optional[str] = None,
    auth_provider_session_id: Optional[str] = None,
) -> str:
    ...
```

Synapse will log a warning when a module uses the deprecated method, to help
administrators find modules using it.


# Upgrading to v1.68.0

Two changes announced in the upgrade notes for v1.67.0 have now landed in v1.68.0.

## SQLite version requirement

Synapse now requires a SQLite version of 3.27.0 or higher if SQLite is configured as
Synapse's database.

Installations using

- Docker images [from `matrixdotorg`](https://hub.docker.com/r/matrixdotorg/synapse),
- Debian packages [from Matrix.org](https://packages.matrix.org/), or
- a PostgreSQL database

are not affected.

## Rust requirement when building from source.

Building from a source checkout of Synapse now requires a recent Rust compiler
(currently Rust 1.58.1, but see also the
[Platform Dependency Policy](https://matrix-org.github.io/synapse/latest/deprecation_policy.html)).

Installations using

- Docker images [from `matrixdotorg`](https://hub.docker.com/r/matrixdotorg/synapse),
- Debian packages [from Matrix.org](https://packages.matrix.org/), or
- PyPI wheels via `pip install matrix-synapse` (on supported platforms and architectures)

will not be affected.

# Upgrading to v1.67.0

## Direct TCP replication is no longer supported: migrate to Redis

Redis support was added in v1.13.0 with it becoming the recommended method in
v1.18.0. It replaced the old direct TCP connections (which was deprecated as of
v1.18.0) to the main process. With Redis, rather than all the workers connecting
to the main process, all the workers and the main process connect to Redis,
which relays replication commands between processes. This can give a significant
CPU saving on the main process and is a prerequisite for upcoming
performance improvements.

To migrate to Redis add the [`redis` config](./workers.md#shared-configuration),
and remove the TCP `replication` listener from config of the master and
`worker_replication_port` from worker config. Note that a HTTP listener with a
`replication` resource is still required.

## Minimum version of Poetry is now v1.2.0

The minimum supported version of poetry is now 1.2. This should only affect
those installing from a source checkout.

## Rust requirement in the next release

From the next major release (v1.68.0) installing Synapse from a source checkout
will require a recent Rust compiler. Those using packages or
`pip install matrix-synapse` will not be affected.

The simplest way of installing Rust is via [rustup.rs](https://rustup.rs/)

## SQLite version requirement in the next release

From the next major release (v1.68.0) Synapse will require SQLite 3.27.0 or
higher. Synapse v1.67.0 will be the last major release supporting SQLite
versions 3.22 to 3.26.

Those using Docker images or Debian packages from Matrix.org will not be
affected. If you have installed from source, you should check the version of
SQLite used by Python with:

```shell
python -c "import sqlite3; print(sqlite3.sqlite_version)"
```

If this is too old, refer to your distribution for advice on upgrading.


# Upgrading to v1.66.0

## Delegation of email validation no longer supported

As of this version, Synapse no longer allows the tasks of verifying email address
ownership, and password reset confirmation, to be delegated to an identity server.
This removal was previously planned for Synapse 1.64.0, but was
[delayed](https://github.com/matrix-org/synapse/issues/13421) until now to give
homeserver administrators more notice of the change.

To continue to allow users to add email addresses to their homeserver accounts,
and perform password resets, make sure that Synapse is configured with a working
email server in the [`email` configuration
section](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#email)
(including, at a minimum, a `notif_from` setting.)

Specifying an `email` setting under `account_threepid_delegates` will now cause
an error at startup.

# Upgrading to v1.64.0

## Deprecation of the ability to delegate e-mail verification to identity servers

Synapse v1.66.0 will remove the ability to delegate the tasks of verifying email address ownership, and password reset confirmation, to an identity server.

If you require your homeserver to verify e-mail addresses or to support password resets via e-mail, please configure your homeserver with SMTP access so that it can send e-mails on its own behalf.
[Consult the configuration documentation for more information.](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#email)

The option that will be removed is `account_threepid_delegates.email`.


## Changes to the event replication streams

Synapse now includes a flag indicating if an event is an outlier when
replicating it to other workers. This is a forwards- and backwards-incompatible
change: v1.63 and workers cannot process events replicated by v1.64 workers, and
vice versa.

Once all workers are upgraded to v1.64 (or downgraded to v1.63), event
replication will resume as normal.

## frozendict release

[frozendict 2.3.3](https://github.com/Marco-Sulla/python-frozendict/releases/tag/v2.3.3)
has recently been released, which fixes a memory leak that occurs during `/sync`
requests. We advise server administrators who installed Synapse via pip to upgrade
frozendict with `pip install --upgrade frozendict`. The Docker image
`matrixdotorg/synapse` and the Debian packages from `packages.matrix.org` already
include the updated library.

# Upgrading to v1.62.0

## New signatures for spam checker callbacks

As a followup to changes in v1.60.0, the following spam-checker callbacks have changed signature:

- `user_may_join_room`
- `user_may_invite`
- `user_may_send_3pid_invite`
- `user_may_create_room`
- `user_may_create_room_alias`
- `user_may_publish_room`
- `check_media_file_for_spam`

For each of these methods, the previous callback signature has been deprecated.

Whereas callbacks used to return `bool`, they should now return `Union["synapse.module_api.NOT_SPAM", "synapse.module_api.errors.Codes"]`.

For instance, if your module implements `user_may_join_room` as follows:

```python
async def user_may_join_room(self, user_id: str, room_id: str, is_invited: bool)
    if ...:
        # Request is spam
        return False
    # Request is not spam
    return True
```

you should rewrite it as follows:

```python
async def user_may_join_room(self, user_id: str, room_id: str, is_invited: bool)
    if ...:
        # Request is spam, mark it as forbidden (you may use some more precise error
        # code if it is useful).
        return synapse.module_api.errors.Codes.FORBIDDEN
    # Request is not spam, mark it as such.
    return synapse.module_api.NOT_SPAM
```

# Upgrading to v1.61.0

## Removal of deprecated community/groups

This release of Synapse will remove deprecated community/groups from codebase.

### Worker endpoints

For those who have deployed workers, following worker endpoints will no longer
exist and they can be removed from the reverse proxy configuration:

-   `^/_matrix/federation/v1/get_groups_publicised$`
-   `^/_matrix/client/(r0|v3|unstable)/joined_groups$`
-   `^/_matrix/client/(r0|v3|unstable)/publicised_groups$`
-   `^/_matrix/client/(r0|v3|unstable)/publicised_groups/`
-   `^/_matrix/federation/v1/groups/`
-   `^/_matrix/client/(r0|v3|unstable)/groups/`

# Upgrading to v1.60.0

## Adding a new unique index to `state_group_edges` could fail if your database is corrupted

This release of Synapse will add a unique index to the `state_group_edges` table, in order
to prevent accidentally introducing duplicate information (for example, because a database
backup was restored multiple times).

Duplicate rows being present in this table could cause drastic performance problems; see
[issue 11779](https://github.com/matrix-org/synapse/issues/11779) for more details.

If your Synapse database already has had duplicate rows introduced into this table,
this could fail, with either of these errors:


**On Postgres:**
```
synapse.storage.background_updates - 623 - INFO - background_updates-0 - Adding index state_group_edges_unique_idx to state_group_edges
synapse.storage.background_updates - 282 - ERROR - background_updates-0 - Error doing update
...
psycopg2.errors.UniqueViolation: could not create unique index "state_group_edges_unique_idx"
DETAIL:  Key (state_group, prev_state_group)=(2, 1) is duplicated.
```
(The numbers may be different.)

**On SQLite:**
```
synapse.storage.background_updates - 623 - INFO - background_updates-0 - Adding index state_group_edges_unique_idx to state_group_edges
synapse.storage.background_updates - 282 - ERROR - background_updates-0 - Error doing update
...
sqlite3.IntegrityError: UNIQUE constraint failed: state_group_edges.state_group, state_group_edges.prev_state_group
```


<details>
<summary><b>Expand this section for steps to resolve this problem</b></summary>

### On Postgres

Connect to your database with `psql`.

```sql
BEGIN;
DELETE FROM state_group_edges WHERE (ctid, state_group, prev_state_group) IN (
  SELECT row_id, state_group, prev_state_group
  FROM (
    SELECT
      ctid AS row_id,
      MIN(ctid) OVER (PARTITION BY state_group, prev_state_group) AS min_row_id,
      state_group,
      prev_state_group
    FROM state_group_edges
  ) AS t1
  WHERE row_id <> min_row_id
);
COMMIT;
```


### On SQLite

At the command-line, use `sqlite3 path/to/your-homeserver-database.db`:

```sql
BEGIN;
DELETE FROM state_group_edges WHERE (rowid, state_group, prev_state_group) IN (
  SELECT row_id, state_group, prev_state_group
  FROM (
    SELECT
      rowid AS row_id,
      MIN(rowid) OVER (PARTITION BY state_group, prev_state_group) AS min_row_id,
      state_group,
      prev_state_group
    FROM state_group_edges
  )
  WHERE row_id <> min_row_id
);
COMMIT;
```


### For more details

[This comment on issue 11779](https://github.com/matrix-org/synapse/issues/11779#issuecomment-1131545970)
has queries that can be used to check a database for this problem in advance.

</details>

## New signature for the spam checker callback `check_event_for_spam`

The previous signature has been deprecated.

Whereas `check_event_for_spam` callbacks used to return `Union[str, bool]`, they should now return `Union["synapse.module_api.NOT_SPAM", "synapse.module_api.errors.Codes"]`.

This is part of an ongoing refactoring of the SpamChecker API to make it less ambiguous and more powerful.

If your module implements `check_event_for_spam` as follows:

```python
async def check_event_for_spam(event):
    if ...:
        # Event is spam
        return True
    # Event is not spam
    return False
```

you should rewrite it as follows:

```python
async def check_event_for_spam(event):
    if ...:
        # Event is spam, mark it as forbidden (you may use some more precise error
        # code if it is useful).
        return synapse.module_api.errors.Codes.FORBIDDEN
    # Event is not spam, mark it as such.
    return synapse.module_api.NOT_SPAM
```

# Upgrading to v1.59.0

## Device name lookup over federation has been disabled by default

The names of user devices are no longer visible to users on other homeservers by default.
Device IDs are unaffected, as these are necessary to facilitate end-to-end encryption.

To re-enable this functionality, set the
[`allow_device_name_lookup_over_federation`](https://matrix-org.github.io/synapse/v1.59/usage/configuration/config_documentation.html#federation)
homeserver config option to `true`.


## Deprecation of the `synapse.app.appservice` and `synapse.app.user_dir` worker application types

The `synapse.app.appservice` worker application type allowed you to configure a
single worker to use to notify application services of new events, as long
as this functionality was disabled on the main process with `notify_appservices: False`.
Further, the `synapse.app.user_dir` worker application type allowed you to configure
a single worker to be responsible for updating the user directory, as long as this
was disabled on the main process with `update_user_directory: False`.

To unify Synapse's worker types, the `synapse.app.appservice` worker application
type and the `notify_appservices` configuration option have been deprecated.
The `synapse.app.user_dir` worker application type and `update_user_directory`
configuration option have also been deprecated.

To get the same functionality as was provided by the deprecated options, it's now recommended that the `synapse.app.generic_worker`
worker application type is used and that the `notify_appservices_from_worker` and/or
`update_user_directory_from_worker` options are set to the name of a worker.

For the time being, the old options can be used alongside the new options to make
it easier to transition between the two configurations, however please note that:

- the options must not contradict each other (otherwise Synapse won't start); and
- the `notify_appservices` and `update_user_directory` options will be removed in a future release of Synapse.

Please see the [*Notifying Application Services*][v1_59_notify_ases_from] and
[*Updating the User Directory*][v1_59_update_user_dir] sections of the worker
documentation for more information.

[v1_59_notify_ases_from]: workers.md#notifying-application-services
[v1_59_update_user_dir]: workers.md#updating-the-user-directory


# Upgrading to v1.58.0

## Groups/communities feature has been disabled by default

The non-standard groups/communities feature in Synapse has been disabled by default
and will be removed in Synapse v1.61.0.


# Upgrading to v1.57.0

## Changes to database schema for application services

Synapse v1.57.0 includes a [change](https://github.com/matrix-org/synapse/pull/12209) to the
way transaction IDs are managed for application services. If your deployment uses a dedicated
worker for application service traffic, **it must be stopped** when the database is upgraded
(which normally happens when the main process is upgraded), to ensure the change is made safely
without any risk of reusing transaction IDs.

Deployments which do not use separate worker processes can be upgraded as normal. Similarly,
deployments where no application services are in use can be upgraded as normal.

<details>
<summary><b>Recovering from an incorrect upgrade</b></summary>

If the database schema is upgraded *without* stopping the worker responsible
for AS traffic, then the following error may be given when attempting to start
a Synapse worker or master process:

```
**********************************************************************************
 Error during initialisation:

 Postgres sequence 'application_services_txn_id_seq' is inconsistent with associated
 table 'application_services_txns'. This can happen if Synapse has been downgraded and
 then upgraded again, or due to a bad migration.

 To fix this error, shut down Synapse (including any and all workers)
 and run the following SQL:

     SELECT setval('application_services_txn_id_seq', (
         SELECT GREATEST(MAX(txn_id), 0) FROM application_services_txns
     ));

 See docs/postgres.md for more information.

 There may be more information in the logs.
**********************************************************************************
```

This error may also be seen if Synapse is *downgraded* to an earlier version,
and then upgraded again to v1.57.0 or later.

In either case:

 1. Ensure that the worker responsible for AS traffic is stopped.
 2. Run the SQL command given in the error message via `psql`.

Synapse should then start correctly.
</details>

# Upgrading to v1.56.0

## Open registration without verification is now disabled by default

Synapse will refuse to start if registration is enabled without email, captcha, or token-based verification unless the new config
flag `enable_registration_without_verification` is set to "true".

## Groups/communities feature has been deprecated

The non-standard groups/communities feature in Synapse has been deprecated and will
be disabled by default in Synapse v1.58.0.

You can test disabling it by adding the following to your homeserver configuration:

```yaml
experimental_features:
  groups_enabled: false
```

## Change in behaviour for PostgreSQL databases with unsafe locale

Synapse now refuses to start when using PostgreSQL with non-`C` values for `COLLATE` and
`CTYPE` unless the config flag `allow_unsafe_locale`, found in the database section of
the configuration file, is set to `true`. See the [PostgreSQL documentation](https://matrix-org.github.io/synapse/latest/postgres.html#fixing-incorrect-collate-or-ctype)
for more information and instructions on how to fix a database with incorrect values.

# Upgrading to v1.55.0

## `synctl` script has been moved

The `synctl` script
[has been made](https://github.com/matrix-org/synapse/pull/12140) an
[entry point](https://packaging.python.org/en/latest/specifications/entry-points/)
and no longer exists at the root of Synapse's source tree. If you wish to use
`synctl` to manage your homeserver, you should invoke `synctl` directly, e.g.
`synctl start` instead of `./synctl start` or `/path/to/synctl start`.

You will need to ensure `synctl` is on your `PATH`.
  - This is automatically the case when using
    [Debian packages](https://packages.matrix.org/debian/) or
    [docker images](https://hub.docker.com/r/matrixdotorg/synapse)
    provided by Matrix.org.
  - When installing from a wheel, sdist, or PyPI, a `synctl` executable is added
    to your Python installation's `bin`. This should be on your `PATH`
    automatically, though you might need to activate a virtual environment
    depending on how you installed Synapse.


## Compatibility dropped for Mjolnir 1.3.1 and earlier

Synapse v1.55.0 drops support for Mjolnir 1.3.1 and earlier.
If you use the Mjolnir module to moderate your homeserver,
please upgrade Mjolnir to version 1.3.2 or later before upgrading Synapse.


# Upgrading to v1.54.0

## Legacy structured logging configuration removal

This release removes support for the `structured: true` logging configuration
which was deprecated in Synapse v1.23.0. If your logging configuration contains
`structured: true` then it should be modified based on the
[structured logging documentation](https://matrix-org.github.io/synapse/v1.56/structured_logging.html#upgrading-from-legacy-structured-logging-configuration).

# Upgrading to v1.53.0

## Dropping support for `webclient` listeners and non-HTTP(S) `web_client_location`

Per the deprecation notice in Synapse v1.51.0, listeners of type  `webclient`
are no longer supported and configuring them is a now a configuration error.

Configuring a non-HTTP(S) `web_client_location` configuration is is now a
configuration error. Since the `webclient` listener is no longer supported, this
setting only applies to the root path `/` of Synapse's web server and no longer
the `/_matrix/client/` path.

## Stablisation of MSC3231

The unstable validity-check endpoint for the
[Registration Tokens](https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv1registermloginregistration_tokenvalidity)
feature has been stabilised and moved from:

`/_matrix/client/unstable/org.matrix.msc3231/register/org.matrix.msc3231.login.registration_token/validity`

to:

`/_matrix/client/v1/register/m.login.registration_token/validity`

Please update any relevant reverse proxy or firewall configurations appropriately.

## Time-based cache expiry is now enabled by default

Formerly, entries in the cache were not evicted regardless of whether they were accessed after storing.
This behavior has now changed. By default entries in the cache are now evicted after 30m of not being accessed.
To change the default behavior, go to the `caches` section of the config and change the `expire_caches` and
`cache_entry_ttl` flags as necessary. Please note that these flags replace the `expiry_time` flag in the config.
The `expiry_time` flag will still continue to work, but it has been deprecated and will be removed in the future.

## Deprecation of `capability` `org.matrix.msc3283.*`

The `capabilities` of MSC3283 from the REST API `/_matrix/client/r0/capabilities`
becomes stable.

The old `capabilities`
- `org.matrix.msc3283.set_displayname`,
- `org.matrix.msc3283.set_avatar_url` and
- `org.matrix.msc3283.3pid_changes`

are deprecated and scheduled to be removed in Synapse v1.54.0.

The new `capabilities`
- `m.set_displayname`,
- `m.set_avatar_url` and
- `m.3pid_changes`

are now active by default.

## Removal of `user_may_create_room_with_invites`

As announced with the release of [Synapse 1.47.0](#deprecation-of-the-user_may_create_room_with_invites-module-callback),
the deprecated `user_may_create_room_with_invites` module callback has been removed.

Modules relying on it can instead implement [`user_may_invite`](https://matrix-org.github.io/synapse/latest/modules/spam_checker_callbacks.html#user_may_invite)
and use the [`get_room_state`](https://github.com/matrix-org/synapse/blob/872f23b95fa980a61b0866c1475e84491991fa20/synapse/module_api/__init__.py#L869-L876)
module API to infer whether the invite is happening while creating a room (see [this function](https://github.com/matrix-org/synapse-domain-rule-checker/blob/e7d092dd9f2a7f844928771dbfd9fd24c2332e48/synapse_domain_rule_checker/__init__.py#L56-L89)
as an example). Alternately, modules can also implement [`on_create_room`](https://matrix-org.github.io/synapse/latest/modules/third_party_rules_callbacks.html#on_create_room).


# Upgrading to v1.52.0

## Twisted security release

Note that [Twisted 22.1.0](https://github.com/twisted/twisted/releases/tag/twisted-22.1.0)
has recently been released, which fixes a [security issue](https://github.com/twisted/twisted/security/advisories/GHSA-92x2-jw7w-xvvx)
within the Twisted library. We do not believe Synapse is affected by this vulnerability,
though we advise server administrators who installed Synapse via pip to upgrade Twisted
with `pip install --upgrade Twisted treq` as a matter of good practice. The Docker image
`matrixdotorg/synapse` and the Debian packages from `packages.matrix.org` are using the
updated library.

# Upgrading to v1.51.0

## Deprecation of `webclient` listeners and non-HTTP(S) `web_client_location`

Listeners of type  `webclient` are deprecated and scheduled to be removed in
Synapse v1.53.0.

Similarly, a non-HTTP(S) `web_client_location` configuration is deprecated and
will become a configuration error in Synapse v1.53.0.


# Upgrading to v1.50.0

## Dropping support for old Python and Postgres versions

In line with our [deprecation policy](deprecation_policy.md),
we've dropped support for Python 3.6 and PostgreSQL 9.6, as they are no
longer supported upstream.

This release of Synapse requires Python 3.7+ and PostgreSQL 10+.


# Upgrading to v1.47.0

## Removal of old Room Admin API

The following admin APIs were deprecated in [Synapse 1.34](https://github.com/matrix-org/synapse/blob/v1.34.0/CHANGES.md#deprecations-and-removals)
(released on 2021-05-17) and have now been removed:

- `POST /_synapse/admin/v1/<room_id>/delete`

Any scripts still using the above APIs should be converted to use the
[Delete Room API](https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#delete-room-api).

## Deprecation of the `user_may_create_room_with_invites` module callback

The `user_may_create_room_with_invites` is deprecated and will be removed in a future
version of Synapse. Modules implementing this callback can instead implement
[`user_may_invite`](https://matrix-org.github.io/synapse/latest/modules/spam_checker_callbacks.html#user_may_invite)
and use the [`get_room_state`](https://github.com/matrix-org/synapse/blob/872f23b95fa980a61b0866c1475e84491991fa20/synapse/module_api/__init__.py#L869-L876)
module API method to infer whether the invite is happening in the context of creating a
room.

We plan to remove this callback in January 2022.

# Upgrading to v1.45.0

## Changes required to media storage provider modules when reading from the Synapse configuration object

Media storage provider modules that read from the Synapse configuration object (i.e. that
read the value of `hs.config.[...]`) now need to specify the configuration section they're
reading from. This means that if a module reads the value of e.g. `hs.config.media_store_path`,
it needs to replace it with `hs.config.media.media_store_path`.

# Upgrading to v1.44.0

## The URL preview cache is no longer mirrored to storage providers
The `url_cache/` and `url_cache_thumbnails/` directories in the media store are
no longer mirrored to storage providers. These two directories can be safely
deleted from any configured storage providers to reclaim space.

# Upgrading to v1.43.0

## The spaces summary APIs can now be handled by workers

The [available worker applications documentation](https://matrix-org.github.io/synapse/latest/workers.html#available-worker-applications)
has been updated to reflect that calls to the `/spaces`, `/hierarchy`, and
`/summary` endpoints can now be routed to workers for both client API and
federation requests.

# Upgrading to v1.42.0

## Removal of old Room Admin API

The following admin APIs were deprecated in [Synapse 1.25](https://github.com/matrix-org/synapse/blob/v1.25.0/CHANGES.md#removal-warning)
(released on 2021-01-13) and have now been removed:

-   `POST /_synapse/admin/v1/purge_room`
-   `POST /_synapse/admin/v1/shutdown_room/<room_id>`

Any scripts still using the above APIs should be converted to use the
[Delete Room API](https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#delete-room-api).

## User-interactive authentication fallback templates can now display errors

This may affect you if you make use of custom HTML templates for the
[reCAPTCHA (`synapse/res/templates/recaptcha.html`)](https://github.com/matrix-org/synapse/tree/develop/synapse/res/templates/recaptcha.html) or
[terms (`synapse/res/templates/terms.html`)](https://github.com/matrix-org/synapse/tree/develop/synapse/res/templates/terms.html) fallback pages.

The template is now provided an `error` variable if the authentication
process failed. See the default templates linked above for an example.

## Removal of out-of-date email pushers

Users will stop receiving message updates via email for addresses that were
once, but not still, linked to their account.

# Upgrading to v1.41.0

## Add support for routing outbound HTTP requests via a proxy for federation

Since Synapse 1.6.0 (2019-11-26) you can set a proxy for outbound HTTP requests via
http_proxy/https_proxy environment variables. This proxy was set for:
- push
- url previews
- phone-home stats
- recaptcha validation
- CAS auth validation
- OpenID Connect
- Federation (checking public key revocation)

In this version we have added support for outbound requests for:
- Outbound federation
- Downloading remote media
- Fetching public keys of other servers

These requests use the same proxy configuration. If you have a proxy configuration we
recommend to verify the configuration. It may be necessary to adjust the `no_proxy`
environment variable.

See [using a forward proxy with Synapse documentation](setup/forward_proxy.md) for
details.

## Deprecation of `template_dir`

The `template_dir` settings in the `sso`, `account_validity` and `email` sections of the
configuration file are now deprecated. Server admins should use the new
`templates.custom_template_directory` setting in the configuration file and use one single
custom template directory for all aforementioned features. Template file names remain
unchanged. See [the related documentation](https://matrix-org.github.io/synapse/latest/templates.html)
for more information and examples.

We plan to remove support for these settings in October 2021.

## `/_synapse/admin/v1/users/{userId}/media` must be handled by media workers

The [media repository worker documentation](https://matrix-org.github.io/synapse/latest/workers.html#synapseappmedia_repository)
has been updated to reflect that calls to `/_synapse/admin/v1/users/{userId}/media`
must now be handled by media repository workers. This is due to the new `DELETE` method
of this endpoint modifying the media store.

# Upgrading to v1.39.0

## Deprecation of the current third-party rules module interface

The current third-party rules module interface is deprecated in favour of the new generic
modules system introduced in Synapse v1.37.0. Authors of third-party rules modules can refer
to [this documentation](modules/porting_legacy_module.md)
to update their modules. Synapse administrators can refer to [this documentation](modules/index.md)
to update their configuration once the modules they are using have been updated.

We plan to remove support for the current third-party rules interface in September 2021.


# Upgrading to v1.38.0

## Re-indexing of `events` table on Postgres databases

This release includes a database schema update which requires re-indexing one of
the larger tables in the database, `events`. This could result in increased
disk I/O for several hours or days after upgrading while the migration
completes. Furthermore, because we have to keep the old indexes until the new
indexes are ready, it could result in a significant, temporary, increase in
disk space.

To get a rough idea of the disk space required, check the current size of one
of the indexes. For example, from a `psql` shell, run the following sql:

```sql
SELECT pg_size_pretty(pg_relation_size('events_order_room'));
```

We need to rebuild **four** indexes, so you will need to multiply this result
by four to give an estimate of the disk space required. For example, on one
particular server:

```
synapse=# select pg_size_pretty(pg_relation_size('events_order_room'));
 pg_size_pretty
----------------
 288 MB
(1 row)
```

On this server, it would be wise to ensure that at least 1152MB are free.

The additional disk space will be freed once the migration completes.

SQLite databases are unaffected by this change.


# Upgrading to v1.37.0

## Deprecation of the current spam checker interface

The current spam checker interface is deprecated in favour of a new generic modules system.
Authors of spam checker modules can refer to [this
documentation](modules/porting_legacy_module.md
to update their modules. Synapse administrators can refer to [this
documentation](modules/index.md)
to update their configuration once the modules they are using have been updated.

We plan to remove support for the current spam checker interface in August 2021.

More module interfaces will be ported over to this new generic system in future versions
of Synapse.


# Upgrading to v1.34.0

## `room_invite_state_types` configuration setting

The `room_invite_state_types` configuration setting has been deprecated
and replaced with `room_prejoin_state`. See the [sample configuration
file](https://github.com/matrix-org/synapse/blob/v1.34.0/docs/sample_config.yaml#L1515).

If you have set `room_invite_state_types` to the default value you
should simply remove it from your configuration file. The default value
used to be:

```yaml
room_invite_state_types:
   - "m.room.join_rules"
   - "m.room.canonical_alias"
   - "m.room.avatar"
   - "m.room.encryption"
   - "m.room.name"
```

If you have customised this value, you should remove
`room_invite_state_types` and configure `room_prejoin_state` instead.

# Upgrading to v1.33.0

## Account Validity HTML templates can now display a user's expiration date

This may affect you if you have enabled the account validity feature,
and have made use of a custom HTML template specified by the
`account_validity.template_dir` or
`account_validity.account_renewed_html_path` Synapse config options.

The template can now accept an `expiration_ts` variable, which
represents the unix timestamp in milliseconds for the future date of
which their account has been renewed until. See the [default
template](https://github.com/matrix-org/synapse/blob/release-v1.33.0/synapse/res/templates/account_renewed.html)
for an example of usage.

ALso note that a new HTML template, `account_previously_renewed.html`,
has been added. This is is shown to users when they attempt to renew
their account with a valid renewal token that has already been used
before. The default template contents can been found
[here](https://github.com/matrix-org/synapse/blob/release-v1.33.0/synapse/res/templates/account_previously_renewed.html),
and can also accept an `expiration_ts` variable. This template replaces
the error message users would previously see upon attempting to use a
valid renewal token more than once.

# Upgrading to v1.32.0

## Regression causing connected Prometheus instances to become overwhelmed

This release introduces [a
regression](https://github.com/matrix-org/synapse/issues/9853) that can
overwhelm connected Prometheus instances. This issue is not present in
Synapse v1.32.0rc1.

If you have been affected, please downgrade to 1.31.0. You then may need
to remove excess writeahead logs in order for Prometheus to recover.
Instructions for doing so are provided
[here](https://github.com/matrix-org/synapse/pull/9854#issuecomment-823472183).

## Dropping support for old Python, Postgres and SQLite versions

In line with our [deprecation policy](deprecation_policy.md),
we've dropped support for Python 3.5 and PostgreSQL 9.5, as they are no
longer supported upstream.

This release of Synapse requires Python 3.6+ and PostgreSQL 9.6+ or
SQLite 3.22+.

## Removal of old List Accounts Admin API

The deprecated v1 "list accounts" admin API
(`GET /_synapse/admin/v1/users/<user_id>`) has been removed in this
version.

The [v2 list accounts API](admin_api/user_admin_api.md#list-accounts)
has been available since Synapse 1.7.0 (2019-12-13), and is accessible
under `GET /_synapse/admin/v2/users`.

The deprecation of the old endpoint was announced with Synapse 1.28.0
(released on 2021-02-25).

## Application Services must use type `m.login.application_service` when registering users

In compliance with the [Application Service
spec](https://matrix.org/docs/spec/application_service/r0.1.2#server-admin-style-permissions),
Application Services are now required to use the
`m.login.application_service` type when registering users via the
`/_matrix/client/r0/register` endpoint. This behaviour was deprecated in
Synapse v1.30.0.

Please ensure your Application Services are up to date.

# Upgrading to v1.29.0

## Requirement for X-Forwarded-Proto header

When using Synapse with a reverse proxy (in particular, when using the
`x_forwarded` option on an HTTP listener), Synapse now
expects to receive an `X-Forwarded-Proto` header on incoming
HTTP requests. If it is not set, Synapse will log a warning on each
received request.

To avoid the warning, administrators using a reverse proxy should ensure
that the reverse proxy sets `X-Forwarded-Proto` header to
`https` or `http` to indicate the protocol used
by the client.

Synapse also requires the `Host` header to be preserved.

See the [reverse proxy documentation](reverse_proxy.md), where the
example configurations have been updated to show how to set these
headers.

(Users of [Caddy](https://caddyserver.com/) are unaffected, since we
believe it sets `X-Forwarded-Proto` by default.)

# Upgrading to v1.27.0

## Changes to callback URI for OAuth2 / OpenID Connect and SAML2

This version changes the URI used for callbacks from OAuth2 and SAML2
identity providers:

-   If your server is configured for single sign-on via an OpenID
    Connect or OAuth2 identity provider, you will need to add
    `[synapse public baseurl]/_synapse/client/oidc/callback` to the list
    of permitted "redirect URIs" at the identity provider.

    See the [OpenID docs](openid.md) for more information on setting
    up OpenID Connect.

-   If your server is configured for single sign-on via a SAML2 identity
    provider, you will need to add
    `[synapse public baseurl]/_synapse/client/saml2/authn_response` as a
    permitted "ACS location" (also known as "allowed callback URLs")
    at the identity provider.

    The "Issuer" in the "AuthnRequest" to the SAML2 identity
    provider is also updated to
    `[synapse public baseurl]/_synapse/client/saml2/metadata.xml`. If
    your SAML2 identity provider uses this property to validate or
    otherwise identify Synapse, its configuration will need to be
    updated to use the new URL. Alternatively you could create a new,
    separate "EntityDescriptor" in your SAML2 identity provider with
    the new URLs and leave the URLs in the existing "EntityDescriptor"
    as they were.

## Changes to HTML templates

The HTML templates for SSO and email notifications now have [Jinja2's
autoescape](https://jinja.palletsprojects.com/en/2.11.x/api/#autoescaping)
enabled for files ending in `.html`, `.htm`, and `.xml`. If you have
customised these templates and see issues when viewing them you might
need to update them. It is expected that most configurations will need
no changes.

If you have customised the templates *names* for these templates, it is
recommended to verify they end in `.html` to ensure autoescape is
enabled.

The above applies to the following templates:

-   `add_threepid.html`
-   `add_threepid_failure.html`
-   `add_threepid_success.html`
-   `notice_expiry.html`
-   `notice_expiry.html`
-   `notif_mail.html` (which, by default, includes `room.html` and
    `notif.html`)
-   `password_reset.html`
-   `password_reset_confirmation.html`
-   `password_reset_failure.html`
-   `password_reset_success.html`
-   `registration.html`
-   `registration_failure.html`
-   `registration_success.html`
-   `sso_account_deactivated.html`
-   `sso_auth_bad_user.html`
-   `sso_auth_confirm.html`
-   `sso_auth_success.html`
-   `sso_error.html`
-   `sso_login_idp_picker.html`
-   `sso_redirect_confirm.html`

# Upgrading to v1.26.0

## Rolling back to v1.25.0 after a failed upgrade

v1.26.0 includes a lot of large changes. If something problematic
occurs, you may want to roll-back to a previous version of Synapse.
Because v1.26.0 also includes a new database schema version, reverting
that version is also required alongside the generic rollback
instructions mentioned above. In short, to roll back to v1.25.0 you need
to:

1.  Stop the server

2.  Decrease the schema version in the database:

    ```sql
    UPDATE schema_version SET version = 58;
    ```

3.  Delete the ignored users & chain cover data:

    ```sql
    DROP TABLE IF EXISTS ignored_users;
    UPDATE rooms SET has_auth_chain_index = false;
    ```

    For PostgreSQL run:

    ```sql
    TRUNCATE event_auth_chain_links;
    TRUNCATE event_auth_chains;
    ```

    For SQLite run:

    ```sql
    DELETE FROM event_auth_chain_links;
    DELETE FROM event_auth_chains;
    ```

4.  Mark the deltas as not run (so they will re-run on upgrade).

    ```sql
    DELETE FROM applied_schema_deltas WHERE version = 59 AND file = "59/01ignored_user.py";
    DELETE FROM applied_schema_deltas WHERE version = 59 AND file = "59/06chain_cover_index.sql";
    ```

5.  Downgrade Synapse by following the instructions for your
    installation method in the "Rolling back to older versions"
    section above.

# Upgrading to v1.25.0

## Last release supporting Python 3.5

This is the last release of Synapse which guarantees support with Python
3.5, which passed its upstream End of Life date several months ago.

We will attempt to maintain support through March 2021, but without
guarantees.

In the future, Synapse will follow upstream schedules for ending support
of older versions of Python and PostgreSQL. Please upgrade to at least
Python 3.6 and PostgreSQL 9.6 as soon as possible.

## Blacklisting IP ranges

Synapse v1.25.0 includes new settings, `ip_range_blacklist` and
`ip_range_whitelist`, for controlling outgoing requests from Synapse for
federation, identity servers, push, and for checking key validity for
third-party invite events. The previous setting,
`federation_ip_range_blacklist`, is deprecated. The new
`ip_range_blacklist` defaults to private IP ranges if it is not defined.

If you have never customised `federation_ip_range_blacklist` it is
recommended that you remove that setting.

If you have customised `federation_ip_range_blacklist` you should update
the setting name to `ip_range_blacklist`.

If you have a custom push server that is reached via private IP space
you may need to customise `ip_range_blacklist` or `ip_range_whitelist`.

# Upgrading to v1.24.0

## Custom OpenID Connect mapping provider breaking change

This release allows the OpenID Connect mapping provider to perform
normalisation of the localpart of the Matrix ID. This allows for the
mapping provider to specify different algorithms, instead of the
[default
way](<https://matrix.org/docs/spec/appendices#mapping-from-other-character-sets>).

If your Synapse configuration uses a custom mapping provider
(`oidc_config.user_mapping_provider.module` is specified and
not equal to
`synapse.handlers.oidc_handler.JinjaOidcMappingProvider`)
then you *must* ensure that `map_user_attributes` of the
mapping provider performs some normalisation of the
`localpart` returned. To match previous behaviour you can
use the `map_username_to_mxid_localpart` function provided
by Synapse. An example is shown below:

```python
from synapse.types import map_username_to_mxid_localpart

class MyMappingProvider:
    def map_user_attributes(self, userinfo, token):
        # ... your custom logic ...
        sso_user_id = ...
        localpart = map_username_to_mxid_localpart(sso_user_id)

        return {"localpart": localpart}
```

## Removal historical Synapse Admin API

Historically, the Synapse Admin API has been accessible under:

-   `/_matrix/client/api/v1/admin`
-   `/_matrix/client/unstable/admin`
-   `/_matrix/client/r0/admin`
-   `/_synapse/admin/v1`

The endpoints with `/_matrix/client/*` prefixes have been removed as of
v1.24.0. The Admin API is now only accessible under:

-   `/_synapse/admin/v1`

The only exception is the `/admin/whois` endpoint, which is
[also available via the client-server
API](https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-admin-whois-userid).

The deprecation of the old endpoints was announced with Synapse 1.20.0
(released on 2020-09-22) and makes it easier for homeserver admins to
lock down external access to the Admin API endpoints.

# Upgrading to v1.23.0

## Structured logging configuration breaking changes

This release deprecates use of the `structured: true` logging
configuration for structured logging. If your logging configuration
contains `structured: true` then it should be modified based on the
[structured logging documentation](https://matrix-org.github.io/synapse/v1.56/structured_logging.html#upgrading-from-legacy-structured-logging-configuration).

The `structured` and `drains` logging options are now deprecated and
should be replaced by standard logging configuration of `handlers` and
`formatters`.

A future will release of Synapse will make using `structured: true` an
error.

# Upgrading to v1.22.0

## ThirdPartyEventRules breaking changes

This release introduces a backwards-incompatible change to modules
making use of `ThirdPartyEventRules` in Synapse. If you make use of a
module defined under the `third_party_event_rules` config option, please
make sure it is updated to handle the below change:

The `http_client` argument is no longer passed to modules as they are
initialised. Instead, modules are expected to make use of the
`http_client` property on the `ModuleApi` class. Modules are now passed
a `module_api` argument during initialisation, which is an instance of
`ModuleApi`. `ModuleApi` instances have a `http_client` property which
acts the same as the `http_client` argument previously passed to
`ThirdPartyEventRules` modules.

# Upgrading to v1.21.0

## Forwarding `/_synapse/client` through your reverse proxy

The [reverse proxy documentation](reverse_proxy.md)
has been updated to include reverse proxy directives for
`/_synapse/client/*` endpoints. As the user password reset flow now uses
endpoints under this prefix, **you must update your reverse proxy
configurations for user password reset to work**.

Additionally, note that the [Synapse worker documentation](workers.md) has been updated to

:   state that the `/_synapse/client/password_reset/email/submit_token`
    endpoint can be handled

by all workers. If you make use of Synapse's worker feature, please
update your reverse proxy configuration to reflect this change.

## New HTML templates

A new HTML template,
[password_reset_confirmation.html](https://github.com/matrix-org/synapse/blob/develop/synapse/res/templates/password_reset_confirmation.html),
has been added to the `synapse/res/templates` directory. If you are
using a custom template directory, you may want to copy the template
over and modify it.

Note that as of v1.20.0, templates do not need to be included in custom
template directories for Synapse to start. The default templates will be
used if a custom template cannot be found.

This page will appear to the user after clicking a password reset link
that has been emailed to them.

To complete password reset, the page must include a way to make a
`POST` request to
`/_synapse/client/password_reset/{medium}/submit_token` with the query
parameters from the original link, presented as a URL-encoded form. See
the file itself for more details.

## Updated Single Sign-on HTML Templates

The `saml_error.html` template was removed from Synapse and replaced
with the `sso_error.html` template. If your Synapse is configured to use
SAML and a custom `sso_redirect_confirm_template_dir` configuration then
any customisations of the `saml_error.html` template will need to be
merged into the `sso_error.html` template. These templates are similar,
but the parameters are slightly different:

-   The `msg` parameter should be renamed to `error_description`.
-   There is no longer a `code` parameter for the response code.
-   A string `error` parameter is available that includes a short hint
    of why a user is seeing the error page.

# Upgrading to v1.18.0

## Docker `-py3` suffix will be removed in future versions

From 10th August 2020, we will no longer publish Docker images with the
`-py3` tag suffix. The images tagged with the
`-py3` suffix have been identical to the non-suffixed tags
since release 0.99.0, and the suffix is obsolete.

On 10th August, we will remove the `latest-py3` tag.
Existing per-release tags (such as `v1.18.0-py3` will not
be removed, but no new `-py3` tags will be added.

Scripts relying on the `-py3` suffix will need to be
updated.

## Redis replication is now recommended in lieu of TCP replication

When setting up worker processes, we now recommend the use of a Redis
server for replication. **The old direct TCP connection method is
deprecated and will be removed in a future release.** See
the [worker documentation](https://matrix-org.github.io/synapse/v1.66/workers.html) for more details.

# Upgrading to v1.14.0

This version includes a database update which is run as part of the
upgrade, and which may take a couple of minutes in the case of a large
server. Synapse will not respond to HTTP requests while this update is
taking place.

# Upgrading to v1.13.0

## Incorrect database migration in old synapse versions

A bug was introduced in Synapse 1.4.0 which could cause the room
directory to be incomplete or empty if Synapse was upgraded directly
from v1.2.1 or earlier, to versions between v1.4.0 and v1.12.x.

This will *not* be a problem for Synapse installations which were:

:   -   created at v1.4.0 or later,
    -   upgraded via v1.3.x, or
    -   upgraded straight from v1.2.1 or earlier to v1.13.0 or later.

If completeness of the room directory is a concern, installations which
are affected can be repaired as follows:

1.  Run the following sql from a `psql` or
    `sqlite3` console:

    ```sql
    INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
       ('populate_stats_process_rooms', '{}', 'current_state_events_membership');

    INSERT INTO background_updates (update_name, progress_json, depends_on) VALUES
       ('populate_stats_process_users', '{}', 'populate_stats_process_rooms');
    ```

2.  Restart synapse.

## New Single Sign-on HTML Templates

New templates (`sso_auth_confirm.html`, `sso_auth_success.html`, and
`sso_account_deactivated.html`) were added to Synapse. If your Synapse
is configured to use SSO and a custom
`sso_redirect_confirm_template_dir` configuration then these templates
will need to be copied from
[`synapse/res/templates`](https://github.com/matrix-org/synapse/tree/develop/synapse/res/templates) into that directory.

## Synapse SSO Plugins Method Deprecation

Plugins using the `complete_sso_login` method of
`synapse.module_api.ModuleApi` should update to using the async/await
version `complete_sso_login_async` which includes additional checks. The
non-async version is considered deprecated.

## Rolling back to v1.12.4 after a failed upgrade

v1.13.0 includes a lot of large changes. If something problematic
occurs, you may want to roll-back to a previous version of Synapse.
Because v1.13.0 also includes a new database schema version, reverting
that version is also required alongside the generic rollback
instructions mentioned above. In short, to roll back to v1.12.4 you need
to:

1.  Stop the server

2.  Decrease the schema version in the database:

    ```sql
    UPDATE schema_version SET version = 57;
    ```

3.  Downgrade Synapse by following the instructions for your
    installation method in the "Rolling back to older versions"
    section above.

# Upgrading to v1.12.0

This version includes a database update which is run as part of the
upgrade, and which may take some time (several hours in the case of a
large server). Synapse will not respond to HTTP requests while this
update is taking place.

This is only likely to be a problem in the case of a server which is
participating in many rooms.

0.  As with all upgrades, it is recommended that you have a recent
    backup of your database which can be used for recovery in the event
    of any problems.

1.  As an initial check to see if you will be affected, you can try
    running the following query from the `psql` or
    `sqlite3` console. It is safe to run it while Synapse is
    still running.

    ```sql
    SELECT MAX(q.v) FROM (
      SELECT (
        SELECT ej.json AS v
        FROM state_events se INNER JOIN event_json ej USING (event_id)
        WHERE se.room_id=rooms.room_id AND se.type='m.room.create' AND se.state_key=''
        LIMIT 1
      ) FROM rooms WHERE rooms.room_version IS NULL
    ) q;
    ```

    This query will take about the same amount of time as the upgrade
    process: ie, if it takes 5 minutes, then it is likely that Synapse
    will be unresponsive for 5 minutes during the upgrade.

    If you consider an outage of this duration to be acceptable, no
    further action is necessary and you can simply start Synapse 1.12.0.

    If you would prefer to reduce the downtime, continue with the steps
    below.

2.  The easiest workaround for this issue is to manually create a new
    index before upgrading. On PostgreSQL, his can be done as follows:

    ```sql
    CREATE INDEX CONCURRENTLY tmp_upgrade_1_12_0_index
    ON state_events(room_id) WHERE type = 'm.room.create';
    ```

    The above query may take some time, but is also safe to run while
    Synapse is running.

    We assume that no SQLite users have databases large enough to be
    affected. If you *are* affected, you can run a similar query,
    omitting the `CONCURRENTLY` keyword. Note however that this
    operation may in itself cause Synapse to stop running for some time.
    Synapse admins are reminded that [SQLite is not recommended for use
    outside a test environment](postgres.md).

3.  Once the index has been created, the `SELECT` query in step 1 above
    should complete quickly. It is therefore safe to upgrade to Synapse
    1.12.0.

4.  Once Synapse 1.12.0 has successfully started and is responding to
    HTTP requests, the temporary index can be removed:

    ```sql
    DROP INDEX tmp_upgrade_1_12_0_index;
    ```

# Upgrading to v1.10.0

Synapse will now log a warning on start up if used with a PostgreSQL
database that has a non-recommended locale set.

See [Postgres](postgres.md) for details.

# Upgrading to v1.8.0

Specifying a `log_file` config option will now cause Synapse to refuse
to start, and should be replaced by with the `log_config` option.
Support for the `log_file` option was removed in v1.3.0 and has since
had no effect.

# Upgrading to v1.7.0

In an attempt to configure Synapse in a privacy preserving way, the
default behaviours of `allow_public_rooms_without_auth` and
`allow_public_rooms_over_federation` have been inverted. This means that
by default, only authenticated users querying the Client/Server API will
be able to query the room directory, and relatedly that the server will
not share room directory information with other servers over federation.

If your installation does not explicitly set these settings one way or
the other and you want either setting to be `true` then it will
necessary to update your homeserver configuration file accordingly.

For more details on the surrounding context see our
[explainer](https://matrix.org/blog/2019/11/09/avoiding-unwelcome-visitors-on-private-matrix-servers).

# Upgrading to v1.5.0

This release includes a database migration which may take several
minutes to complete if there are a large number (more than a million or
so) of entries in the `devices` table. This is only likely to a be a
problem on very large installations.

# Upgrading to v1.4.0

## New custom templates

If you have configured a custom template directory with the
`email.template_dir` option, be aware that there are new templates
regarding registration and threepid management (see below) that must be
included.

-   `registration.html` and `registration.txt`
-   `registration_success.html` and `registration_failure.html`
-   `add_threepid.html` and `add_threepid.txt`
-   `add_threepid_failure.html` and `add_threepid_success.html`

Synapse will expect these files to exist inside the configured template
directory, and **will fail to start** if they are absent. To view the
default templates, see
[synapse/res/templates](https://github.com/matrix-org/synapse/tree/master/synapse/res/templates).

## 3pid verification changes

**Note: As of this release, users will be unable to add phone numbers or
email addresses to their accounts, without changes to the Synapse
configuration. This includes adding an email address during
registration.**

It is possible for a user to associate an email address or phone number
with their account, for a number of reasons:

-   for use when logging in, as an alternative to the user id.
-   in the case of email, as an alternative contact to help with account
    recovery.
-   in the case of email, to receive notifications of missed messages.

Before an email address or phone number can be added to a user's
account, or before such an address is used to carry out a
password-reset, Synapse must confirm the operation with the owner of the
email address or phone number. It does this by sending an email or text
giving the user a link or token to confirm receipt. This process is
known as '3pid verification'. ('3pid', or 'threepid', stands for
third-party identifier, and we use it to refer to external identifiers
such as email addresses and phone numbers.)

Previous versions of Synapse delegated the task of 3pid verification to
an identity server by default. In most cases this server is `vector.im`
or `matrix.org`.

In Synapse 1.4.0, for security and privacy reasons, the homeserver will
no longer delegate this task to an identity server by default. Instead,
the server administrator will need to explicitly decide how they would
like the verification messages to be sent.

In the medium term, the `vector.im` and `matrix.org` identity servers
will disable support for delegated 3pid verification entirely. However,
in order to ease the transition, they will retain the capability for a
limited period. Delegated email verification will be disabled on Monday
2nd December 2019 (giving roughly 2 months notice). Disabling delegated
SMS verification will follow some time after that once SMS verification
support lands in Synapse.

Once delegated 3pid verification support has been disabled in the
`vector.im` and `matrix.org` identity servers, all Synapse versions that
depend on those instances will be unable to verify email and phone
numbers through them. There are no imminent plans to remove delegated
3pid verification from Sydent generally. (Sydent is the identity server
project that backs the `vector.im` and `matrix.org` instances).

### Email

Following upgrade, to continue verifying email (e.g. as part of the
registration process), admins can either:-

-   Configure Synapse to use an email server.
-   Run or choose an identity server which allows delegated email
    verification and delegate to it.

#### Configure SMTP in Synapse

To configure an SMTP server for Synapse, modify the configuration
section headed `email`, and be sure to have at least the
`smtp_host, smtp_port` and `notif_from` fields filled out.

You may also need to set `smtp_user`, `smtp_pass`, and
`require_transport_security`.

See the [sample configuration file](usage/configuration/homeserver_sample_config.md)
for more details on these settings.

#### Delegate email to an identity server

Some admins will wish to continue using email verification as part of
the registration process, but will not immediately have an appropriate
SMTP server at hand.

To this end, we will continue to support email verification delegation
via the `vector.im` and `matrix.org` identity servers for two months.
Support for delegated email verification will be disabled on Monday 2nd
December.

The `account_threepid_delegates` dictionary defines whether the
homeserver should delegate an external server (typically an [identity
server](https://matrix.org/docs/spec/identity_service/r0.2.1)) to handle
sending confirmation messages via email and SMS.

So to delegate email verification, in `homeserver.yaml`, set
`account_threepid_delegates.email` to the base URL of an identity
server. For example:

```yaml
account_threepid_delegates:
    email: https://example.com     # Delegate email sending to example.com
```

Note that `account_threepid_delegates.email` replaces the deprecated
`email.trust_identity_server_for_password_resets`: if
`email.trust_identity_server_for_password_resets` is set to `true`, and
`account_threepid_delegates.email` is not set, then the first entry in
`trusted_third_party_id_servers` will be used as the
`account_threepid_delegate` for email. This is to ensure compatibility
with existing Synapse installs that set up external server handling for
these tasks before v1.4.0. If
`email.trust_identity_server_for_password_resets` is `true` and no
trusted identity server domains are configured, Synapse will report an
error and refuse to start.

If `email.trust_identity_server_for_password_resets` is `false` or
absent and no `email` delegate is configured in
`account_threepid_delegates`, then Synapse will send email verification
messages itself, using the configured SMTP server (see above). that
type.

### Phone numbers

Synapse does not support phone-number verification itself, so the only
way to maintain the ability for users to add phone numbers to their
accounts will be by continuing to delegate phone number verification to
the `matrix.org` and `vector.im` identity servers (or another identity
server that supports SMS sending).

The `account_threepid_delegates` dictionary defines whether the
homeserver should delegate an external server (typically an [identity
server](https://matrix.org/docs/spec/identity_service/r0.2.1)) to handle
sending confirmation messages via email and SMS.

So to delegate phone number verification, in `homeserver.yaml`, set
`account_threepid_delegates.msisdn` to the base URL of an identity
server. For example:

```yaml
account_threepid_delegates:
    msisdn: https://example.com     # Delegate sms sending to example.com
```

The `matrix.org` and `vector.im` identity servers will continue to
support delegated phone number verification via SMS until such time as
it is possible for admins to configure their servers to perform phone
number verification directly. More details will follow in a future
release.

## Rolling back to v1.3.1

If you encounter problems with v1.4.0, it should be possible to roll
back to v1.3.1, subject to the following:

-   The 'room statistics' engine was heavily reworked in this release
    (see [#5971](https://github.com/matrix-org/synapse/pull/5971)),
    including significant changes to the database schema, which are not
    easily reverted. This will cause the room statistics engine to stop
    updating when you downgrade.

    The room statistics are essentially unused in v1.3.1 (in future
    versions of Synapse, they will be used to populate the room
    directory), so there should be no loss of functionality. However,
    the statistics engine will write errors to the logs, which can be
    avoided by setting the following in `homeserver.yaml`:

    ```yaml
    stats:
      enabled: false
    ```

    Don't forget to re-enable it when you upgrade again, in preparation
    for its use in the room directory!

# Upgrading to v1.2.0

Some counter metrics have been renamed, with the old names deprecated.
See [the metrics
documentation](metrics-howto.md#renaming-of-metrics--deprecation-of-old-names-in-12)
for details.

# Upgrading to v1.1.0

Synapse v1.1.0 removes support for older Python and PostgreSQL versions,
as outlined in [our deprecation
notice](https://matrix.org/blog/2019/04/08/synapse-deprecating-postgres-9-4-and-python-2-x).

## Minimum Python Version

Synapse v1.1.0 has a minimum Python requirement of Python 3.5. Python
3.6 or Python 3.7 are recommended as they have improved internal string
handling, significantly reducing memory usage.

If you use current versions of the Matrix.org-distributed Debian
packages or Docker images, action is not required.

If you install Synapse in a Python virtual environment, please see
"Upgrading to v0.34.0" for notes on setting up a new virtualenv under
Python 3.

## Minimum PostgreSQL Version

If using PostgreSQL under Synapse, you will need to use PostgreSQL 9.5
or above. Please see the [PostgreSQL
documentation](https://www.postgresql.org/docs/11/upgrading.html) for
more details on upgrading your database.

# Upgrading to v1.0

## Validation of TLS certificates

Synapse v1.0 is the first release to enforce validation of TLS
certificates for the federation API. It is therefore essential that your
certificates are correctly configured.

Note, v1.0 installations will also no longer be able to federate with
servers that have not correctly configured their certificates.

In rare cases, it may be desirable to disable certificate checking: for
example, it might be essential to be able to federate with a given
legacy server in a closed federation. This can be done in one of two
ways:-

-   Configure the global switch `federation_verify_certificates` to
    `false`.
-   Configure a whitelist of server domains to trust via
    `federation_certificate_verification_whitelist`.

See the [sample configuration file](usage/configuration/homeserver_sample_config.md)
for more details on these settings.

## Email

When a user requests a password reset, Synapse will send an email to the
user to confirm the request.

Previous versions of Synapse delegated the job of sending this email to
an identity server. If the identity server was somehow malicious or
became compromised, it would be theoretically possible to hijack an
account through this means.

Therefore, by default, Synapse v1.0 will send the confirmation email
itself. If Synapse is not configured with an SMTP server, password reset
via email will be disabled.

To configure an SMTP server for Synapse, modify the configuration
section headed `email`, and be sure to have at least the `smtp_host`,
`smtp_port` and `notif_from` fields filled out. You may also need to set
`smtp_user`, `smtp_pass`, and `require_transport_security`.

If you are absolutely certain that you wish to continue using an
identity server for password resets, set
`trust_identity_server_for_password_resets` to `true`.

See the [sample configuration file](usage/configuration/homeserver_sample_config.md)
for more details on these settings.

## New email templates

Some new templates have been added to the default template directory for the purpose of
the homeserver sending its own password reset emails. If you have configured a
custom `template_dir` in your Synapse config, these files will need to be added.

`password_reset.html` and `password_reset.txt` are HTML and plain text
templates respectively that contain the contents of what will be emailed
to the user upon attempting to reset their password via email.
`password_reset_success.html` and `password_reset_failure.html` are HTML
files that the content of which (assuming no redirect URL is set) will
be shown to the user after they attempt to click the link in the email
sent to them.

# Upgrading to v0.99.0

Please be aware that, before Synapse v1.0 is released around March 2019,
you will need to replace any self-signed certificates with those
verified by a root CA. Information on how to do so can be found at the
ACME docs.

# Upgrading to v0.34.0

1.  This release is the first to fully support Python 3. Synapse will
    now run on Python versions 3.5, or 3.6 (as well as 2.7). We
    recommend switching to Python 3, as it has been shown to give
    performance improvements.

    For users who have installed Synapse into a virtualenv, we recommend
    doing this by creating a new virtualenv. For example:

    ```sh
    virtualenv -p python3 ~/synapse/env3
    source ~/synapse/env3/bin/activate
    pip install matrix-synapse
    ```

    You can then start synapse as normal, having activated the new
    virtualenv:

    ```sh
    cd ~/synapse
    source env3/bin/activate
    synctl start
    ```

    Users who have installed from distribution packages should see the
    relevant package documentation. See below for notes on Debian
    packages.

    -   When upgrading to Python 3, you **must** make sure that your log
        files are configured as UTF-8, by adding `encoding: utf8` to the
        `RotatingFileHandler` configuration (if you have one) in your
        `<server>.log.config` file. For example, if your `log.config`
        file contains:

        ```yaml
        handlers:
          file:
            class: logging.handlers.RotatingFileHandler
            formatter: precise
            filename: homeserver.log
            maxBytes: 104857600
            backupCount: 10
            filters: [context]
          console:
            class: logging.StreamHandler
            formatter: precise
            filters: [context]
        ```

        Then you should update this to be:

        ```yaml
        handlers:
          file:
            class: logging.handlers.RotatingFileHandler
            formatter: precise
            filename: homeserver.log
            maxBytes: 104857600
            backupCount: 10
            filters: [context]
            encoding: utf8
          console:
            class: logging.StreamHandler
            formatter: precise
            filters: [context]
        ```

        There is no need to revert this change if downgrading to
        Python 2.

    We are also making available Debian packages which will run Synapse
    on Python 3. You can switch to these packages with
    `apt-get install matrix-synapse-py3`, however, please read
    [debian/NEWS](https://github.com/matrix-org/synapse/blob/release-v0.34.0/debian/NEWS)
    before doing so. The existing `matrix-synapse` packages will
    continue to use Python 2 for the time being.

2.  This release removes the `riot.im` from the default list of trusted
    identity servers.

    If `riot.im` is in your homeserver's list of
    `trusted_third_party_id_servers`, you should remove it. It was added
    in case a hypothetical future identity server was put there. If you
    don't remove it, users may be unable to deactivate their accounts.

3.  This release no longer installs the (unmaintained) Matrix Console
    web client as part of the default installation. It is possible to
    re-enable it by installing it separately and setting the
    `web_client_location` config option, but please consider switching
    to another client.

# Upgrading to v0.33.7

This release removes the example email notification templates from
`res/templates` (they are now internal to the python package). This
should only affect you if you (a) deploy your Synapse instance from a
git checkout or a github snapshot URL, and (b) have email notifications
enabled.

If you have email notifications enabled, you should ensure that
`email.template_dir` is either configured to point at a directory where
you have installed customised templates, or leave it unset to use the
default templates.

# Upgrading to v0.27.3

This release expands the anonymous usage stats sent if the opt-in
`report_stats` configuration is set to `true`. We now capture RSS memory
and cpu use at a very coarse level. This requires administrators to
install the optional `psutil` python module.

We would appreciate it if you could assist by ensuring this module is
available and `report_stats` is enabled. This will let us see if
performance changes to synapse are having an impact to the general
community.

# Upgrading to v0.15.0

If you want to use the new URL previewing API
(`/_matrix/media/r0/preview_url`) then you have to explicitly enable it
in the config and update your dependencies dependencies. See README.rst
for details.

# Upgrading to v0.11.0

This release includes the option to send anonymous usage stats to
matrix.org, and requires that administrators explicitly opt in or out by
setting the `report_stats` option to either `true` or `false`.

We would really appreciate it if you could help our project out by
reporting anonymized usage statistics from your homeserver. Only very
basic aggregate data (e.g. number of users) will be reported, but it
helps us to track the growth of the Matrix community, and helps us to
make Matrix a success, as well as to convince other networks that they
should peer with us.

# Upgrading to v0.9.0

Application services have had a breaking API change in this version.

They can no longer register themselves with a home server using the AS
HTTP API. This decision was made because a compromised application
service with free reign to register any regex in effect grants full
read/write access to the home server if a regex of `.*` is used. An
attack where a compromised AS re-registers itself with `.*` was deemed
too big of a security risk to ignore, and so the ability to register
with the HS remotely has been removed.

It has been replaced by specifying a list of application service
registrations in `homeserver.yaml`:

```yaml
app_service_config_files: ["registration-01.yaml", "registration-02.yaml"]
```

Where `registration-01.yaml` looks like:

```yaml
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
```

# Upgrading to v0.8.0

Servers which use captchas will need to add their public key to:

    static/client/register/register_config.js

      window.matrixRegistrationConfig = {
          recaptcha_public_key: "YOUR_PUBLIC_KEY"
      };

This is required in order to support registration fallback (typically
used on mobile devices).

# Upgrading to v0.7.0

New dependencies are:

-   pydenticon
-   simplejson
-   syutil
-   matrix-angular-sdk

To pull in these dependencies in a virtual env, run:

    python synapse/python_dependencies.py | xargs -n 1 pip install

# Upgrading to v0.6.0

To pull in new dependencies, run:

    python setup.py develop --user

This update includes a change to the database schema. To upgrade you
first need to upgrade the database by running:

    python scripts/upgrade_db_to_v0.6.0.py <db> <server_name> <signing_key>

Where `<db>` is the location of the database,
`<server_name>` is the server name as specified in the
synapse configuration, and `<signing_key>` is the location
of the signing key as specified in the synapse configuration.

This may take some time to complete. Failures of signatures and content
hashes can safely be ignored.

# Upgrading to v0.5.1

Depending on precisely when you installed v0.5.0 you may have ended up
with a stale release of the reference matrix webclient installed as a
python module. To uninstall it and ensure you are depending on the
latest module, please run:

    $ pip uninstall syweb

# Upgrading to v0.5.0

The webclient has been split out into a separate repository/package in
this release. Before you restart your homeserver you will need to pull
in the webclient package by running:

    python setup.py develop --user

This release completely changes the database schema and so requires
upgrading it before starting the new version of the homeserver.

The script "database-prepare-for-0.5.0.sh" should be used to upgrade
the database. This will save all user information, such as logins and
profiles, but will otherwise purge the database. This includes messages,
which rooms the home server was a member of and room alias mappings.

If you would like to keep your history, please take a copy of your
database file and ask for help in #matrix:matrix.org. The upgrade
process is, unfortunately, non trivial and requires human intervention
to resolve any resulting conflicts during the upgrade process.

Before running the command the homeserver should be first completely
shutdown. To run it, simply specify the location of the database, e.g.:

> ./scripts/database-prepare-for-0.5.0.sh "homeserver.db"

Once this has successfully completed it will be safe to restart the
homeserver. You may notice that the homeserver takes a few seconds
longer to restart than usual as it reinitializes the database.

On startup of the new version, users can either rejoin remote rooms
using room aliases or by being reinvited. Alternatively, if any other
homeserver sends a message to a room that the homeserver was previously
in the local HS will automatically rejoin the room.

# Upgrading to v0.4.0

This release needs an updated syutil version. Run:

    python setup.py develop

You will also need to upgrade your configuration as the signing key
format has changed. Run:

    python -m synapse.app.homeserver --config-path <CONFIG> --generate-config

# Upgrading to v0.3.0

This registration API now closely matches the login API. This introduces
a bit more backwards and forwards between the HS and the client, but
this improves the overall flexibility of the API. You can now GET on
/register to retrieve a list of valid registration flows. Upon choosing
one, they are submitted in the same way as login, e.g:

    {
      type: m.login.password,
      user: foo,
      password: bar
    }

The default HS supports 2 flows, with and without Identity Server email
authentication. Enabling captcha on the HS will add in an extra step to
all flows: `m.login.recaptcha` which must be completed before you can
transition to the next stage. There is a new login type:
`m.login.email.identity` which contains the `threepidCreds` key which
were previously sent in the original register request. For more
information on this, see the specification.

## Web Client

The VoIP specification has changed between v0.2.0 and v0.3.0. Users
should refresh any browser tabs to get the latest web client code. Users
on v0.2.0 of the web client will not be able to call those on v0.3.0 and
vice versa.

# Upgrading to v0.2.0

The home server now requires setting up of SSL config before it can run.
To automatically generate default config use:

    $ python synapse/app/homeserver.py \
        --server-name machine.my.domain.name \
        --bind-port 8448 \
        --config-path homeserver.config \
        --generate-config

This config can be edited if desired, for example to specify a different
SSL certificate to use. Once done you can run the home server using:

    $ python synapse/app/homeserver.py --config-path homeserver.config

See the README.rst for more information.

Also note that some config options have been renamed, including:

-   "host" to "server-name"
-   "database" to "database-path"
-   "port" to "bind-port" and "unsecure-port"

# Upgrading to v0.0.1

This release completely changes the database schema and so requires
upgrading it before starting the new version of the homeserver.

The script "database-prepare-for-0.0.1.sh" should be used to upgrade
the database. This will save all user information, such as logins and
profiles, but will otherwise purge the database. This includes messages,
which rooms the home server was a member of and room alias mappings.

Before running the command the homeserver should be first completely
shutdown. To run it, simply specify the location of the database, e.g.:

> ./scripts/database-prepare-for-0.0.1.sh "homeserver.db"

Once this has successfully completed it will be safe to restart the
homeserver. You may notice that the homeserver takes a few seconds
longer to restart than usual as it reinitializes the database.

On startup of the new version, users can either rejoin remote rooms
using room aliases or by being reinvited. Alternatively, if any other
homeserver sends a message to a room that the homeserver was previously
in the local HS will automatically rejoin the room.
