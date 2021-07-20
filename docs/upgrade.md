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

-   If Synapse was installed using [prebuilt
    packages](setup/installation.md#prebuilt-packages), you will need to follow the
    normal process for upgrading those packages.

-   If Synapse was installed from source, then:

    1.  Activate the virtualenv before upgrading. For example, if
        Synapse is installed in a virtualenv in `~/synapse/env` then
        run:

        ```bash
        source ~/synapse/env/bin/activate
        ```

    2.  If Synapse was installed using pip then upgrade to the latest
        version by running:

        ```bash
        pip install --upgrade matrix-synapse
        ```

        If Synapse was installed using git then upgrade to the latest
        version by running:

        ```bash
        git pull
        pip install --upgrade .
        ```

    3.  Restart Synapse:

        ```bash
        ./synctl restart
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
documentation](https://matrix-org.github.io/synapse/develop/modules.html#porting-an-existing-module-that-uses-the-old-interface)
to update their modules. Synapse administrators can refer to [this
documentation](https://matrix-org.github.io/synapse/develop/modules.html#using-modules)
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

In line with our [deprecation
policy](https://github.com/matrix-org/synapse/blob/release-v1.32.0/docs/deprecation_policy.md),
we've dropped support for Python 3.5 and PostgreSQL 9.5, as they are no
longer supported upstream.

This release of Synapse requires Python 3.6+ and PostgresSQL 9.6+ or
SQLite 3.22+.

## Removal of old List Accounts Admin API

The deprecated v1 "list accounts" admin API
(`GET /_synapse/admin/v1/users/<user_id>`) has been removed in this
version.

The [v2 list accounts
API](https://github.com/matrix-org/synapse/blob/master/docs/admin_api/user_admin_api.rst#list-accounts)
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
[x_forwarded]{.title-ref} option on an HTTP listener), Synapse now
expects to receive an [X-Forwarded-Proto]{.title-ref} header on incoming
HTTP requests. If it is not set, Synapse will log a warning on each
received request.

To avoid the warning, administrators using a reverse proxy should ensure
that the reverse proxy sets [X-Forwarded-Proto]{.title-ref} header to
[https]{.title-ref} or [http]{.title-ref} to indicate the protocol used
by the client.

Synapse also requires the [Host]{.title-ref} header to be preserved.

See the [reverse proxy documentation](../reverse_proxy.md), where the
example configurations have been updated to show how to set these
headers.

(Users of [Caddy](https://caddyserver.com/) are unaffected, since we
believe it sets [X-Forwarded-Proto]{.title-ref} by default.)

# Upgrading to v1.27.0

## Changes to callback URI for OAuth2 / OpenID Connect and SAML2

This version changes the URI used for callbacks from OAuth2 and SAML2
identity providers:

-   If your server is configured for single sign-on via an OpenID
    Connect or OAuth2 identity provider, you will need to add
    `[synapse public baseurl]/_synapse/client/oidc/callback` to the list
    of permitted "redirect URIs" at the identity provider.

    See the [OpenID docs](../openid.md) for more information on setting
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
([oidc_config.user_mapping_provider.module]{.title-ref} is specified and
not equal to
[synapse.handlers.oidc_handler.JinjaOidcMappingProvider]{.title-ref})
then you *must* ensure that [map_user_attributes]{.title-ref} of the
mapping provider performs some normalisation of the
[localpart]{.title-ref} returned. To match previous behaviour you can
use the [map_username_to_mxid_localpart]{.title-ref} function provided
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

The only exception is the [/admin/whois]{.title-ref} endpoint, which is
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
[structured logging
documentation](../structured_logging.md).

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

The [reverse proxy
documentation](https://github.com/matrix-org/synapse/blob/develop/docs/reverse_proxy.md)
has been updated to include reverse proxy directives for
`/_synapse/client/*` endpoints. As the user password reset flow now uses
endpoints under this prefix, **you must update your reverse proxy
configurations for user password reset to work**.

Additionally, note that the [Synapse worker documentation](https://github.com/matrix-org/synapse/blob/develop/docs/workers.md) has been updated to

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
[POST]{.title-ref} request to
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

## Docker [-py3]{.title-ref} suffix will be removed in future versions

From 10th August 2020, we will no longer publish Docker images with the
[-py3]{.title-ref} tag suffix. The images tagged with the
[-py3]{.title-ref} suffix have been identical to the non-suffixed tags
since release 0.99.0, and the suffix is obsolete.

On 10th August, we will remove the [latest-py3]{.title-ref} tag.
Existing per-release tags (such as [v1.18.0-py3]{.title-ref}) will not
be removed, but no new [-py3]{.title-ref} tags will be added.

Scripts relying on the [-py3]{.title-ref} suffix will need to be
updated.

## Redis replication is now recommended in lieu of TCP replication

When setting up worker processes, we now recommend the use of a Redis
server for replication. **The old direct TCP connection method is
deprecated and will be removed in a future release.** See
[workers](../workers.md) for more details.

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

1.  Run the following sql from a [psql]{.title-ref} or
    [sqlite3]{.title-ref} console:

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
[synapse/res/templates](synapse/res/templates) into that directory.

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
    running the following query from the [psql]{.title-ref} or
    [sqlite3]{.title-ref} console. It is safe to run it while Synapse is
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
    outside a test
    environment](https://github.com/matrix-org/synapse/blob/master/README.rst#using-postgresql).

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

See [Postgres](../postgres.md) for details.

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

See the [sample configuration file](docs/sample_config.yaml) for more
details on these settings.

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
documentation](../metrics-howto.md#renaming-of-metrics--deprecation-of-old-names-in-12)
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
certificates are correctly configured. See the
[FAQ](../MSC1711_certificates_FAQ.md) for more information.

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

See the [sample configuration file](docs/sample_config.yaml) for more
details on these settings.

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

See the [sample configuration file](docs/sample_config.yaml) for more
details on these settings.

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
verified by a root CA. Information on how to do so can be found at [the
ACME docs](../ACME.md).

For more information on configuring TLS certificates see the
[FAQ](../MSC1711_certificates_FAQ.md).

# Upgrading to v0.34.0

1.  This release is the first to fully support Python 3. Synapse will
    now run on Python versions 3.5, or 3.6 (as well as 2.7). We
    recommend switching to Python 3, as it has been shown to give
    performance improvements.

    For users who have installed Synapse into a virtualenv, we recommend
    doing this by creating a new virtualenv. For example:

        virtualenv -p python3 ~/synapse/env3
        source ~/synapse/env3/bin/activate
        pip install matrix-synapse

    You can then start synapse as normal, having activated the new
    virtualenv:

        cd ~/synapse
        source env3/bin/activate
        synctl start

    Users who have installed from distribution packages should see the
    relevant package documentation. See below for notes on Debian
    packages.

    -   When upgrading to Python 3, you **must** make sure that your log
        files are configured as UTF-8, by adding `encoding: utf8` to the
        `RotatingFileHandler` configuration (if you have one) in your
        `<server>.log.config` file. For example, if your `log.config`
        file contains:

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

        Then you should update this to be:

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
matrix.org, and requires that administrators explictly opt in or out by
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

    app_service_config_files: ["registration-01.yaml", "registration-02.yaml"]

Where `registration-01.yaml` looks like:

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

Where [<db>]{.title-ref} is the location of the database,
[<server_name>]{.title-ref} is the server name as specified in the
synapse configuration, and [<signing_key>]{.title-ref} is the location
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

The webclient has been split out into a seperate repository/pacakage in
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
