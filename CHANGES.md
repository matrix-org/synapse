# Synapse 1.91.1 (2023-09-04)

### Bugfixes

- Fix a performance regression introduced in Synapse 1.91.0 where event persistence would cause an excessive linear growth in CPU usage. ([\#16220](https://github.com/matrix-org/synapse/issues/16220))


# Synapse 1.91.0 (2023-08-30)

No significant changes since 1.91.0rc1.


# Synapse 1.91.0rc1 (2023-08-23)

### Features

- Implements an admin API to lock an user without deactivating them. Based on [MSC3939](https://github.com/matrix-org/matrix-spec-proposals/pull/3939). ([\#15870](https://github.com/matrix-org/synapse/issues/15870))
- Implements a task scheduler for	resumable potentially long running tasks. ([\#15891](https://github.com/matrix-org/synapse/issues/15891))
- Allow specifying `client_secret_path` as alternative to `client_secret` for OIDC providers. This avoids leaking the client secret in the homeserver config. Contributed by @Ma27. ([\#16030](https://github.com/matrix-org/synapse/issues/16030))
- Allow customising the IdP display name, icon, and brand for SAML and CAS providers (in addition to OIDC provider). ([\#16094](https://github.com/matrix-org/synapse/issues/16094))
- Add an `admins` query parameter to the [List Accounts](https://matrix-org.github.io/synapse/v1.91/admin_api/user_admin_api.html#list-accounts) [admin API](https://matrix-org.github.io/synapse/v1.91/usage/administration/admin_api/index.html), to include only admins or to exclude admins in user queries. ([\#16114](https://github.com/matrix-org/synapse/issues/16114))

### Bugfixes

- Fix long-standing bug where concurrent requests to change a user's push rules could cause a deadlock. Contributed by Nick @ Beeper (@fizzadar). ([\#16052](https://github.com/matrix-org/synapse/issues/16052))
- Fix a long-standing bu in `/sync` where timeout=0 does not skip caching, resulting in slow calls in cases where there are no new changes. Contributed by @PlasmaIntec. ([\#16080](https://github.com/matrix-org/synapse/issues/16080))
- Fix performance of state resolutions for large, old rooms that did not have the full auth chain persisted. ([\#16116](https://github.com/matrix-org/synapse/issues/16116))
- Filter out user agent references to the sliding sync proxy and rust-sdk from the user_daily_visits table to ensure that Element X can be represented fully. ([\#16124](https://github.com/matrix-org/synapse/issues/16124))
- User constent and 3-PID changes capability cannot be enabled when using experimental [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861) support. ([\#16127](https://github.com/matrix-org/synapse/issues/16127), [\#16134](https://github.com/matrix-org/synapse/issues/16134))
- Fix a rare race that could block new events from being sent for up to two minutes. Introduced in v1.90.0. ([\#16133](https://github.com/matrix-org/synapse/issues/16133), [\#16169](https://github.com/matrix-org/synapse/issues/16169))
- Fix performance degredation when there are a lot of in-flight replication requests. ([\#16148](https://github.com/matrix-org/synapse/issues/16148))
- Fix a bug introduced in 1.87 where synapse would send an excessive amount of federation requests to servers which have been offline for a long time. Contributed by Nico. ([\#16156](https://github.com/matrix-org/synapse/issues/16156), [\#16164](https://github.com/matrix-org/synapse/issues/16164))

### Improved Documentation

- Structured logging docs: add a link to explain the ELK stack ([\#16091](https://github.com/matrix-org/synapse/issues/16091))

### Internal Changes

- Update dehydrated devices implementation. ([\#16010](https://github.com/matrix-org/synapse/issues/16010))
- Fix database performance of read/write worker locks. ([\#16061](https://github.com/matrix-org/synapse/issues/16061))
- Fix building the nix development environment on MacOS systems. ([\#16063](https://github.com/matrix-org/synapse/issues/16063))
- Override global statement timeout when creating indexes in Postgres. ([\#16085](https://github.com/matrix-org/synapse/issues/16085))
- Fix the type annotation on `run_db_interaction` in the Module API. ([\#16089](https://github.com/matrix-org/synapse/issues/16089))
- Clean-up the presence code. ([\#16092](https://github.com/matrix-org/synapse/issues/16092))
- Run `pyupgrade` for Python 3.8+. ([\#16110](https://github.com/matrix-org/synapse/issues/16110))
- Rename pagination and purge locks and add comments to explain why they exist and how they work. ([\#16112](https://github.com/matrix-org/synapse/issues/16112))
- Attempt to fix the twisted trunk job. ([\#16115](https://github.com/matrix-org/synapse/issues/16115))
- Cache token introspection response from OIDC provider. ([\#16117](https://github.com/matrix-org/synapse/issues/16117))
- Add cache to `get_server_keys_json_for_remote`. ([\#16123](https://github.com/matrix-org/synapse/issues/16123))
- Add an admin endpoint to allow authorizing server to signal token revocations. ([\#16125](https://github.com/matrix-org/synapse/issues/16125))
- Add response time metrics for introspection requests for delegated auth. ([\#16131](https://github.com/matrix-org/synapse/issues/16131))
- MSC3861: allow impersonation by an admin user using `_oidc_admin_impersonate_user_id` query parameter. ([\#16132](https://github.com/matrix-org/synapse/issues/16132))
- Increase performance of read/write locks. ([\#16149](https://github.com/matrix-org/synapse/issues/16149))
- Improve presence tests. ([\#16150](https://github.com/matrix-org/synapse/issues/16150), [\#16151](https://github.com/matrix-org/synapse/issues/16151), [\#16158](https://github.com/matrix-org/synapse/issues/16158))
- Raised the poetry-core version cap to 1.7.0. ([\#16152](https://github.com/matrix-org/synapse/issues/16152))
- Fix assertion in user directory unit tests. ([\#16157](https://github.com/matrix-org/synapse/issues/16157))
- Reduce scope of locks when paginating to alleviate DB contention. ([\#16159](https://github.com/matrix-org/synapse/issues/16159))
- Reduce DB contention on worker locks. ([\#16160](https://github.com/matrix-org/synapse/issues/16160))
- Task scheduler: mark task as active if we are scheduling as soon as possible. ([\#16165](https://github.com/matrix-org/synapse/issues/16165))

### Updates to locked dependencies

* Bump click from 8.1.6 to 8.1.7. ([\#16145](https://github.com/matrix-org/synapse/issues/16145))
* Bump gitpython from 3.1.31 to 3.1.32. ([\#16103](https://github.com/matrix-org/synapse/issues/16103))
* Bump ijson from 3.2.1 to 3.2.3. ([\#16143](https://github.com/matrix-org/synapse/issues/16143))
* Bump isort from 5.11.5 to 5.12.0. ([\#16108](https://github.com/matrix-org/synapse/issues/16108))
* Bump log from 0.4.19 to 0.4.20. ([\#16109](https://github.com/matrix-org/synapse/issues/16109))
* Bump pygithub from 1.59.0 to 1.59.1. ([\#16144](https://github.com/matrix-org/synapse/issues/16144))
* Bump sentry-sdk from 1.28.1 to 1.29.2. ([\#16142](https://github.com/matrix-org/synapse/issues/16142))
* Bump serde from 1.0.183 to 1.0.184. ([\#16139](https://github.com/matrix-org/synapse/issues/16139))
* Bump txredisapi from 1.4.9 to 1.4.10. ([\#16107](https://github.com/matrix-org/synapse/issues/16107))
* Bump types-bleach from 6.0.0.3 to 6.0.0.4. ([\#16106](https://github.com/matrix-org/synapse/issues/16106))
* Bump types-pillow from 10.0.0.1 to 10.0.0.2. ([\#16105](https://github.com/matrix-org/synapse/issues/16105))
* Bump types-pyopenssl from 23.2.0.1 to 23.2.0.2. ([\#16146](https://github.com/matrix-org/synapse/issues/16146))

# Synapse 1.91.0rc1 (2023-08-23)

### Features

- Implements an admin API to lock an user without deactivating them. Based on [MSC3939](https://github.com/matrix-org/matrix-spec-proposals/pull/3939). ([\#15870](https://github.com/matrix-org/synapse/issues/15870))
- Allow specifying `client_secret_path` as alternative to `client_secret` for OIDC providers. This avoids leaking the client secret in the homeserver config. Contributed by @Ma27. ([\#16030](https://github.com/matrix-org/synapse/issues/16030))
- Allow customising the IdP display name, icon, and brand for SAML and CAS providers (in addition to OIDC provider). ([\#16094](https://github.com/matrix-org/synapse/issues/16094))
- Add an `admins` query parameter to the [List Accounts](https://matrix-org.github.io/synapse/v1.91/admin_api/user_admin_api.html#list-accounts) [admin API](https://matrix-org.github.io/synapse/v1.91/usage/administration/admin_api/index.html), to include only admins or to exclude admins in user queries. ([\#16114](https://github.com/matrix-org/synapse/issues/16114))

### Bugfixes

- Fix long-standing bug where concurrent requests to change a user's push rules could cause a deadlock. Contributed by Nick @ Beeper (@fizzadar). ([\#16052](https://github.com/matrix-org/synapse/issues/16052))
- Fix a long-standing bug in `/sync` where timeout=0 does not skip caching, resulting in slow calls in cases where there are no new changes. Contributed by @PlasmaIntec. ([\#16080](https://github.com/matrix-org/synapse/issues/16080))
- Fix performance of state resolutions for large, old rooms that did not have the full auth chain persisted. ([\#16116](https://github.com/matrix-org/synapse/issues/16116))
- Filter out user agent references to the sliding sync proxy and rust-sdk from the `user_daily_visits` table to ensure that Element X can be represented fully. ([\#16124](https://github.com/matrix-org/synapse/issues/16124))
- User constent and third-party ID changes capability cannot be enabled when using experimental [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861) support. ([\#16127](https://github.com/matrix-org/synapse/issues/16127), [\#16134](https://github.com/matrix-org/synapse/issues/16134))
- Fix a rare race that could block new events from being sent for up to two minutes. Introduced in v1.90.0. ([\#16133](https://github.com/matrix-org/synapse/issues/16133), [\#16169](https://github.com/matrix-org/synapse/issues/16169))
- Fix performance degredation when there are a lot of in-flight replication requests. ([\#16148](https://github.com/matrix-org/synapse/issues/16148))
- Fix a bug introduced in 1.87 where synapse would send an excessive amount of federation requests to servers which have been offline for a long time. Contributed by Nico. ([\#16156](https://github.com/matrix-org/synapse/issues/16156), [\#16164](https://github.com/matrix-org/synapse/issues/16164))

### Improved Documentation

- Structured logging docs: add a link to explain the ELK stack ([\#16091](https://github.com/matrix-org/synapse/issues/16091))

### Internal Changes

- Update dehydrated devices implementation. ([\#16010](https://github.com/matrix-org/synapse/issues/16010))
- Fix database performance of read/write worker locks. ([\#16061](https://github.com/matrix-org/synapse/issues/16061))
- Fix building the nix development environment on MacOS systems. ([\#16063](https://github.com/matrix-org/synapse/issues/16063))
- Override global statement timeout when creating indexes in Postgres. ([\#16085](https://github.com/matrix-org/synapse/issues/16085))
- Fix the type annotation on `run_db_interaction` in the Module API. ([\#16089](https://github.com/matrix-org/synapse/issues/16089))
- Clean-up the presence code. ([\#16092](https://github.com/matrix-org/synapse/issues/16092))
- Run `pyupgrade` for Python 3.8+. ([\#16110](https://github.com/matrix-org/synapse/issues/16110))
- Rename pagination and purge locks and add comments to explain why they exist and how they work. ([\#16112](https://github.com/matrix-org/synapse/issues/16112))
- Attempt to fix the twisted trunk job. ([\#16115](https://github.com/matrix-org/synapse/issues/16115))
- Cache token introspection response from OIDC provider. ([\#16117](https://github.com/matrix-org/synapse/issues/16117))
- Add cache to `get_server_keys_json_for_remote`. ([\#16123](https://github.com/matrix-org/synapse/issues/16123))
- Add an admin endpoint to allow authorizing server to signal token revocations. ([\#16125](https://github.com/matrix-org/synapse/issues/16125))
- Add response time metrics for introspection requests for delegated auth. ([\#16131](https://github.com/matrix-org/synapse/issues/16131))
- [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861): allow impersonation by an admin user using `_oidc_admin_impersonate_user_id` query parameter. ([\#16132](https://github.com/matrix-org/synapse/issues/16132))
- Increase performance of read/write locks. ([\#16149](https://github.com/matrix-org/synapse/issues/16149))
- Improve presence tests. ([\#16150](https://github.com/matrix-org/synapse/issues/16150), [\#16151](https://github.com/matrix-org/synapse/issues/16151), [\#16158](https://github.com/matrix-org/synapse/issues/16158))
- Raised the poetry-core version cap to 1.7.0. ([\#16152](https://github.com/matrix-org/synapse/issues/16152))
- Fix assertion in user directory unit tests. ([\#16157](https://github.com/matrix-org/synapse/issues/16157))
- Reduce scope of locks when paginating to alleviate DB contention. ([\#16159](https://github.com/matrix-org/synapse/issues/16159))
- Reduce DB contention on worker locks. ([\#16160](https://github.com/matrix-org/synapse/issues/16160))
- Task scheduler: mark task as active if we are scheduling as soon as possible. ([\#16165](https://github.com/matrix-org/synapse/issues/16165))
- Implements a task scheduler for	resumable potentially long running tasks. ([\#15891](https://github.com/matrix-org/synapse/issues/15891))

### Updates to locked dependencies

* Bump click from 8.1.6 to 8.1.7. ([\#16145](https://github.com/matrix-org/synapse/issues/16145))
* Bump gitpython from 3.1.31 to 3.1.32. ([\#16103](https://github.com/matrix-org/synapse/issues/16103))
* Bump ijson from 3.2.1 to 3.2.3. ([\#16143](https://github.com/matrix-org/synapse/issues/16143))
* Bump isort from 5.11.5 to 5.12.0. ([\#16108](https://github.com/matrix-org/synapse/issues/16108))
* Bump log from 0.4.19 to 0.4.20. ([\#16109](https://github.com/matrix-org/synapse/issues/16109))
* Bump pygithub from 1.59.0 to 1.59.1. ([\#16144](https://github.com/matrix-org/synapse/issues/16144))
* Bump sentry-sdk from 1.28.1 to 1.29.2. ([\#16142](https://github.com/matrix-org/synapse/issues/16142))
* Bump serde from 1.0.183 to 1.0.184. ([\#16139](https://github.com/matrix-org/synapse/issues/16139))
* Bump txredisapi from 1.4.9 to 1.4.10. ([\#16107](https://github.com/matrix-org/synapse/issues/16107))
* Bump types-bleach from 6.0.0.3 to 6.0.0.4. ([\#16106](https://github.com/matrix-org/synapse/issues/16106))
* Bump types-pillow from 10.0.0.1 to 10.0.0.2. ([\#16105](https://github.com/matrix-org/synapse/issues/16105))
* Bump types-pyopenssl from 23.2.0.1 to 23.2.0.2. ([\#16146](https://github.com/matrix-org/synapse/issues/16146))

# Synapse 1.90.0 (2023-08-15)

No significant changes since 1.90.0rc1.


# Synapse 1.90.0rc1 (2023-08-08)

### Features

- Scope transaction IDs to devices (implement [MSC3970](https://github.com/matrix-org/matrix-spec-proposals/pull/3970)). ([\#15629](https://github.com/matrix-org/synapse/issues/15629))
- Remove old rows from the `cache_invalidation_stream_by_instance` table automatically (this table is unused in SQLite). ([\#15868](https://github.com/matrix-org/synapse/issues/15868))

### Bugfixes

- Fix a long-standing bug where purging history and paginating simultaneously could lead to database corruption when using workers. ([\#15791](https://github.com/matrix-org/synapse/issues/15791))
- Fix a long-standing bug where profile endpoint returned a 404 when the user's display name was empty. ([\#16012](https://github.com/matrix-org/synapse/issues/16012))
- Fix a long-standing bug where the `synapse_port_db` failed to configure sequences for application services and partial stated rooms. ([\#16043](https://github.com/matrix-org/synapse/issues/16043))
- Fix long-standing bug with deletion in dehydrated devices v2. ([\#16046](https://github.com/matrix-org/synapse/issues/16046))

### Updates to the Docker image

- Add `org.opencontainers.image.version` labels to Docker containers [published by Matrix.org](https://hub.docker.com/r/matrixdotorg/synapse). Contributed by Mo Balaa. ([\#15972](https://github.com/matrix-org/synapse/issues/15972), [\#16009](https://github.com/matrix-org/synapse/issues/16009))

### Improved Documentation

- Add a internal documentation page describing the ["streams" used within Synapse](https://matrix-org.github.io/synapse/v1.90/development/synapse_architecture/streams.html). ([\#16015](https://github.com/matrix-org/synapse/issues/16015))
- Clarify comment on the keys/upload over replication enpoint. ([\#16016](https://github.com/matrix-org/synapse/issues/16016))
- Do not expose Admin API in caddy reverse proxy example. Contributed by @NilsIrl. ([\#16027](https://github.com/matrix-org/synapse/issues/16027))

### Deprecations and Removals

- Remove support for legacy application service paths. ([\#15964](https://github.com/matrix-org/synapse/issues/15964))
- Move support for application service query parameter authorization behind a configuration option. ([\#16017](https://github.com/matrix-org/synapse/issues/16017))

### Internal Changes

- Update SQL queries to inline boolean parameters as supported in SQLite 3.27. ([\#15525](https://github.com/matrix-org/synapse/issues/15525))
- Allow for the configuration of the backoff algorithm for federation destinations. ([\#15754](https://github.com/matrix-org/synapse/issues/15754))
- Allow modules to check whether the current worker is configured to run background tasks. ([\#15991](https://github.com/matrix-org/synapse/issues/15991))
- Update support for [MSC3958](https://github.com/matrix-org/matrix-spec-proposals/pull/3958) to match the latest revision of the MSC. ([\#15992](https://github.com/matrix-org/synapse/issues/15992))
- Allow modules to schedule delayed background calls. ([\#15993](https://github.com/matrix-org/synapse/issues/15993))
- Properly overwrite the `redacts` content-property for forwards-compatibility with room versions 1 through 10. ([\#16013](https://github.com/matrix-org/synapse/issues/16013))
- Fix building the nix development environment on MacOS systems. ([\#16019](https://github.com/matrix-org/synapse/issues/16019))
- Remove leading and trailing spaces when setting a display name. ([\#16031](https://github.com/matrix-org/synapse/issues/16031))
- Combine duplicated code. ([\#16023](https://github.com/matrix-org/synapse/issues/16023))
- Collect additional metrics from `ResponseCache` for eviction. ([\#16028](https://github.com/matrix-org/synapse/issues/16028))
- Fix endpoint improperly declaring support for MSC3814. ([\#16068](https://github.com/matrix-org/synapse/issues/16068))
- Drop backwards compat hack for event serialization. ([\#16069](https://github.com/matrix-org/synapse/issues/16069))

### Updates to locked dependencies

* Update PyYAML to 6.0.1. ([\#16011](https://github.com/matrix-org/synapse/issues/16011))
* Bump cryptography from 41.0.2 to 41.0.3. ([\#16048](https://github.com/matrix-org/synapse/issues/16048))
* Bump furo from 2023.5.20 to 2023.7.26. ([\#16077](https://github.com/matrix-org/synapse/issues/16077))
* Bump immutabledict from 2.2.4 to 3.0.0. ([\#16034](https://github.com/matrix-org/synapse/issues/16034))
* Update certifi to 2023.7.22 and pygments to 2.15.1. ([\#16044](https://github.com/matrix-org/synapse/issues/16044))
* Bump jsonschema from 4.18.3 to 4.19.0. ([\#16081](https://github.com/matrix-org/synapse/issues/16081))
* Bump phonenumbers from 8.13.14 to 8.13.18. ([\#16076](https://github.com/matrix-org/synapse/issues/16076))
* Bump regex from 1.9.1 to 1.9.3. ([\#16073](https://github.com/matrix-org/synapse/issues/16073))
* Bump serde from 1.0.171 to 1.0.175. ([\#15982](https://github.com/matrix-org/synapse/issues/15982))
* Bump serde from 1.0.175 to 1.0.179. ([\#16033](https://github.com/matrix-org/synapse/issues/16033))
* Bump serde from 1.0.179 to 1.0.183. ([\#16074](https://github.com/matrix-org/synapse/issues/16074))
* Bump serde_json from 1.0.103 to 1.0.104. ([\#16032](https://github.com/matrix-org/synapse/issues/16032))
* Bump service-identity from 21.1.0 to 23.1.0. ([\#16038](https://github.com/matrix-org/synapse/issues/16038))
* Bump types-commonmark from 0.9.2.3 to 0.9.2.4. ([\#16037](https://github.com/matrix-org/synapse/issues/16037))
* Bump types-jsonschema from 4.17.0.8 to 4.17.0.10. ([\#16036](https://github.com/matrix-org/synapse/issues/16036))
* Bump types-netaddr from 0.8.0.8 to 0.8.0.9. ([\#16035](https://github.com/matrix-org/synapse/issues/16035))
* Bump types-opentracing from 2.4.10.5 to 2.4.10.6. ([\#16078](https://github.com/matrix-org/synapse/issues/16078))
* Bump types-setuptools from 68.0.0.0 to 68.0.0.3. ([\#16079](https://github.com/matrix-org/synapse/issues/16079))

# Synapse 1.89.0 (2023-08-01)

No significant changes since 1.89.0rc1.


# Synapse 1.89.0rc1 (2023-07-25)

### Features

- Add Unix Socket support for HTTP Replication Listeners. [Document and provide usage instructions](https://matrix-org.github.io/synapse/v1.89/usage/configuration/config_documentation.html#listeners) for utilizing Unix sockets in Synapse. Contributed by Jason Little. ([\#15708](https://github.com/matrix-org/synapse/issues/15708), [\#15924](https://github.com/matrix-org/synapse/issues/15924))
- Allow `+` in Matrix IDs, per [MSC4009](https://github.com/matrix-org/matrix-spec-proposals/pull/4009). ([\#15911](https://github.com/matrix-org/synapse/issues/15911))
- Support room version 11 from [MSC3820](https://github.com/matrix-org/matrix-spec-proposals/pull/3820). ([\#15912](https://github.com/matrix-org/synapse/issues/15912))
- Allow configuring the set of workers to proxy outbound federation traffic through via `outbound_federation_restricted_to`. ([\#15913](https://github.com/matrix-org/synapse/issues/15913), [\#15969](https://github.com/matrix-org/synapse/issues/15969))
- Implement [MSC3814](https://github.com/matrix-org/matrix-spec-proposals/pull/3814), dehydrated devices v2/shrivelled sessions and move [MSC2697](https://github.com/matrix-org/matrix-spec-proposals/pull/2697) behind a config flag. Contributed by Nico from Famedly, H-Shay and poljar. ([\#15929](https://github.com/matrix-org/synapse/issues/15929))

### Bugfixes

- Fix a long-standing bug where remote invites weren't correctly pushed. ([\#15820](https://github.com/matrix-org/synapse/issues/15820))
- Fix background schema updates failing over a large upgrade gap. ([\#15887](https://github.com/matrix-org/synapse/issues/15887))
- Fix a bug introduced in 1.86.0 where Synapse starting with an empty `experimental_features` configuration setting. ([\#15925](https://github.com/matrix-org/synapse/issues/15925))
- Fixed deploy annotations in the provided Grafana dashboard config, so that it shows for any homeserver and not just matrix.org. Contributed by @wrjlewis. ([\#15957](https://github.com/matrix-org/synapse/issues/15957))
- Ensure a long state res does not starve CPU by occasionally yielding to the reactor. ([\#15960](https://github.com/matrix-org/synapse/issues/15960))
- Properly handle redactions of creation events. ([\#15973](https://github.com/matrix-org/synapse/issues/15973))
- Fix a bug where resyncing stale device lists could block responding to federation transactions, and thus delay receiving new data from the remote server. ([\#15975](https://github.com/matrix-org/synapse/issues/15975))

### Improved Documentation

- Better clarify how to run a worker instance (pass both configs). ([\#15921](https://github.com/matrix-org/synapse/issues/15921))
- Improve [the documentation](https://matrix-org.github.io/synapse/v1.89/admin_api/user_admin_api.html#login-as-a-user) for the login as a user admin API. ([\#15938](https://github.com/matrix-org/synapse/issues/15938))
- Fix broken Arch Linux package link. Contributed by @SnipeXandrej. ([\#15981](https://github.com/matrix-org/synapse/issues/15981))

### Deprecations and Removals

- Remove support for calling the `/register` endpoint with an unspecced `user` property for application services. ([\#15928](https://github.com/matrix-org/synapse/issues/15928))

### Internal Changes

- Mark `get_user_in_directory` private since it is only used in tests. Also remove the cache from it. ([\#15884](https://github.com/matrix-org/synapse/issues/15884))
- Document which Python version runs on a given Linux distribution so we can more easily clean up later. ([\#15909](https://github.com/matrix-org/synapse/issues/15909))
- Add details to warning in log when we fail to fetch an alias. ([\#15922](https://github.com/matrix-org/synapse/issues/15922))
- Remove unneeded `__init__`. ([\#15926](https://github.com/matrix-org/synapse/issues/15926))
- Fix bug with read/write lock implementation. This is currently unused so has no observable effects. ([\#15933](https://github.com/matrix-org/synapse/issues/15933), [\#15958](https://github.com/matrix-org/synapse/issues/15958))
- Unbreak the nix development environment by pinning the Rust version to 1.70.0. ([\#15940](https://github.com/matrix-org/synapse/issues/15940))
- Update presence metrics to differentiate remote vs local users. ([\#15952](https://github.com/matrix-org/synapse/issues/15952))
- Stop reading from column `user_id` of table `profiles`. ([\#15955](https://github.com/matrix-org/synapse/issues/15955))
- Build packages for Debian Trixie. ([\#15961](https://github.com/matrix-org/synapse/issues/15961))
- Reduce the amount of state we pull out. ([\#15968](https://github.com/matrix-org/synapse/issues/15968))
- Speed up updating state in large rooms. ([\#15971](https://github.com/matrix-org/synapse/issues/15971))

### Updates to locked dependencies

* Bump anyhow from 1.0.71 to 1.0.72. ([\#15949](https://github.com/matrix-org/synapse/issues/15949))
* Bump click from 8.1.3 to 8.1.6. ([\#15984](https://github.com/matrix-org/synapse/issues/15984))
* Bump cryptography from 41.0.1 to 41.0.2. ([\#15943](https://github.com/matrix-org/synapse/issues/15943))
* Bump jsonschema from 4.17.3 to 4.18.3. ([\#15948](https://github.com/matrix-org/synapse/issues/15948))
* Bump pillow from 9.4.0 to 10.0.0. ([\#15986](https://github.com/matrix-org/synapse/issues/15986))
* Bump prometheus-client from 0.17.0 to 0.17.1. ([\#15945](https://github.com/matrix-org/synapse/issues/15945))
* Bump pydantic from 1.10.10 to 1.10.11. ([\#15946](https://github.com/matrix-org/synapse/issues/15946))
* Bump pygithub from 1.58.2 to 1.59.0. ([\#15834](https://github.com/matrix-org/synapse/issues/15834))
* Bump pyo3-log from 0.8.2 to 0.8.3. ([\#15951](https://github.com/matrix-org/synapse/issues/15951))
* Bump sentry-sdk from 1.26.0 to 1.28.1. ([\#15985](https://github.com/matrix-org/synapse/issues/15985))
* Bump serde_json from 1.0.100 to 1.0.103. ([\#15950](https://github.com/matrix-org/synapse/issues/15950))
* Bump types-pillow from 9.5.0.4 to 10.0.0.1. ([\#15932](https://github.com/matrix-org/synapse/issues/15932))
* Bump types-requests from 2.31.0.1 to 2.31.0.2. ([\#15983](https://github.com/matrix-org/synapse/issues/15983))
* Bump typing-extensions from 4.5.0 to 4.7.1. ([\#15947](https://github.com/matrix-org/synapse/issues/15947))

# Synapse 1.88.0 (2023-07-18)

This release
 - raises the minimum supported version of Python to 3.8, as Python 3.7 is now [end-of-life](https://devguide.python.org/versions/), and
 - removes deprecated config options related to worker deployment.

See [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.88/docs/upgrade.md#upgrading-to-v1880) for more information.


### Bugfixes

- Revert "Stop writing to column `user_id` of tables `profiles` and `user_filters`", which was introduced in Synapse 1.88.0rc1. ([\#15953](https://github.com/matrix-org/synapse/issues/15953))


# Synapse 1.88.0rc1 (2023-07-11)

### Features

- Add `not_user_type` param to the [list accounts admin API](https://matrix-org.github.io/synapse/v1.88/admin_api/user_admin_api.html#list-accounts). ([\#15844](https://github.com/matrix-org/synapse/issues/15844))

### Bugfixes

- Pin `pydantic` to `^=1.7.4` to avoid backwards-incompatible API changes from the 2.0.0 release.
  Contributed by @PaarthShah. ([\#15862](https://github.com/matrix-org/synapse/issues/15862))
- Correctly resize thumbnails with pillow version >=10. ([\#15876](https://github.com/matrix-org/synapse/issues/15876))

### Improved Documentation

- Fixed header levels on the [Admin API "Users"](https://matrix-org.github.io/synapse/v1.87/admin_api/user_admin_api.html) documentation page. Contributed by @sumnerevans at @beeper. ([\#15852](https://github.com/matrix-org/synapse/issues/15852))
- Remove deprecated `worker_replication_host`, `worker_replication_http_port` and `worker_replication_http_tls` configuration options. ([\#15872](https://github.com/matrix-org/synapse/issues/15872))

### Deprecations and Removals

- **Remove deprecated `worker_replication_host`, `worker_replication_http_port` and `worker_replication_http_tls` configuration options.** See the [upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.88/docs/upgrade.md#removal-of-worker_replication_-settings) for more details. ([\#15860](https://github.com/matrix-org/synapse/issues/15860))
- Remove support for Python 3.7 and hence for Debian Buster. ([\#15851](https://github.com/matrix-org/synapse/issues/15851), [\#15892](https://github.com/matrix-org/synapse/issues/15892), [\#15893](https://github.com/matrix-org/synapse/issues/15893), [\#15917](https://github.com/matrix-org/synapse/pull/15917))

### Internal Changes

- Add foreign key constraint to `event_forward_extremities`. ([\#15751](https://github.com/matrix-org/synapse/issues/15751), [\#15907](https://github.com/matrix-org/synapse/issues/15907))
- Add read/write style cross-worker locks. ([\#15782](https://github.com/matrix-org/synapse/issues/15782))
- Stop writing to column `user_id` of tables `profiles` and `user_filters`. ([\#15787](https://github.com/matrix-org/synapse/issues/15787))
- Use lower isolation level when cleaning old presence stream data to avoid serialization errors. ([\#15826](https://github.com/matrix-org/synapse/issues/15826))
- Add tracing to media `/upload` code paths. ([\#15850](https://github.com/matrix-org/synapse/issues/15850), [\#15888](https://github.com/matrix-org/synapse/issues/15888))
- Add a timeout that aborts any Postgres statement taking more than 1 hour. ([\#15853](https://github.com/matrix-org/synapse/issues/15853))
- Fix the `devenv up` configuration which was ignoring the config overrides. ([\#15854](https://github.com/matrix-org/synapse/issues/15854))
- Optimised cleanup of old entries in `device_lists_stream`. ([\#15861](https://github.com/matrix-org/synapse/issues/15861))
- Update the Matrix clients link in the _It works! Synapse is running_ landing page. ([\#15874](https://github.com/matrix-org/synapse/issues/15874))
- Fix building Synapse with the nightly Rust compiler. ([\#15906](https://github.com/matrix-org/synapse/issues/15906))
- Add `Server` to Access-Control-Expose-Headers header. ([\#15908](https://github.com/matrix-org/synapse/issues/15908))

### Updates to locked dependencies

* Bump authlib from 1.2.0 to 1.2.1. ([\#15864](https://github.com/matrix-org/synapse/issues/15864))
* Bump importlib-metadata from 6.6.0 to 6.7.0. ([\#15865](https://github.com/matrix-org/synapse/issues/15865))
* Bump lxml from 4.9.2 to 4.9.3. ([\#15897](https://github.com/matrix-org/synapse/issues/15897))
* Bump regex from 1.8.4 to 1.9.1. ([\#15902](https://github.com/matrix-org/synapse/issues/15902))
* Bump ruff from 0.0.275 to 0.0.277. ([\#15900](https://github.com/matrix-org/synapse/issues/15900))
* Bump sentry-sdk from 1.25.1 to 1.26.0. ([\#15867](https://github.com/matrix-org/synapse/issues/15867))
* Bump serde_json from 1.0.99 to 1.0.100. ([\#15901](https://github.com/matrix-org/synapse/issues/15901))
* Bump types-pyopenssl from 23.2.0.0 to 23.2.0.1. ([\#15866](https://github.com/matrix-org/synapse/issues/15866))

# Synapse 1.87.0 (2023-07-04)

Please note that this will be the last release of Synapse that is compatible with
Python 3.7 and earlier.
This is due to Python 3.7 now having reached End of Life; see our [deprecation policy](https://matrix-org.github.io/synapse/v1.87/deprecation_policy.html)
for more details.

### Bugfixes

- Pin `pydantic` to `^1.7.4` to avoid backwards-incompatible API changes from the 2.0.0 release.
  Resolves https://github.com/matrix-org/synapse/issues/15858.
  Contributed by @PaarthShah. ([\#15862](https://github.com/matrix-org/synapse/issues/15862))

### Internal Changes

- Split out 2022 changes from the changelog so the rendered version in GitHub doesn't timeout as much. ([\#15846](https://github.com/matrix-org/synapse/issues/15846))


# Synapse 1.87.0rc1 (2023-06-27)

### Features

- Improve `/messages` response time by avoiding backfill when we already have messages to return. ([\#15737](https://github.com/matrix-org/synapse/issues/15737))
- Add spam checker module API for logins. ([\#15838](https://github.com/matrix-org/synapse/issues/15838))

### Bugfixes

- Fix a long-standing bug where media files were served in an unsafe manner. Contributed by @joshqou. ([\#15680](https://github.com/matrix-org/synapse/issues/15680))
- Avoid invalidating a cache that was just prefilled. ([\#15758](https://github.com/matrix-org/synapse/issues/15758))
- Fix requesting multiple keys at once over federation, related to [MSC3983](https://github.com/matrix-org/matrix-spec-proposals/pull/3983). ([\#15770](https://github.com/matrix-org/synapse/issues/15770))
- Fix joining rooms through aliases where the alias server isn't a real homeserver. Contributed by @tulir @ Beeper. ([\#15776](https://github.com/matrix-org/synapse/issues/15776))
- Fix a bug in push rules handling leading to an invalid (per spec) `is_user_mention` rule sent to clients. Also fix wrong rule names for `is_user_mention` and `is_room_mention`. ([\#15781](https://github.com/matrix-org/synapse/issues/15781))
- Fix a bug introduced in 1.57.0 where the wrong table would be locked on updating database rows when using SQLite as the database backend. ([\#15788](https://github.com/matrix-org/synapse/issues/15788))
- Fix Sytest environmental variable evaluation in CI. ([\#15804](https://github.com/matrix-org/synapse/issues/15804))
- Fix forgotten rooms missing from initial sync after rejoining them. Contributed by Nico from Famedly. ([\#15815](https://github.com/matrix-org/synapse/issues/15815))
- Fix sqlite `user_filters` upgrade introduced in v1.86.0. ([\#15817](https://github.com/matrix-org/synapse/issues/15817))

### Improved Documentation

- Document `looping_call()` functionality that will wait for the given function to finish before scheduling another. ([\#15772](https://github.com/matrix-org/synapse/issues/15772))
- Fix a typo in the [Admin API](https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/index.html). ([\#15805](https://github.com/matrix-org/synapse/issues/15805))
- Fix typo in MSC number in faster remote room join architecture doc. ([\#15812](https://github.com/matrix-org/synapse/issues/15812))

### Deprecations and Removals

- Remove experimental [MSC2716](https://github.com/matrix-org/matrix-spec-proposals/pull/2716) implementation to incrementally import history into existing rooms. ([\#15748](https://github.com/matrix-org/synapse/issues/15748))

### Internal Changes

- Replace `EventContext` fields `prev_group` and `delta_ids` with field `state_group_deltas`. ([\#15233](https://github.com/matrix-org/synapse/issues/15233))
- Regularly try to send transactions to other servers after they failed instead of waiting for a new event to be available before trying. ([\#15743](https://github.com/matrix-org/synapse/issues/15743))
- Fix requesting multiple keys at once over federation, related to [MSC3983](https://github.com/matrix-org/matrix-spec-proposals/pull/3983). ([\#15755](https://github.com/matrix-org/synapse/issues/15755))
- Allow for the configuration of max request retries and min/max retry delays in the matrix federation client. ([\#15783](https://github.com/matrix-org/synapse/issues/15783))
- Switch from `matrix://` to `matrix-federation://` scheme for internal Synapse routing of outbound federation traffic. ([\#15806](https://github.com/matrix-org/synapse/issues/15806))
- Fix harmless exceptions being printed when running the port DB script. ([\#15814](https://github.com/matrix-org/synapse/issues/15814))

### Updates to locked dependencies

* Bump attrs from 22.2.0 to 23.1.0. ([\#15801](https://github.com/matrix-org/synapse/issues/15801))
* Bump cryptography from 40.0.2 to 41.0.1. ([\#15800](https://github.com/matrix-org/synapse/issues/15800))
* Bump ijson from 3.2.0.post0 to 3.2.1. ([\#15802](https://github.com/matrix-org/synapse/issues/15802))
* Bump phonenumbers from 8.13.13 to 8.13.14. ([\#15798](https://github.com/matrix-org/synapse/issues/15798))
* Bump ruff from 0.0.265 to 0.0.272. ([\#15799](https://github.com/matrix-org/synapse/issues/15799))
* Bump ruff from 0.0.272 to 0.0.275. ([\#15833](https://github.com/matrix-org/synapse/issues/15833))
* Bump serde_json from 1.0.96 to 1.0.97. ([\#15797](https://github.com/matrix-org/synapse/issues/15797))
* Bump serde_json from 1.0.97 to 1.0.99. ([\#15832](https://github.com/matrix-org/synapse/issues/15832))
* Bump towncrier from 22.12.0 to 23.6.0. ([\#15831](https://github.com/matrix-org/synapse/issues/15831))
* Bump types-opentracing from 2.4.10.4 to 2.4.10.5. ([\#15830](https://github.com/matrix-org/synapse/issues/15830))
* Bump types-setuptools from 67.8.0.0 to 68.0.0.0. ([\#15835](https://github.com/matrix-org/synapse/issues/15835))

Synapse 1.86.0 (2023-06-20)
===========================

No significant changes since 1.86.0rc2.


Synapse 1.86.0rc2 (2023-06-14)
==============================

Bugfixes
--------

- Fix an error when having workers of different versions running. ([\#15774](https://github.com/matrix-org/synapse/issues/15774))


Synapse 1.86.0rc1 (2023-06-13)
==============================

This version was tagged but never released.

Features
--------

- Stable support for [MSC3882](https://github.com/matrix-org/matrix-spec-proposals/pull/3882) to allow an existing device/session to generate a login token for use on a new device/session. ([\#15388](https://github.com/matrix-org/synapse/issues/15388))
- Support resolving a room's [canonical alias](https://spec.matrix.org/v1.7/client-server-api/#mroomcanonical_alias) via the module API. ([\#15450](https://github.com/matrix-org/synapse/issues/15450))
- Enable support for [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952): intentional mentions. ([\#15520](https://github.com/matrix-org/synapse/issues/15520))
- Experimental [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861) support: delegate auth to an OIDC provider. ([\#15582](https://github.com/matrix-org/synapse/issues/15582))
- Add Synapse version deploy annotations to Grafana dashboard which enables easy correlation between behavior changes witnessed in a graph to a certain Synapse version and nail down regressions. ([\#15674](https://github.com/matrix-org/synapse/issues/15674))
- Add a catch-all * to the supported relation types when redacting an event and its related events. This is an update to [MSC3912](https://github.com/matrix-org/matrix-spec-proposals/pull/3861) implementation. ([\#15705](https://github.com/matrix-org/synapse/issues/15705))
- Speed up `/messages` by backfilling in the background when there are no backward extremities where we are directly paginating. ([\#15710](https://github.com/matrix-org/synapse/issues/15710))
- Expose a metric reporting the database background update status. ([\#15740](https://github.com/matrix-org/synapse/issues/15740))


Bugfixes
--------

- Correctly clear caches when we delete a room. ([\#15609](https://github.com/matrix-org/synapse/issues/15609))
- Check permissions for enabling encryption earlier during room creation to avoid creating broken rooms. ([\#15695](https://github.com/matrix-org/synapse/issues/15695))


Improved Documentation
----------------------

- Simplify query to find participating servers in a room. ([\#15732](https://github.com/matrix-org/synapse/issues/15732))


Internal Changes
----------------

- Log when events are (maybe unexpectedly) filtered out of responses in tests. ([\#14213](https://github.com/matrix-org/synapse/issues/14213))
- Read from column `full_user_id` rather than `user_id` of tables `profiles` and `user_filters`. ([\#15649](https://github.com/matrix-org/synapse/issues/15649))
- Add support for tracing functions which return `Awaitable`s. ([\#15650](https://github.com/matrix-org/synapse/issues/15650))
- Cache requests for user's devices over federation. ([\#15675](https://github.com/matrix-org/synapse/issues/15675))
- Add fully qualified docker image names to Dockerfiles. ([\#15689](https://github.com/matrix-org/synapse/issues/15689))
- Remove some unused code. ([\#15690](https://github.com/matrix-org/synapse/issues/15690))
- Improve type hints. ([\#15694](https://github.com/matrix-org/synapse/issues/15694), [\#15697](https://github.com/matrix-org/synapse/issues/15697))
- Update docstring and traces on `maybe_backfill()` functions. ([\#15709](https://github.com/matrix-org/synapse/issues/15709))
- Add context for when/why to use the `long_retries` option when sending Federation requests. ([\#15721](https://github.com/matrix-org/synapse/issues/15721))
- Removed some unused fields. ([\#15723](https://github.com/matrix-org/synapse/issues/15723))
- Update federation error to more plainly explain we can only authorize our own membership events. ([\#15725](https://github.com/matrix-org/synapse/issues/15725))
- Prevent the `latest_deps` and `twisted_trunk` daily GitHub Actions workflows from running on forks of the codebase. ([\#15726](https://github.com/matrix-org/synapse/issues/15726))
- Improve performance of user directory search. ([\#15729](https://github.com/matrix-org/synapse/issues/15729))
- Remove redundant table join with `room_memberships` when doing a `is_host_joined()`/`is_host_invited()` call (`membership` is already part of the `current_state_events`). ([\#15731](https://github.com/matrix-org/synapse/issues/15731))
- Remove superfluous `room_memberships` join from background update. ([\#15733](https://github.com/matrix-org/synapse/issues/15733))
- Speed up typechecking CI. ([\#15752](https://github.com/matrix-org/synapse/issues/15752))
- Bump minimum supported Rust version to 1.60.0. ([\#15768](https://github.com/matrix-org/synapse/issues/15768))

### Updates to locked dependencies

* Bump importlib-metadata from 6.1.0 to 6.6.0. ([\#15711](https://github.com/matrix-org/synapse/issues/15711))
* Bump library/redis from 6-bullseye to 7-bullseye in /docker. ([\#15712](https://github.com/matrix-org/synapse/issues/15712))
* Bump log from 0.4.18 to 0.4.19. ([\#15761](https://github.com/matrix-org/synapse/issues/15761))
* Bump phonenumbers from 8.13.11 to 8.13.13. ([\#15763](https://github.com/matrix-org/synapse/issues/15763))
* Bump pyasn1 from 0.4.8 to 0.5.0. ([\#15713](https://github.com/matrix-org/synapse/issues/15713))
* Bump pydantic from 1.10.8 to 1.10.9. ([\#15762](https://github.com/matrix-org/synapse/issues/15762))
* Bump pyo3-log from 0.8.1 to 0.8.2. ([\#15759](https://github.com/matrix-org/synapse/issues/15759))
* Bump pyopenssl from 23.1.1 to 23.2.0. ([\#15765](https://github.com/matrix-org/synapse/issues/15765))
* Bump regex from 1.7.3 to 1.8.4. ([\#15769](https://github.com/matrix-org/synapse/issues/15769))
* Bump sentry-sdk from 1.22.1 to 1.25.0. ([\#15714](https://github.com/matrix-org/synapse/issues/15714))
* Bump sentry-sdk from 1.25.0 to 1.25.1. ([\#15764](https://github.com/matrix-org/synapse/issues/15764))
* Bump serde from 1.0.163 to 1.0.164. ([\#15760](https://github.com/matrix-org/synapse/issues/15760))
* Bump types-jsonschema from 4.17.0.7 to 4.17.0.8. ([\#15716](https://github.com/matrix-org/synapse/issues/15716))
* Bump types-pyopenssl from 23.1.0.2 to 23.2.0.0. ([\#15766](https://github.com/matrix-org/synapse/issues/15766))
* Bump types-requests from 2.31.0.0 to 2.31.0.1. ([\#15715](https://github.com/matrix-org/synapse/issues/15715))

Synapse 1.85.2 (2023-06-08)
===========================

Bugfixes
--------

- Fix regression where using TLS for HTTP replication between workers did not work. Introduced in v1.85.0. ([\#15746](https://github.com/matrix-org/synapse/issues/15746))


Synapse 1.85.1 (2023-06-07)
===========================

Note: this release only fixes a bug that stopped some deployments from upgrading to v1.85.0. There is no need to upgrade to v1.85.1 if successfully running v1.85.0.

Bugfixes
--------

- Fix bug in schema delta that broke upgrades for some deployments. Introduced in v1.85.0. ([\#15738](https://github.com/matrix-org/synapse/issues/15738), [\#15739](https://github.com/matrix-org/synapse/issues/15739))


Synapse 1.85.0 (2023-06-06)
===========================

No significant changes since 1.85.0rc2.


## Security advisory

The following issues are fixed in 1.85.0 (and RCs).

- [GHSA-26c5-ppr8-f33p](https://github.com/matrix-org/synapse/security/advisories/GHSA-26c5-ppr8-f33p) / [CVE-2023-32682](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32682) — Low Severity

  It may be possible for a deactivated user to login when using uncommon configurations.

- [GHSA-98px-6486-j7qc](https://github.com/matrix-org/synapse/security/advisories/GHSA-98px-6486-j7qc) / [CVE-2023-32683](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32683) — Low Severity

  A discovered oEmbed or image URL can bypass the `url_preview_url_blacklist` setting potentially allowing server side request forgery or bypassing network policies. Impact is limited to IP addresses allowed by the `url_preview_ip_range_blacklist` setting (by default this only allows public IPs).

See the advisories for more details. If you have any questions, email security@matrix.org.


Synapse 1.85.0rc2 (2023-06-01)
==============================

Bugfixes
--------

- Fix a performance issue introduced in Synapse v1.83.0 which meant that purging rooms was very slow and database-intensive. ([\#15693](https://github.com/matrix-org/synapse/issues/15693))


Deprecations and Removals
-------------------------

- Deprecate calling the `/register` endpoint with an unspecced `user` property for application services. ([\#15703](https://github.com/matrix-org/synapse/issues/15703))


Internal Changes
----------------

- Speed up background jobs `populate_full_user_id_user_filters` and `populate_full_user_id_profiles`. ([\#15700](https://github.com/matrix-org/synapse/issues/15700))


Synapse 1.85.0rc1 (2023-05-30)
==============================

Features
--------

- Improve performance of backfill requests by performing backfill of previously failed requests in the background. ([\#15585](https://github.com/matrix-org/synapse/issues/15585))
- Add a new [admin API](https://matrix-org.github.io/synapse/v1.85/usage/administration/admin_api/index.html) to [create a new device for a user](https://matrix-org.github.io/synapse/v1.85/admin_api/user_admin_api.html#create-a-device). ([\#15611](https://github.com/matrix-org/synapse/issues/15611))
- Add Unix socket support for Redis connections. Contributed by Jason Little. ([\#15644](https://github.com/matrix-org/synapse/issues/15644))


Bugfixes
--------

- Fix a long-standing bug where setting the read marker could fail when using message retention. Contributed by Nick @ Beeper (@fizzadar). ([\#15464](https://github.com/matrix-org/synapse/issues/15464))
- Fix a long-standing bug where the `url_preview_url_blacklist` configuration setting was not applied to oEmbed or image URLs found while previewing a URL. ([\#15601](https://github.com/matrix-org/synapse/issues/15601))
- Fix a long-standing bug where filters with multiple backslashes were rejected. ([\#15607](https://github.com/matrix-org/synapse/issues/15607))
- Fix a bug introduced in Synapse 1.82.0 where the error message displayed when validation of the `app_service_config_files` config option fails would be incorrectly formatted. ([\#15614](https://github.com/matrix-org/synapse/issues/15614))
- Fix a long-standing bug where deactivated users were still able to login using the custom `org.matrix.login.jwt` login type (if enabled). ([\#15624](https://github.com/matrix-org/synapse/issues/15624))
- Fix a long-standing bug where deactivated users were able to login in uncommon situations. ([\#15634](https://github.com/matrix-org/synapse/issues/15634))


Improved Documentation
----------------------

- Warn users that at least 3.75GB of space is needed for the nix Synapse development environment. ([\#15613](https://github.com/matrix-org/synapse/issues/15613))
- Remove outdated comment from the generated and sample homeserver log configs. ([\#15648](https://github.com/matrix-org/synapse/issues/15648))
- Improve contributor docs to make it more clear that Rust is a necessary prerequisite. Contributed by @grantm. ([\#15668](https://github.com/matrix-org/synapse/issues/15668))


Deprecations and Removals
-------------------------

- Remove the old version of the R30 (30-day retained users) phone-home metric. ([\#10428](https://github.com/matrix-org/synapse/issues/10428))


Internal Changes
----------------

- Create dependabot changelogs at release time. ([\#15481](https://github.com/matrix-org/synapse/issues/15481))
- Add not null constraint to column `full_user_id` of tables `profiles` and `user_filters`. ([\#15537](https://github.com/matrix-org/synapse/issues/15537))
- Allow connecting to HTTP Replication Endpoints by using `worker_name` when constructing the request. ([\#15578](https://github.com/matrix-org/synapse/issues/15578))
- Make the `thread_id` column on `event_push_actions`, `event_push_actions_staging`, and `event_push_summary` non-null. ([\#15597](https://github.com/matrix-org/synapse/issues/15597))
- Run mypy type checking with the minimum supported Python version to catch new usage that isn't backwards-compatible. ([\#15602](https://github.com/matrix-org/synapse/issues/15602))
- Fix subscriptable type usage in Python <3.9. ([\#15604](https://github.com/matrix-org/synapse/issues/15604))
- Update internal terminology. ([\#15606](https://github.com/matrix-org/synapse/issues/15606), [\#15620](https://github.com/matrix-org/synapse/issues/15620))
- Instrument `state` and `state_group` storage-related operations to better picture what's happening when tracing. ([\#15610](https://github.com/matrix-org/synapse/issues/15610), [\#15647](https://github.com/matrix-org/synapse/issues/15647))
- Trace how many new events from the backfill response we need to process. ([\#15633](https://github.com/matrix-org/synapse/issues/15633))
- Re-type config paths in `ConfigError`s to be `StrSequence`s instead of `Iterable[str]`s. ([\#15615](https://github.com/matrix-org/synapse/issues/15615))
- Update Mutual Rooms ([MSC2666](https://github.com/matrix-org/matrix-spec-proposals/pull/2666)) implementation to match new proposal text. ([\#15621](https://github.com/matrix-org/synapse/issues/15621))
- Remove the unstable identifiers from faster joins ([MSC3706](https://github.com/matrix-org/matrix-spec-proposals/pull/3706)). ([\#15625](https://github.com/matrix-org/synapse/issues/15625))
- Fix the olddeps CI. ([\#15626](https://github.com/matrix-org/synapse/issues/15626))
- Remove duplicate timestamp from test logs (`_trial_temp/test.log`). ([\#15636](https://github.com/matrix-org/synapse/issues/15636))
- Fix two memory leaks in `trial` test runs. ([\#15630](https://github.com/matrix-org/synapse/issues/15630))
- Limit the size of the `HomeServerConfig` cache in trial test runs. ([\#15646](https://github.com/matrix-org/synapse/issues/15646))
- Improve type hints. ([\#15658](https://github.com/matrix-org/synapse/issues/15658), [\#15659](https://github.com/matrix-org/synapse/issues/15659))
- Add requesting user id parameter to key claim methods in `TransportLayerClient`. ([\#15663](https://github.com/matrix-org/synapse/issues/15663))
- Speed up rebuilding of the user directory for local users. ([\#15665](https://github.com/matrix-org/synapse/issues/15665))
- Implement "option 2" for [MSC3820](https://github.com/matrix-org/matrix-spec-proposals/pull/3820): Room version 11. ([\#15666](https://github.com/matrix-org/synapse/issues/15666), [\#15678](https://github.com/matrix-org/synapse/issues/15678))

### Updates to locked dependencies

* Bump furo from 2023.3.27 to 2023.5.20. ([\#15642](https://github.com/matrix-org/synapse/issues/15642))
* Bump log from 0.4.17 to 0.4.18. ([\#15681](https://github.com/matrix-org/synapse/issues/15681))
* Bump prometheus-client from 0.16.0 to 0.17.0. ([\#15682](https://github.com/matrix-org/synapse/issues/15682))
* Bump pydantic from 1.10.7 to 1.10.8. ([\#15685](https://github.com/matrix-org/synapse/issues/15685))
* Bump pygithub from 1.58.1 to 1.58.2. ([\#15643](https://github.com/matrix-org/synapse/issues/15643))
* Bump requests from 2.28.2 to 2.31.0. ([\#15651](https://github.com/matrix-org/synapse/issues/15651))
* Bump sphinx from 6.1.3 to 6.2.1. ([\#15641](https://github.com/matrix-org/synapse/issues/15641))
* Bump types-bleach from 6.0.0.1 to 6.0.0.3. ([\#15686](https://github.com/matrix-org/synapse/issues/15686))
* Bump types-pillow from 9.5.0.2 to 9.5.0.4. ([\#15640](https://github.com/matrix-org/synapse/issues/15640))
* Bump types-pyyaml from 6.0.12.9 to 6.0.12.10. ([\#15683](https://github.com/matrix-org/synapse/issues/15683))
* Bump types-requests from 2.30.0.0 to 2.31.0.0. ([\#15684](https://github.com/matrix-org/synapse/issues/15684))
* Bump types-setuptools from 67.7.0.2 to 67.8.0.0. ([\#15639](https://github.com/matrix-org/synapse/issues/15639))

Synapse 1.84.1 (2023-05-26)
===========================

This patch release fixes a major issue with homeservers that do not have an `instance_map` defined but which do use workers.
If you have already upgraded to Synapse 1.84.0 and your homeserver is working normally, then there is no need to update to this patch release.


Bugfixes
--------

- Fix a bug introduced in Synapse v1.84.0 where workers do not start up when no `instance_map` was provided. ([\#15672](https://github.com/matrix-org/synapse/issues/15672))


Internal Changes
----------------

- Add `dch` and `notify-send` to the development Nix flake so that the release script can be used. ([\#15673](https://github.com/matrix-org/synapse/issues/15673))


Synapse 1.84.0 (2023-05-23)
===========================

The `worker_replication_*` configuration settings have been deprecated in favour of configuring the main process consistently with other instances in the `instance_map`. The deprecated settings will be removed in Synapse v1.88.0, but changing your configuration in advance is recommended. See the [upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.84/docs/upgrade.md#upgrading-to-v1840) for more information.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.84.0rc1 where errors during startup were not reported correctly on Python < 3.10. ([\#15599](https://github.com/matrix-org/synapse/issues/15599))


Synapse 1.84.0rc1 (2023-05-16)
==============================

Features
--------

- Add an option to prevent media downloads from configured domains. ([\#15197](https://github.com/matrix-org/synapse/issues/15197))
- Add `forget_rooms_on_leave` config option to automatically forget rooms when users leave them or are removed from them. ([\#15224](https://github.com/matrix-org/synapse/issues/15224))
- Add redis TLS configuration options. ([\#15312](https://github.com/matrix-org/synapse/issues/15312))
- Add a config option to delay push notifications by a random amount, to discourage time-based profiling. ([\#15516](https://github.com/matrix-org/synapse/issues/15516))
- Stabilize support for [MSC2659](https://github.com/matrix-org/matrix-spec-proposals/pull/2659): application service ping endpoint. Contributed by Tulir @ Beeper. ([\#15528](https://github.com/matrix-org/synapse/issues/15528))
- Implement [MSC4009](https://github.com/matrix-org/matrix-spec-proposals/pull/4009) to expand the supported characters in Matrix IDs. ([\#15536](https://github.com/matrix-org/synapse/issues/15536))
- Advertise support for Matrix 1.6 on `/_matrix/client/versions`. ([\#15559](https://github.com/matrix-org/synapse/issues/15559))
- Print full error and stack-trace of any exception that occurs during startup/initialization. ([\#15569](https://github.com/matrix-org/synapse/issues/15569))


Bugfixes
--------

- Don't fail on federation over TOR where SRV queries are not supported. Contributed by Zdzichu. ([\#15523](https://github.com/matrix-org/synapse/issues/15523))
- Experimental support for [MSC4010](https://github.com/matrix-org/matrix-spec-proposals/pull/4010) which rejects setting the `"m.push_rules"` via account data. ([\#15554](https://github.com/matrix-org/synapse/issues/15554), [\#15555](https://github.com/matrix-org/synapse/issues/15555))
- Fix a long-standing bug where an invalid membership event could cause an internal server error. ([\#15564](https://github.com/matrix-org/synapse/issues/15564))
- Require at least poetry-core v1.1.0. ([\#15566](https://github.com/matrix-org/synapse/issues/15566), [\#15571](https://github.com/matrix-org/synapse/issues/15571))


Deprecations and Removals
-------------------------

- Remove need for `worker_replication_*` based settings in worker configuration yaml by placing this data directly on the `instance_map` instead. ([\#15491](https://github.com/matrix-org/synapse/issues/15491))


Updates to the Docker image
---------------------------

- Add pkg-config package to Stage 0 to be able to build Dockerfile on ppc64le architecture. ([\#15567](https://github.com/matrix-org/synapse/issues/15567))


Improved Documentation
----------------------

- Clarify documentation of the "Create or modify account" Admin API. ([\#15544](https://github.com/matrix-org/synapse/issues/15544))
- Fix path to the `statistics/database/rooms` admin API in documentation. ([\#15560](https://github.com/matrix-org/synapse/issues/15560))
- Update and improve Mastodon Single Sign-On documentation. ([\#15587](https://github.com/matrix-org/synapse/issues/15587))


Internal Changes
----------------

- Use oEmbed to generate URL previews for YouTube Shorts. ([\#15025](https://github.com/matrix-org/synapse/issues/15025))
- Create new `Client` for use with HTTP Replication between workers. Contributed by Jason Little. ([\#15470](https://github.com/matrix-org/synapse/issues/15470))
- Bump pyicu from 2.10.2 to 2.11. ([\#15509](https://github.com/matrix-org/synapse/issues/15509))
- Remove references to supporting per-user flag for [MSC2654](https://github.com/matrix-org/matrix-spec-proposals/pull/2654). ([\#15522](https://github.com/matrix-org/synapse/issues/15522))
- Don't use a trusted key server when running the demo scripts. ([\#15527](https://github.com/matrix-org/synapse/issues/15527))
- Speed up rebuilding of the user directory for local users. ([\#15529](https://github.com/matrix-org/synapse/issues/15529))
- Speed up deleting of old rows in `event_push_actions`. ([\#15531](https://github.com/matrix-org/synapse/issues/15531))
- Install the `xmlsec` and `mdbook` packages and switch back to the upstream [cachix/devenv](https://github.com/cachix/devenv) repo in the nix development environment. ([\#15532](https://github.com/matrix-org/synapse/issues/15532), [\#15533](https://github.com/matrix-org/synapse/issues/15533), [\#15545](https://github.com/matrix-org/synapse/issues/15545))
- Implement [MSC3987](https://github.com/matrix-org/matrix-spec-proposals/pull/3987) by removing `"dont_notify"` from the list of actions in default push rules. ([\#15534](https://github.com/matrix-org/synapse/issues/15534))
- Move various module API callback registration methods to a dedicated class. ([\#15535](https://github.com/matrix-org/synapse/issues/15535))
- Proxy `/user/devices` federation queries to application services for [MSC3984](https://github.com/matrix-org/matrix-spec-proposals/pull/3984). ([\#15539](https://github.com/matrix-org/synapse/issues/15539))
- Factor out an `is_mine_server_name` method. ([\#15542](https://github.com/matrix-org/synapse/issues/15542))
- Allow running Complement tests using [podman](https://podman.io/) by adding a `PODMAN` environment variable to `scripts-dev/complement.sh`. ([\#15543](https://github.com/matrix-org/synapse/issues/15543))
- Bump serde from 1.0.160 to 1.0.162. ([\#15548](https://github.com/matrix-org/synapse/issues/15548))
- Bump types-setuptools from 67.6.0.5 to 67.7.0.1. ([\#15549](https://github.com/matrix-org/synapse/issues/15549))
- Bump sentry-sdk from 1.19.1 to 1.22.1. ([\#15550](https://github.com/matrix-org/synapse/issues/15550))
- Bump ruff from 0.0.259 to 0.0.265. ([\#15551](https://github.com/matrix-org/synapse/issues/15551))
- Bump hiredis from 2.2.2 to 2.2.3. ([\#15552](https://github.com/matrix-org/synapse/issues/15552))
- Bump types-requests from 2.29.0.0 to 2.30.0.0. ([\#15553](https://github.com/matrix-org/synapse/issues/15553))
- Add `org.matrix.msc3981` info to `/_matrix/client/versions`. ([\#15558](https://github.com/matrix-org/synapse/issues/15558))
- Declare unstable support for [MSC3391](https://github.com/matrix-org/matrix-spec-proposals/pull/3391) under `/_matrix/client/versions` if the experimental implementation is enabled. ([\#15562](https://github.com/matrix-org/synapse/issues/15562))
- Implement [MSC3821](https://github.com/matrix-org/matrix-spec-proposals/pull/3821) to update the redaction rules. ([\#15563](https://github.com/matrix-org/synapse/issues/15563))
- Implement updated redaction rules from [MSC3389](https://github.com/matrix-org/matrix-spec-proposals/pull/3389). ([\#15565](https://github.com/matrix-org/synapse/issues/15565))
- Allow `pip install` to use setuptools_rust 1.6.0 when building Synapse. ([\#15570](https://github.com/matrix-org/synapse/issues/15570))
- Deal with upcoming Github Actions deprecations. ([\#15576](https://github.com/matrix-org/synapse/issues/15576))
- Export `run_as_background_process` from the module API. ([\#15577](https://github.com/matrix-org/synapse/issues/15577))
- Update build system requirements to allow building with poetry-core==1.6.0. ([\#15588](https://github.com/matrix-org/synapse/issues/15588))
- Bump serde from 1.0.162 to 1.0.163. ([\#15589](https://github.com/matrix-org/synapse/issues/15589))
- Bump phonenumbers from 8.13.7 to 8.13.11. ([\#15590](https://github.com/matrix-org/synapse/issues/15590))
- Bump types-psycopg2 from 2.9.21.9 to 2.9.21.10. ([\#15591](https://github.com/matrix-org/synapse/issues/15591))
- Bump types-commonmark from 0.9.2.2 to 0.9.2.3. ([\#15592](https://github.com/matrix-org/synapse/issues/15592))
- Bump types-setuptools from 67.7.0.1 to 67.7.0.2. ([\#15594](https://github.com/matrix-org/synapse/issues/15594))


Synapse 1.83.0 (2023-05-09)
===========================

No significant changes since 1.83.0rc1.


Synapse 1.83.0rc1 (2023-05-02)
==============================

Features
--------

- Experimental support to recursively provide relations per [MSC3981](https://github.com/matrix-org/matrix-spec-proposals/pull/3981). ([\#15315](https://github.com/matrix-org/synapse/issues/15315))
- Experimental support for [MSC3970](https://github.com/matrix-org/matrix-spec-proposals/pull/3970): Scope transaction IDs to devices. ([\#15318](https://github.com/matrix-org/synapse/issues/15318))
- Add an [admin API endpoint](https://matrix-org.github.io/synapse/v1.83/admin_api/experimental_features.html) to support per-user feature flags. ([\#15344](https://github.com/matrix-org/synapse/issues/15344))
- Add a module API to send an HTTP push notification. ([\#15387](https://github.com/matrix-org/synapse/issues/15387))
- Add an [admin API endpoint](https://matrix-org.github.io/synapse/v1.83/admin_api/statistics.html#get-largest-rooms-by-size-in-database) to query the largest rooms by disk space used in the database. ([\#15482](https://github.com/matrix-org/synapse/issues/15482))


Bugfixes
--------

- Disable push rule evaluation for rooms excluded from sync. ([\#15361](https://github.com/matrix-org/synapse/issues/15361))
- Fix a long-standing bug where cached server key results which were directly fetched would not be properly re-used. ([\#15417](https://github.com/matrix-org/synapse/issues/15417))
- Fix a bug introduced in Synapse 1.73.0 where some experimental push rules were returned by default. ([\#15494](https://github.com/matrix-org/synapse/issues/15494))


Improved Documentation
----------------------

- Add Nginx loadbalancing example with sticky mxid for workers. ([\#15411](https://github.com/matrix-org/synapse/issues/15411))
- Update outdated development docs that mention restrictions in versions of SQLite that we no longer support. ([\#15498](https://github.com/matrix-org/synapse/issues/15498))


Internal Changes
----------------

- Speedup tests by caching HomeServerConfig instances. ([\#15284](https://github.com/matrix-org/synapse/issues/15284))
- Add denormalised event stream ordering column to membership state tables for future use. Contributed by Nick @ Beeper (@fizzadar). ([\#15356](https://github.com/matrix-org/synapse/issues/15356))
- Always use multi-user device resync replication endpoints. ([\#15418](https://github.com/matrix-org/synapse/issues/15418))
- Add column `full_user_id` to tables `profiles` and `user_filters`. ([\#15458](https://github.com/matrix-org/synapse/issues/15458))
- Update support for [MSC3983](https://github.com/matrix-org/matrix-spec-proposals/pull/3983) to allow always returning fallback-keys in a `/keys/claim` request. ([\#15462](https://github.com/matrix-org/synapse/issues/15462))
- Improve type hints. ([\#15465](https://github.com/matrix-org/synapse/issues/15465), [\#15496](https://github.com/matrix-org/synapse/issues/15496), [\#15497](https://github.com/matrix-org/synapse/issues/15497))
- Support claiming more than one OTK at a time. ([\#15468](https://github.com/matrix-org/synapse/issues/15468))
- Bump types-pyyaml from 6.0.12.8 to 6.0.12.9. ([\#15471](https://github.com/matrix-org/synapse/issues/15471))
- Bump pyasn1-modules from 0.2.8 to 0.3.0. ([\#15473](https://github.com/matrix-org/synapse/issues/15473))
- Bump cryptography from 40.0.1 to 40.0.2. ([\#15474](https://github.com/matrix-org/synapse/issues/15474))
- Bump types-netaddr from 0.8.0.7 to 0.8.0.8. ([\#15475](https://github.com/matrix-org/synapse/issues/15475))
- Bump types-jsonschema from 4.17.0.6 to 4.17.0.7. ([\#15476](https://github.com/matrix-org/synapse/issues/15476))
- Ask bug reporters to provide logs as text. ([\#15479](https://github.com/matrix-org/synapse/issues/15479))
- Add a Nix flake for use as a development environment. ([\#15495](https://github.com/matrix-org/synapse/issues/15495))
- Bump anyhow from 1.0.70 to 1.0.71. ([\#15507](https://github.com/matrix-org/synapse/issues/15507))
- Bump types-pillow from 9.4.0.19 to 9.5.0.2. ([\#15508](https://github.com/matrix-org/synapse/issues/15508))
- Bump packaging from 23.0 to 23.1. ([\#15510](https://github.com/matrix-org/synapse/issues/15510))
- Bump types-requests from 2.28.11.16 to 2.29.0.0. ([\#15511](https://github.com/matrix-org/synapse/issues/15511))
- Bump setuptools-rust from 1.5.2 to 1.6.0. ([\#15512](https://github.com/matrix-org/synapse/issues/15512))
- Update the check_schema_delta script to account for when the schema version has been bumped locally. ([\#15466](https://github.com/matrix-org/synapse/issues/15466))


Synapse 1.82.0 (2023-04-25)
===========================

No significant changes since 1.82.0rc1.


Synapse 1.82.0rc1 (2023-04-18)
==============================

Features
--------

- Allow loading the `/directory/room/{roomAlias}` endpoint on workers. ([\#15333](https://github.com/matrix-org/synapse/issues/15333))
- Add some validation to `instance_map` configuration loading. ([\#15431](https://github.com/matrix-org/synapse/issues/15431))
- Allow loading the `/capabilities` endpoint on workers. ([\#15436](https://github.com/matrix-org/synapse/issues/15436))


Bugfixes
--------

- Delete server-side backup keys when deactivating an account. ([\#15181](https://github.com/matrix-org/synapse/issues/15181))
- Fix and document untold assumption that `on_logged_out` module hooks will be called before the deletion of pushers. ([\#15410](https://github.com/matrix-org/synapse/issues/15410))
- Improve robustness when handling a perspective key response by deduplicating received server keys. ([\#15423](https://github.com/matrix-org/synapse/issues/15423))
- Synapse now correctly fails to start if the config option `app_service_config_files` is not a list. ([\#15425](https://github.com/matrix-org/synapse/issues/15425))
- Disable loading `RefreshTokenServlet` (`/_matrix/client/(r0|v3|unstable)/refresh`) on workers. ([\#15428](https://github.com/matrix-org/synapse/issues/15428))


Improved Documentation
----------------------

- Note that the `delete_stale_devices_after` background job always runs on the main process. ([\#15452](https://github.com/matrix-org/synapse/issues/15452))


Deprecations and Removals
-------------------------

- Remove the broken, unspecced registration fallback. Note that the *login* fallback is unaffected by this change. ([\#15405](https://github.com/matrix-org/synapse/issues/15405))


Internal Changes
----------------

- Bump black from 23.1.0 to 23.3.0. ([\#15372](https://github.com/matrix-org/synapse/issues/15372))
- Bump pyopenssl from 23.1.0 to 23.1.1. ([\#15373](https://github.com/matrix-org/synapse/issues/15373))
- Bump types-psycopg2 from 2.9.21.8 to 2.9.21.9. ([\#15374](https://github.com/matrix-org/synapse/issues/15374))
- Bump types-netaddr from 0.8.0.6 to 0.8.0.7. ([\#15375](https://github.com/matrix-org/synapse/issues/15375))
- Bump types-opentracing from 2.4.10.3 to 2.4.10.4. ([\#15376](https://github.com/matrix-org/synapse/issues/15376))
- Bump dawidd6/action-download-artifact from 2.26.0 to 2.26.1. ([\#15404](https://github.com/matrix-org/synapse/issues/15404))
- Bump parameterized from 0.8.1 to 0.9.0. ([\#15412](https://github.com/matrix-org/synapse/issues/15412))
- Bump types-pillow from 9.4.0.17 to 9.4.0.19. ([\#15413](https://github.com/matrix-org/synapse/issues/15413))
- Bump sentry-sdk from 1.17.0 to 1.19.1. ([\#15414](https://github.com/matrix-org/synapse/issues/15414))
- Bump immutabledict from 2.2.3 to 2.2.4. ([\#15415](https://github.com/matrix-org/synapse/issues/15415))
- Bump dawidd6/action-download-artifact from 2.26.1 to 2.27.0. ([\#15441](https://github.com/matrix-org/synapse/issues/15441))
- Bump serde_json from 1.0.95 to 1.0.96. ([\#15442](https://github.com/matrix-org/synapse/issues/15442))
- Bump serde from 1.0.159 to 1.0.160. ([\#15443](https://github.com/matrix-org/synapse/issues/15443))
- Bump pillow from 9.4.0 to 9.5.0. ([\#15444](https://github.com/matrix-org/synapse/issues/15444))
- Bump furo from 2023.3.23 to 2023.3.27. ([\#15445](https://github.com/matrix-org/synapse/issues/15445))
- Bump types-pyopenssl from 23.1.0.0 to 23.1.0.2. ([\#15446](https://github.com/matrix-org/synapse/issues/15446))
- Bump mypy from 1.0.0 to 1.0.1. ([\#15447](https://github.com/matrix-org/synapse/issues/15447))
- Bump psycopg2 from 2.9.5 to 2.9.6. ([\#15448](https://github.com/matrix-org/synapse/issues/15448))
- Improve DB performance of clearing out old data from `stream_ordering_to_exterm`. ([\#15382](https://github.com/matrix-org/synapse/issues/15382), [\#15429](https://github.com/matrix-org/synapse/issues/15429))
- Implement [MSC3989](https://github.com/matrix-org/matrix-spec-proposals/pull/3989) redaction algorithm. ([\#15393](https://github.com/matrix-org/synapse/issues/15393))
- Implement [MSC2175](https://github.com/matrix-org/matrix-doc/pull/2175) to stop adding `creator` to create events. ([\#15394](https://github.com/matrix-org/synapse/issues/15394))
- Implement [MSC2174](https://github.com/matrix-org/matrix-spec-proposals/pull/2174) to move the `redacts` key to a `content` property. ([\#15395](https://github.com/matrix-org/synapse/issues/15395))
- Trust dtonlay/rust-toolchain in CI. ([\#15406](https://github.com/matrix-org/synapse/issues/15406))
- Explicitly install Synapse during typechecking in CI. ([\#15409](https://github.com/matrix-org/synapse/issues/15409))
- Only load the SSO redirect servlet if SSO is enabled. ([\#15421](https://github.com/matrix-org/synapse/issues/15421))
- Refactor `SimpleHttpClient` to pull out a base class. ([\#15427](https://github.com/matrix-org/synapse/issues/15427))
- Improve type hints. ([\#15432](https://github.com/matrix-org/synapse/issues/15432))
- Convert async to normal tests in `TestSSOHandler`. ([\#15433](https://github.com/matrix-org/synapse/issues/15433))
- Speed up the user directory background update. ([\#15435](https://github.com/matrix-org/synapse/issues/15435))
- Disable directory listing for static resources in `/_matrix/static/`. ([\#15438](https://github.com/matrix-org/synapse/issues/15438))
- Move various module API callback registration methods to a dedicated class. ([\#15453](https://github.com/matrix-org/synapse/issues/15453))


Synapse 1.81.0 (2023-04-11)
===========================

Synapse now attempts the versioned appservice paths before falling back to the
[legacy paths](https://spec.matrix.org/v1.6/application-service-api/#legacy-routes).
Usage of the legacy routes should be considered deprecated.

Additionally, Synapse has supported sending the application service access token
via [the `Authorization` header](https://spec.matrix.org/v1.6/application-service-api/#authorization)
since v1.70.0. For backwards compatibility it is *also* sent as the `access_token`
query parameter. This is insecure and should be considered deprecated.

A future version of Synapse (v1.88.0 or later) will remove support for legacy
application service routes and query parameter authorization.


No significant changes since 1.81.0rc2.


Synapse 1.81.0rc2 (2023-04-06)
==============================

Bugfixes
--------

- Fix the `set_device_id_for_pushers_txn` background update crash. ([\#15391](https://github.com/matrix-org/synapse/issues/15391))


Internal Changes
----------------

- Update CI to run complement under the latest stable go version. ([\#15403](https://github.com/matrix-org/synapse/issues/15403))


Synapse 1.81.0rc1 (2023-04-04)
==============================

Features
--------

- Add the ability to enable/disable registrations when in the OIDC flow. ([\#14978](https://github.com/matrix-org/synapse/issues/14978))
- Add a primitive helper script for listing worker endpoints. ([\#15243](https://github.com/matrix-org/synapse/issues/15243))
- Experimental support for passing One Time Key and device key requests to application services ([MSC3983](https://github.com/matrix-org/matrix-spec-proposals/pull/3983) and [MSC3984](https://github.com/matrix-org/matrix-spec-proposals/pull/3984)). ([\#15314](https://github.com/matrix-org/synapse/issues/15314), [\#15321](https://github.com/matrix-org/synapse/issues/15321))
- Allow loading `/password_policy` endpoint on workers. ([\#15331](https://github.com/matrix-org/synapse/issues/15331))
- Add experimental support for Unix sockets. Contributed by Jason Little. ([\#15353](https://github.com/matrix-org/synapse/issues/15353))
- Build Debian packages for Ubuntu 23.04 (Lunar Lobster). ([\#15381](https://github.com/matrix-org/synapse/issues/15381))


Bugfixes
--------

- Fix a long-standing bug where edits of non-`m.room.message` events would not be correctly bundled. ([\#15295](https://github.com/matrix-org/synapse/issues/15295))
- Fix a bug introduced in Synapse v1.55.0 which could delay remote homeservers being able to decrypt encrypted messages sent by local users. ([\#15297](https://github.com/matrix-org/synapse/issues/15297))
- Add a check to [SQLite port_db script](https://matrix-org.github.io/synapse/latest/postgres.html#porting-from-sqlite)
  to ensure that the sqlite database passed to the script exists before trying to port from it. ([\#15306](https://github.com/matrix-org/synapse/issues/15306))
- Fix a bug introduced in Synapse 1.76.0 where responses from worker deployments could include an internal `_INT_STREAM_POS` key. ([\#15309](https://github.com/matrix-org/synapse/issues/15309))
- Fix a long-standing bug that Synpase only used the [legacy appservice routes](https://spec.matrix.org/v1.6/application-service-api/#legacy-routes). ([\#15317](https://github.com/matrix-org/synapse/issues/15317))
- Fix a long-standing bug preventing users from rejoining rooms after being banned and unbanned over federation. Contributed by Nico. ([\#15323](https://github.com/matrix-org/synapse/issues/15323))
- Fix bug in worker mode where on a rolling restart of workers the "typing" worker would consume 100% CPU until it got restarted. ([\#15332](https://github.com/matrix-org/synapse/issues/15332))
- Fix a long-standing bug where some to_device messages could be dropped when using workers. ([\#15349](https://github.com/matrix-org/synapse/issues/15349))
- Fix a bug introduced in Synapse 1.70.0 where the background sync from a faster join could spin for hours when one of the events involved had been marked for backoff. ([\#15351](https://github.com/matrix-org/synapse/issues/15351))
- Fix missing app variable in mail subject for password resets. Contributed by Cyberes. ([\#15352](https://github.com/matrix-org/synapse/issues/15352))
- Fix a rare bug introduced in Synapse 1.66.0 where initial syncs would fail when the user had been kicked from a faster joined room that had not finished syncing. ([\#15383](https://github.com/matrix-org/synapse/issues/15383))


Improved Documentation
----------------------

- Fix a typo in login requests ratelimit defaults. ([\#15341](https://github.com/matrix-org/synapse/issues/15341))
- Add some clarification to the doc/comments regarding TCP replication. ([\#15354](https://github.com/matrix-org/synapse/issues/15354))
- Note that Synapse 1.74 queued a rebuild of the user directory tables. ([\#15386](https://github.com/matrix-org/synapse/issues/15386))


Internal Changes
----------------

- Use `immutabledict` instead of `frozendict`. ([\#15113](https://github.com/matrix-org/synapse/issues/15113))
- Add developer documentation for the Federation Sender and add a documentation mechanism using Sphinx. ([\#15265](https://github.com/matrix-org/synapse/issues/15265), [\#15336](https://github.com/matrix-org/synapse/issues/15336))
- Make the pushers rely on the `device_id` instead of the `access_token_id` for various operations. ([\#15280](https://github.com/matrix-org/synapse/issues/15280))
- Bump sentry-sdk from 1.15.0 to 1.17.0. ([\#15285](https://github.com/matrix-org/synapse/issues/15285))
- Allow running the Twisted trunk job against other branches. ([\#15302](https://github.com/matrix-org/synapse/issues/15302))
- Remind the releaser to ask for changelog feedback in [#synapse-dev](https://matrix.to/#/#synapse-dev:matrix.org). ([\#15303](https://github.com/matrix-org/synapse/issues/15303))
- Bump dtolnay/rust-toolchain from e12eda571dc9a5ee5d58eecf4738ec291c66f295 to fc3253060d0c959bea12a59f10f8391454a0b02d. ([\#15304](https://github.com/matrix-org/synapse/issues/15304))
- Reject events with an invalid "mentions" property per [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952). ([\#15311](https://github.com/matrix-org/synapse/issues/15311))
- As an optimisation, use `TRUNCATE` on Postgres when clearing the user directory tables. ([\#15316](https://github.com/matrix-org/synapse/issues/15316))
- Fix `.gitignore` rule for the Complement source tarball downloaded automatically by `complement.sh`. ([\#15319](https://github.com/matrix-org/synapse/issues/15319))
- Bump serde from 1.0.157 to 1.0.158. ([\#15324](https://github.com/matrix-org/synapse/issues/15324))
- Bump regex from 1.7.1 to 1.7.3. ([\#15325](https://github.com/matrix-org/synapse/issues/15325))
- Bump types-pyopenssl from 23.0.0.4 to 23.1.0.0. ([\#15326](https://github.com/matrix-org/synapse/issues/15326))
- Bump furo from 2022.12.7 to 2023.3.23. ([\#15327](https://github.com/matrix-org/synapse/issues/15327))
- Bump ruff from 0.0.252 to 0.0.259. ([\#15328](https://github.com/matrix-org/synapse/issues/15328))
- Bump cryptography from 40.0.0 to 40.0.1. ([\#15329](https://github.com/matrix-org/synapse/issues/15329))
- Bump mypy-zope from 0.9.0 to 0.9.1. ([\#15330](https://github.com/matrix-org/synapse/issues/15330))
- Speed up unit tests when using SQLite3. ([\#15334](https://github.com/matrix-org/synapse/issues/15334))
- Speed up pydantic CI job. ([\#15339](https://github.com/matrix-org/synapse/issues/15339))
- Speed up sample config CI job. ([\#15340](https://github.com/matrix-org/synapse/issues/15340))
- Fix copyright year in SSO footer template. ([\#15358](https://github.com/matrix-org/synapse/issues/15358))
- Bump peaceiris/actions-gh-pages from 3.9.2 to 3.9.3. ([\#15369](https://github.com/matrix-org/synapse/issues/15369))
- Bump serde from 1.0.158 to 1.0.159. ([\#15370](https://github.com/matrix-org/synapse/issues/15370))
- Bump serde_json from 1.0.94 to 1.0.95. ([\#15371](https://github.com/matrix-org/synapse/issues/15371))
- Speed up membership queries for users with forgotten rooms. ([\#15385](https://github.com/matrix-org/synapse/issues/15385))


Synapse 1.80.0 (2023-03-28)
===========================

No significant changes since 1.80.0rc2.


Synapse 1.80.0rc2 (2023-03-22)
==============================

Bugfixes
--------

- Fix a bug in which the [`POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`](https://spec.matrix.org/v1.6/client-server-api/#post_matrixclientv3roomsroomidreporteventid) endpoint would return the wrong error if the user did not have permission to view the event. This aligns Synapse's implementation with [MSC2249](https://github.com/matrix-org/matrix-spec-proposals/pull/2249). ([\#15298](https://github.com/matrix-org/synapse/issues/15298), [\#15300](https://github.com/matrix-org/synapse/issues/15300))
- Fix a bug introduced in Synapse 1.75.0rc1 where the [SQLite port_db script](https://matrix-org.github.io/synapse/latest/postgres.html#porting-from-sqlite)
  would fail to open the SQLite database. ([\#15301](https://github.com/matrix-org/synapse/issues/15301))


Synapse 1.80.0rc1 (2023-03-21)
==============================

Features
--------

- Stabilise support for [MSC3966](https://github.com/matrix-org/matrix-spec-proposals/pull/3966): `event_property_contains` push condition. ([\#15187](https://github.com/matrix-org/synapse/issues/15187))
- Implement [MSC2659](https://github.com/matrix-org/matrix-spec-proposals/pull/2659): application service ping endpoint. Contributed by Tulir @ Beeper. ([\#15249](https://github.com/matrix-org/synapse/issues/15249))
- Allow loading `/register/available` endpoint on workers. ([\#15268](https://github.com/matrix-org/synapse/issues/15268))
- Improve performance of creating and authenticating events. ([\#15195](https://github.com/matrix-org/synapse/issues/15195))
- Add topic and name events to group of events that are batch persisted when creating a room. ([\#15229](https://github.com/matrix-org/synapse/issues/15229))


Bugfixes
--------

- Fix a long-standing bug in which the user directory would assume any remote membership state events represent a profile change. ([\#14755](https://github.com/matrix-org/synapse/issues/14755), [\#14756](https://github.com/matrix-org/synapse/issues/14756))
- Implement [MSC3873](https://github.com/matrix-org/matrix-spec-proposals/pull/3873) to fix a long-standing bug where properties with dots were handled ambiguously in push rules. ([\#15190](https://github.com/matrix-org/synapse/issues/15190))
- Faster joins: Fix a bug introduced in Synapse 1.66 where spurious "Failed to find memberships ..." errors would be logged. ([\#15232](https://github.com/matrix-org/synapse/issues/15232))
- Fix a long-standing error when sending message into deleted room. ([\#15235](https://github.com/matrix-org/synapse/issues/15235))


Updates to the Docker image
---------------------------

- Ensure the Dockerfile builds on platforms that don't have a `cryptography` wheel. ([\#15239](https://github.com/matrix-org/synapse/issues/15239))
- Mirror images to the GitHub Container Registry (`ghcr.io/matrix-org/synapse`). ([\#15281](https://github.com/matrix-org/synapse/issues/15281), [\#15282](https://github.com/matrix-org/synapse/issues/15282))


Improved Documentation
----------------------

- Add a missing endpoint to the workers documentation. ([\#15223](https://github.com/matrix-org/synapse/issues/15223))


Internal Changes
----------------

- Add additional functionality to declaring worker types when starting Complement in worker mode. ([\#14921](https://github.com/matrix-org/synapse/issues/14921))
- Add `Synapse-Trace-Id` to `access-control-expose-headers` header. ([\#14974](https://github.com/matrix-org/synapse/issues/14974))
- Make the `HttpTransactionCache` use the `Requester` in addition of the just the `Request` to build the transaction key. ([\#15200](https://github.com/matrix-org/synapse/issues/15200))
- Improve log lines when purging rooms. ([\#15222](https://github.com/matrix-org/synapse/issues/15222))
- Improve type hints. ([\#15230](https://github.com/matrix-org/synapse/issues/15230), [\#15231](https://github.com/matrix-org/synapse/issues/15231), [\#15238](https://github.com/matrix-org/synapse/issues/15238))
- Move various module API callback registration methods to a dedicated class. ([\#15237](https://github.com/matrix-org/synapse/issues/15237))
- Configure GitHub Actions for merge queues. ([\#15244](https://github.com/matrix-org/synapse/issues/15244))
- Add schema comments about the `destinations` and `destination_rooms` tables. ([\#15247](https://github.com/matrix-org/synapse/issues/15247))
- Skip processing of auto-join room behaviour if there are no auto-join rooms configured. ([\#15262](https://github.com/matrix-org/synapse/issues/15262))
- Remove unused store method `_set_destination_retry_timings_emulated`. ([\#15266](https://github.com/matrix-org/synapse/issues/15266))
- Reorganize URL preview code. ([\#15269](https://github.com/matrix-org/synapse/issues/15269))
- Clean-up direct TCP replication code. ([\#15272](https://github.com/matrix-org/synapse/issues/15272), [\#15274](https://github.com/matrix-org/synapse/issues/15274))
- Make `configure_workers_and_start` script used in Complement tests compatible with older versions of Python. ([\#15275](https://github.com/matrix-org/synapse/issues/15275))
- Add a `/versions` flag for [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952). ([\#15293](https://github.com/matrix-org/synapse/issues/15293))
- Bump hiredis from 2.2.1 to 2.2.2. ([\#15252](https://github.com/matrix-org/synapse/issues/15252))
- Bump serde from 1.0.152 to 1.0.155. ([\#15253](https://github.com/matrix-org/synapse/issues/15253))
- Bump pysaml2 from 7.2.1 to 7.3.1. ([\#15254](https://github.com/matrix-org/synapse/issues/15254))
- Bump msgpack from 1.0.4 to 1.0.5. ([\#15255](https://github.com/matrix-org/synapse/issues/15255))
- Bump gitpython from 3.1.30 to 3.1.31. ([\#15256](https://github.com/matrix-org/synapse/issues/15256))
- Bump cryptography from 39.0.1 to 39.0.2. ([\#15257](https://github.com/matrix-org/synapse/issues/15257))
- Bump pydantic from 1.10.4 to 1.10.6. ([\#15286](https://github.com/matrix-org/synapse/issues/15286))
- Bump serde from 1.0.155 to 1.0.157. ([\#15287](https://github.com/matrix-org/synapse/issues/15287))
- Bump anyhow from 1.0.69 to 1.0.70. ([\#15288](https://github.com/matrix-org/synapse/issues/15288))
- Bump txredisapi from 1.4.7 to 1.4.9. ([\#15289](https://github.com/matrix-org/synapse/issues/15289))
- Bump pygithub from 1.57 to 1.58.1. ([\#15290](https://github.com/matrix-org/synapse/issues/15290))
- Bump types-requests from 2.28.11.12 to 2.28.11.15. ([\#15291](https://github.com/matrix-org/synapse/issues/15291))



Synapse 1.79.0 (2023-03-14)
===========================

No significant changes since 1.79.0rc2.


Synapse 1.79.0rc2 (2023-03-13)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.79.0rc1 where attempting to register a `on_remove_user_third_party_identifier` module API callback would be a no-op. ([\#15227](https://github.com/matrix-org/synapse/issues/15227))
- Fix a rare bug introduced in Synapse 1.73 where events could remain unsent to other homeservers after a faster-join to a room. ([\#15248](https://github.com/matrix-org/synapse/issues/15248))


Internal Changes
----------------

- Refactor `filter_events_for_server`. ([\#15240](https://github.com/matrix-org/synapse/issues/15240))


Synapse 1.79.0rc1 (2023-03-07)
==============================

Features
--------

- Add two new Third Party Rules module API callbacks: [`on_add_user_third_party_identifier`](https://matrix-org.github.io/synapse/v1.79/modules/third_party_rules_callbacks.html#on_add_user_third_party_identifier) and [`on_remove_user_third_party_identifier`](https://matrix-org.github.io/synapse/v1.79/modules/third_party_rules_callbacks.html#on_remove_user_third_party_identifier). ([\#15044](https://github.com/matrix-org/synapse/issues/15044))
- Experimental support for [MSC3967](https://github.com/matrix-org/matrix-spec-proposals/pull/3967) to not require UIA for setting up cross-signing on first use. ([\#15077](https://github.com/matrix-org/synapse/issues/15077))
- Add media information to the command line [user data export tool](https://matrix-org.github.io/synapse/v1.79/usage/administration/admin_faq.html#how-can-i-export-user-data). ([\#15107](https://github.com/matrix-org/synapse/issues/15107))
- Add an [admin API](https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/index.html) to delete a [specific event report](https://spec.matrix.org/v1.6/client-server-api/#reporting-content). ([\#15116](https://github.com/matrix-org/synapse/issues/15116))
- Add support for knocking to workers. ([\#15133](https://github.com/matrix-org/synapse/issues/15133))
- Allow use of the `/filter` Client-Server APIs on workers. ([\#15134](https://github.com/matrix-org/synapse/issues/15134))
- Update support for [MSC2677](https://github.com/matrix-org/matrix-spec-proposals/pull/2677): remove support for server-side aggregation of reactions. ([\#15172](https://github.com/matrix-org/synapse/issues/15172))
- Stabilise support for [MSC3758](https://github.com/matrix-org/matrix-spec-proposals/pull/3758): `event_property_is` push condition. ([\#15185](https://github.com/matrix-org/synapse/issues/15185))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.75 that caused experimental support for deleting account data to raise an internal server error while using an account data writer worker. ([\#14869](https://github.com/matrix-org/synapse/issues/14869))
- Fix a long-standing bug where Synapse handled an unspecced field on push rules. ([\#15088](https://github.com/matrix-org/synapse/issues/15088))
- Fix a long-standing bug where a URL preview would break if the discovered oEmbed failed to download. ([\#15092](https://github.com/matrix-org/synapse/issues/15092))
- Fix a long-standing bug where an initial sync would not respond to changes to the list of ignored users if there was an initial sync cached. ([\#15163](https://github.com/matrix-org/synapse/issues/15163))
- Add the `transaction_id` in the events included in many endpoints' responses. ([\#15174](https://github.com/matrix-org/synapse/issues/15174))
- Fix a bug introduced in Synapse 1.78.0 where requests to claim dehydrated devices would fail with a `405` error. ([\#15180](https://github.com/matrix-org/synapse/issues/15180))
- Stop applying edits when bundling aggregations, per [MSC3925](https://github.com/matrix-org/matrix-spec-proposals/pull/3925). ([\#15193](https://github.com/matrix-org/synapse/issues/15193))
- Fix a long-standing bug where the user directory search was not case-insensitive for accented characters. ([\#15143](https://github.com/matrix-org/synapse/issues/15143))


Updates to the Docker image
---------------------------

- Improve startup logging in the with-workers Docker image. ([\#15186](https://github.com/matrix-org/synapse/issues/15186))


Improved Documentation
----------------------

- Document how to use caches in a module. ([\#14026](https://github.com/matrix-org/synapse/issues/14026))
- Clarify which worker processes the ThirdPartyRules' [`on_new_event`](https://matrix-org.github.io/synapse/v1.78/modules/third_party_rules_callbacks.html#on_new_event) module API callback runs on. ([\#15071](https://github.com/matrix-org/synapse/issues/15071))
- Document using [Shibboleth](https://www.shibboleth.net/) as an OpenID Provider. ([\#15112](https://github.com/matrix-org/synapse/issues/15112))
- Correct reference to `federation_verify_certificates` in configuration documentation. ([\#15139](https://github.com/matrix-org/synapse/issues/15139))
- Correct small documentation errors in some `MatrixFederationHttpClient` methods. ([\#15148](https://github.com/matrix-org/synapse/issues/15148))
- Correct the description of the behavior of `registration_shared_secret_path` on startup. ([\#15168](https://github.com/matrix-org/synapse/issues/15168))


Deprecations and Removals
-------------------------

- Deprecate the `on_threepid_bind` module callback, to be replaced by [`on_add_user_third_party_identifier`](https://matrix-org.github.io/synapse/v1.79/modules/third_party_rules_callbacks.html#on_add_user_third_party_identifier). See [upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.79/docs/upgrade.md#upgrading-to-v1790). ([\#15044](https://github.com/matrix-org/synapse/issues/15044))
- Remove the unspecced `room_alias` field from the [`/createRoom`](https://spec.matrix.org/v1.6/client-server-api/#post_matrixclientv3createroom) response. ([\#15093](https://github.com/matrix-org/synapse/issues/15093))
- Remove the unspecced `PUT` on the `/knock/{roomIdOrAlias}` endpoint. ([\#15189](https://github.com/matrix-org/synapse/issues/15189))
- Remove the undocumented and unspecced `type` parameter to the `/thumbnail` endpoint. ([\#15137](https://github.com/matrix-org/synapse/issues/15137))
- Remove unspecced and buggy `PUT` method on the unstable `/rooms/<room_id>/batch_send` endpoint. ([\#15199](https://github.com/matrix-org/synapse/issues/15199))


Internal Changes
----------------

- Run the integration test suites with the asyncio reactor enabled in CI. ([\#14101](https://github.com/matrix-org/synapse/issues/14101))
- Batch up storing state groups when creating a new room. ([\#14918](https://github.com/matrix-org/synapse/issues/14918))
- Update [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952) support based on changes to the MSC. ([\#15051](https://github.com/matrix-org/synapse/issues/15051))
- Refactor writing json data in `FileExfiltrationWriter`. ([\#15095](https://github.com/matrix-org/synapse/issues/15095))
- Tighten the login ratelimit defaults. ([\#15135](https://github.com/matrix-org/synapse/issues/15135))
- Fix a typo in an experimental config setting. ([\#15138](https://github.com/matrix-org/synapse/issues/15138))
- Refactor the media modules. ([\#15146](https://github.com/matrix-org/synapse/issues/15146), [\#15175](https://github.com/matrix-org/synapse/issues/15175))
- Improve type hints. ([\#15164](https://github.com/matrix-org/synapse/issues/15164))
- Move `get_event_report` and `get_event_reports_paginate` from `RoomStore` to `RoomWorkerStore`. ([\#15165](https://github.com/matrix-org/synapse/issues/15165))
- Remove dangling reference to being a reference implementation in docstring. ([\#15167](https://github.com/matrix-org/synapse/issues/15167))
- Add an option to force a rebuild of the "editable" complement image. ([\#15184](https://github.com/matrix-org/synapse/issues/15184))
- Use nightly rustfmt in CI. ([\#15188](https://github.com/matrix-org/synapse/issues/15188))
- Add a `get_next_txn` method to `StreamIdGenerator` to match `MultiWriterIdGenerator`. ([\#15191](https://github.com/matrix-org/synapse/issues/15191))
- Combine `AbstractStreamIdTracker` and `AbstractStreamIdGenerator`. ([\#15192](https://github.com/matrix-org/synapse/issues/15192))
- Automatically fix errors with `ruff`. ([\#15194](https://github.com/matrix-org/synapse/issues/15194))
- Refactor database transaction for query users' devices to reduce database pool contention. ([\#15215](https://github.com/matrix-org/synapse/issues/15215))
- Correct `test_icu_word_boundary_punctuation` so that it passes with the ICU versions available in Alpine and macOS. ([\#15177](https://github.com/matrix-org/synapse/issues/15177))

<details><summary>Locked dependency updates</summary>

  - Bump actions/checkout from 2 to 3. ([\#15155](https://github.com/matrix-org/synapse/issues/15155))
  - Bump black from 22.12.0 to 23.1.0. ([\#15103](https://github.com/matrix-org/synapse/issues/15103))
  - Bump dawidd6/action-download-artifact from 2.25.0 to 2.26.0. ([\#15152](https://github.com/matrix-org/synapse/issues/15152))
  - Bump docker/login-action from 1 to 2. ([\#15154](https://github.com/matrix-org/synapse/issues/15154))
  - Bump matrix-org/backend-meta from 1 to 2. ([\#15156](https://github.com/matrix-org/synapse/issues/15156))
  - Bump ruff from 0.0.237 to 0.0.252. ([\#15159](https://github.com/matrix-org/synapse/issues/15159))
  - Bump serde_json from 1.0.93 to 1.0.94. ([\#15214](https://github.com/matrix-org/synapse/issues/15214))
  - Bump types-commonmark from 0.9.2.1 to 0.9.2.2. ([\#15209](https://github.com/matrix-org/synapse/issues/15209))
  - Bump types-opentracing from 2.4.10.1 to 2.4.10.3. ([\#15158](https://github.com/matrix-org/synapse/issues/15158))
  - Bump types-pillow from 9.4.0.13 to 9.4.0.17. ([\#15211](https://github.com/matrix-org/synapse/issues/15211))
  - Bump types-psycopg2 from 2.9.21.4 to 2.9.21.8. ([\#15210](https://github.com/matrix-org/synapse/issues/15210))
  - Bump types-pyopenssl from 22.1.0.2 to 23.0.0.4. ([\#15213](https://github.com/matrix-org/synapse/issues/15213))
  - Bump types-setuptools from 67.3.0.1 to 67.4.0.3. ([\#15160](https://github.com/matrix-org/synapse/issues/15160))
  - Bump types-setuptools from 67.4.0.3 to 67.5.0.0. ([\#15212](https://github.com/matrix-org/synapse/issues/15212))
  - Bump typing-extensions from 4.4.0 to 4.5.0. ([\#15157](https://github.com/matrix-org/synapse/issues/15157))
</details>


Synapse 1.78.0 (2023-02-28)
===========================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.76 where 5s delays would occasionally occur in deployments using workers. ([\#15150](https://github.com/matrix-org/synapse/issues/15150))


Synapse 1.78.0rc1 (2023-02-21)
==============================

Features
--------

- Implement the experimental `exact_event_match` push rule condition from [MSC3758](https://github.com/matrix-org/matrix-spec-proposals/pull/3758). ([\#14964](https://github.com/matrix-org/synapse/issues/14964))
- Add account data to the command line [user data export tool](https://matrix-org.github.io/synapse/v1.78/usage/administration/admin_faq.html#how-can-i-export-user-data). ([\#14969](https://github.com/matrix-org/synapse/issues/14969))
- Implement [MSC3873](https://github.com/matrix-org/matrix-spec-proposals/pull/3873) to disambiguate push rule keys with dots in them. ([\#15004](https://github.com/matrix-org/synapse/issues/15004))
- Allow Synapse to use a specific Redis [logical database](https://redis.io/commands/select/) in worker-mode deployments. ([\#15034](https://github.com/matrix-org/synapse/issues/15034))
- Tag opentracing spans for federation requests with the name of the worker serving the request. ([\#15042](https://github.com/matrix-org/synapse/issues/15042))
- Implement the experimental `exact_event_property_contains` push rule condition from [MSC3966](https://github.com/matrix-org/matrix-spec-proposals/pull/3966). ([\#15045](https://github.com/matrix-org/synapse/issues/15045))
- Remove spurious `dont_notify` action from the defaults for the `.m.rule.reaction` pushrule. ([\#15073](https://github.com/matrix-org/synapse/issues/15073))
- Update the error code returned when user sends a duplicate annotation. ([\#15075](https://github.com/matrix-org/synapse/issues/15075))


Bugfixes
--------

- Prevent clients from reporting nonexistent events. ([\#13779](https://github.com/matrix-org/synapse/issues/13779))
- Return spec-compliant JSON errors when unknown endpoints are requested. ([\#14605](https://github.com/matrix-org/synapse/issues/14605))
- Fix a long-standing bug where the room aliases returned could be corrupted. ([\#15038](https://github.com/matrix-org/synapse/issues/15038))
- Fix a bug introduced in Synapse 1.76.0 where partially-joined rooms could not be deleted using the [purge room API](https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#delete-room-api). ([\#15068](https://github.com/matrix-org/synapse/issues/15068))
- Fix a long-standing bug where federated joins would fail if the first server in the list of servers to try is not in the room. ([\#15074](https://github.com/matrix-org/synapse/issues/15074))
- Fix a bug introduced in Synapse v1.74.0 where searching with colons when using ICU for search term tokenisation would fail with an error. ([\#15079](https://github.com/matrix-org/synapse/issues/15079))
- Reduce the likelihood of a rare race condition where rejoining a restricted room over federation would fail. ([\#15080](https://github.com/matrix-org/synapse/issues/15080))
- Fix a bug introduced in Synapse 1.76 where workers would fail to start if the `health` listener was configured. ([\#15096](https://github.com/matrix-org/synapse/issues/15096))
- Fix a bug introduced in Synapse 1.75 where the [portdb script](https://matrix-org.github.io/synapse/release-v1.78/postgres.html#porting-from-sqlite) would fail to run after a room had been faster-joined. ([\#15108](https://github.com/matrix-org/synapse/issues/15108))


Improved Documentation
----------------------

- Document how to start Synapse with Poetry. Contributed by @thezaidbintariq. ([\#14892](https://github.com/matrix-org/synapse/issues/14892), [\#15022](https://github.com/matrix-org/synapse/issues/15022))
- Update delegation documentation to clarify that SRV DNS delegation does not eliminate all needs to serve files from .well-known locations. Contributed by @williamkray. ([\#14959](https://github.com/matrix-org/synapse/issues/14959))
- Fix a mistake in registration_shared_secret_path docs. ([\#15078](https://github.com/matrix-org/synapse/issues/15078))
- Refer to a more recent blog post on the [Database Maintenance Tools](https://matrix-org.github.io/synapse/latest/usage/administration/database_maintenance_tools.html) page. Contributed by @jahway603. ([\#15083](https://github.com/matrix-org/synapse/issues/15083))


Internal Changes
----------------

- Re-type hint some collections as read-only. ([\#13755](https://github.com/matrix-org/synapse/issues/13755))
- Faster joins: don't stall when another user joins during a partial-state room resync. ([\#14606](https://github.com/matrix-org/synapse/issues/14606))
- Add a class `UnpersistedEventContext` to allow for the batching up of storing state groups. ([\#14675](https://github.com/matrix-org/synapse/issues/14675))
- Add a check to ensure that locked dependencies have source distributions available. ([\#14742](https://github.com/matrix-org/synapse/issues/14742))
- Tweak comment on `_is_local_room_accessible` as part of room visibility in `/hierarchy` to clarify the condition for a room being visible. ([\#14834](https://github.com/matrix-org/synapse/issues/14834))
- Prevent `WARNING: there is already a transaction in progress` lines appearing in PostgreSQL's logs on some occasions. ([\#14840](https://github.com/matrix-org/synapse/issues/14840))
- Use `StrCollection` to avoid potential bugs with `Collection[str]`. ([\#14929](https://github.com/matrix-org/synapse/issues/14929))
- Improve performance of `/sync` in a few situations. ([\#14973](https://github.com/matrix-org/synapse/issues/14973))
- Limit concurrent event creation for a room to avoid state resolution when sending bursts of events to a local room. ([\#14977](https://github.com/matrix-org/synapse/issues/14977))
- Skip calculating unread push actions in /sync when enable_push is false. ([\#14980](https://github.com/matrix-org/synapse/issues/14980))
- Add a schema dump symlinks inside `contrib`, to make it easier for IDEs to interrogate Synapse's database schema. ([\#14982](https://github.com/matrix-org/synapse/issues/14982))
- Improve type hints. ([\#15008](https://github.com/matrix-org/synapse/issues/15008), [\#15026](https://github.com/matrix-org/synapse/issues/15026), [\#15027](https://github.com/matrix-org/synapse/issues/15027), [\#15028](https://github.com/matrix-org/synapse/issues/15028), [\#15031](https://github.com/matrix-org/synapse/issues/15031), [\#15035](https://github.com/matrix-org/synapse/issues/15035), [\#15052](https://github.com/matrix-org/synapse/issues/15052), [\#15072](https://github.com/matrix-org/synapse/issues/15072), [\#15084](https://github.com/matrix-org/synapse/issues/15084))
- Update [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952) support based on changes to the MSC. ([\#15037](https://github.com/matrix-org/synapse/issues/15037))
- Avoid mutating a cached value in `get_user_devices_from_cache`. ([\#15040](https://github.com/matrix-org/synapse/issues/15040))
- Fix a rare exception in logs on start up. ([\#15041](https://github.com/matrix-org/synapse/issues/15041))
- Update pyo3-log to v0.8.1. ([\#15043](https://github.com/matrix-org/synapse/issues/15043))
- Avoid mutating cached values in `_generate_sync_entry_for_account_data`. ([\#15047](https://github.com/matrix-org/synapse/issues/15047))
- Refactor arguments of `try_unbind_threepid` and `_try_unbind_threepid_with_id_server` to not use dictionaries. ([\#15053](https://github.com/matrix-org/synapse/issues/15053))
- Merge debug logging from the hotfixes branch. ([\#15054](https://github.com/matrix-org/synapse/issues/15054))
- Faster joins: omit device list updates originating from partial state rooms in /sync responses without lazy loading of members enabled. ([\#15069](https://github.com/matrix-org/synapse/issues/15069))
- Fix clashing database transaction name. ([\#15070](https://github.com/matrix-org/synapse/issues/15070))
- Upper-bound frozendict dependency. This works around us being unable to test installing our wheels against Python 3.11 in CI. ([\#15114](https://github.com/matrix-org/synapse/issues/15114))
- Tweak logging for when a worker waits for its view of a replication stream to catch up. ([\#15120](https://github.com/matrix-org/synapse/issues/15120))

<details><summary>Locked dependency updates</summary>

- Bump bleach from 5.0.1 to 6.0.0. ([\#15059](https://github.com/matrix-org/synapse/issues/15059))
- Bump cryptography from 38.0.4 to 39.0.1. ([\#15020](https://github.com/matrix-org/synapse/issues/15020))
- Bump ruff version from 0.0.230 to 0.0.237. ([\#15033](https://github.com/matrix-org/synapse/issues/15033))
- Bump dtolnay/rust-toolchain from 9cd00a88a73addc8617065438eff914dd08d0955 to 25dc93b901a87e864900a8aec6c12e9aa794c0c3. ([\#15060](https://github.com/matrix-org/synapse/issues/15060))
- Bump systemd-python from 234 to 235. ([\#15061](https://github.com/matrix-org/synapse/issues/15061))
- Bump serde_json from 1.0.92 to 1.0.93. ([\#15062](https://github.com/matrix-org/synapse/issues/15062))
- Bump types-requests from 2.28.11.8 to 2.28.11.12. ([\#15063](https://github.com/matrix-org/synapse/issues/15063))
- Bump types-pillow from 9.4.0.5 to 9.4.0.10. ([\#15064](https://github.com/matrix-org/synapse/issues/15064))
- Bump sentry-sdk from 1.13.0 to 1.15.0. ([\#15065](https://github.com/matrix-org/synapse/issues/15065))
- Bump types-jsonschema from 4.17.0.3 to 4.17.0.5. ([\#15099](https://github.com/matrix-org/synapse/issues/15099))
- Bump types-bleach from 5.0.3.1 to 6.0.0.0. ([\#15100](https://github.com/matrix-org/synapse/issues/15100))
- Bump dtolnay/rust-toolchain from 25dc93b901a87e864900a8aec6c12e9aa794c0c3 to e12eda571dc9a5ee5d58eecf4738ec291c66f295. ([\#15101](https://github.com/matrix-org/synapse/issues/15101))
- Bump dawidd6/action-download-artifact from 2.24.3 to 2.25.0. ([\#15102](https://github.com/matrix-org/synapse/issues/15102))
- Bump types-pillow from 9.4.0.10 to 9.4.0.13. ([\#15104](https://github.com/matrix-org/synapse/issues/15104))
- Bump types-setuptools from 67.1.0.0 to 67.3.0.1. ([\#15105](https://github.com/matrix-org/synapse/issues/15105))


</details>


Synapse 1.77.0 (2023-02-14)
===========================

No significant changes since 1.77.0rc2.


Synapse 1.77.0rc2 (2023-02-10)
==============================

Bugfixes
--------

- Fix bug where retried replication requests would return a failure. Introduced in v1.76.0. ([\#15024](https://github.com/matrix-org/synapse/issues/15024))


Internal Changes
----------------

- Prepare for future database schema changes. ([\#15036](https://github.com/matrix-org/synapse/issues/15036))


Synapse 1.77.0rc1 (2023-02-07)
==============================

Features
--------

- Experimental support for [MSC3952](https://github.com/matrix-org/matrix-spec-proposals/pull/3952): intentional mentions. ([\#14823](https://github.com/matrix-org/synapse/issues/14823), [\#14943](https://github.com/matrix-org/synapse/issues/14943), [\#14957](https://github.com/matrix-org/synapse/issues/14957), [\#14958](https://github.com/matrix-org/synapse/issues/14958))
- Experimental support to suppress notifications from message edits ([MSC3958](https://github.com/matrix-org/matrix-spec-proposals/pull/3958)). ([\#14960](https://github.com/matrix-org/synapse/issues/14960), [\#15016](https://github.com/matrix-org/synapse/issues/15016))
- Add profile information, devices and connections to the command line [user data export tool](https://matrix-org.github.io/synapse/v1.77/usage/administration/admin_faq.html#how-can-i-export-user-data). ([\#14894](https://github.com/matrix-org/synapse/issues/14894))
- Improve performance when joining or sending an event in large rooms. ([\#14962](https://github.com/matrix-org/synapse/issues/14962))
- Improve performance of joining and leaving large rooms with many local users. ([\#14971](https://github.com/matrix-org/synapse/issues/14971))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.53.0 where `next_batch` tokens from `/sync` could not be used with the `/relations` endpoint. ([\#14866](https://github.com/matrix-org/synapse/issues/14866))
- Fix a bug introduced in Synapse 1.35.0 where the module API's `send_local_online_presence_to` would fail to send presence updates over federation. ([\#14880](https://github.com/matrix-org/synapse/issues/14880))
- Fix a bug introduced in Synapse 1.70.0 where the background updates to add non-thread unique indexes on receipts could fail when upgrading from 1.67.0 or earlier. ([\#14915](https://github.com/matrix-org/synapse/issues/14915))
- Fix a regression introduced in Synapse 1.69.0 which can result in database corruption when database migrations are interrupted on sqlite. ([\#14926](https://github.com/matrix-org/synapse/issues/14926))
- Fix a bug introduced in Synapse 1.68.0 where we were unable to service remote joins in rooms with `@room` notification levels set to `null` in their (malformed) power levels. ([\#14942](https://github.com/matrix-org/synapse/issues/14942))
- Fix a bug introduced in Synapse 1.64.0 where boolean power levels were erroneously permitted in [v10 rooms](https://spec.matrix.org/v1.5/rooms/v10/). ([\#14944](https://github.com/matrix-org/synapse/issues/14944))
- Fix a long-standing bug where sending messages on servers with presence enabled would spam "Re-starting finished log context" log lines. ([\#14947](https://github.com/matrix-org/synapse/issues/14947))
- Fix a bug introduced in Synapse 1.68.0 where logging from the Rust module was not properly logged. ([\#14976](https://github.com/matrix-org/synapse/issues/14976))
- Fix various long-standing bugs in Synapse's config, event and request handling where booleans were unintentionally accepted where an integer was expected. ([\#14945](https://github.com/matrix-org/synapse/issues/14945))


Internal Changes
----------------

- Add missing type hints. ([\#14879](https://github.com/matrix-org/synapse/issues/14879), [\#14886](https://github.com/matrix-org/synapse/issues/14886), [\#14887](https://github.com/matrix-org/synapse/issues/14887), [\#14904](https://github.com/matrix-org/synapse/issues/14904), [\#14927](https://github.com/matrix-org/synapse/issues/14927), [\#14956](https://github.com/matrix-org/synapse/issues/14956), [\#14983](https://github.com/matrix-org/synapse/issues/14983), [\#14984](https://github.com/matrix-org/synapse/issues/14984), [\#14985](https://github.com/matrix-org/synapse/issues/14985), [\#14987](https://github.com/matrix-org/synapse/issues/14987), [\#14988](https://github.com/matrix-org/synapse/issues/14988), [\#14990](https://github.com/matrix-org/synapse/issues/14990), [\#14991](https://github.com/matrix-org/synapse/issues/14991), [\#14992](https://github.com/matrix-org/synapse/issues/14992), [\#15007](https://github.com/matrix-org/synapse/issues/15007))
- Use `StrCollection` to avoid potential bugs with `Collection[str]`. ([\#14922](https://github.com/matrix-org/synapse/issues/14922))
- Allow running the complement tests suites with the asyncio reactor enabled. ([\#14858](https://github.com/matrix-org/synapse/issues/14858))
- Improve performance of `/sync` in a few situations. ([\#14908](https://github.com/matrix-org/synapse/issues/14908), [\#14970](https://github.com/matrix-org/synapse/issues/14970))
- Document how to handle Dependabot pull requests. ([\#14916](https://github.com/matrix-org/synapse/issues/14916))
- Fix typo in release script. ([\#14920](https://github.com/matrix-org/synapse/issues/14920))
- Update build system requirements to allow building with poetry-core 1.5.0. ([\#14949](https://github.com/matrix-org/synapse/issues/14949), [\#15019](https://github.com/matrix-org/synapse/issues/15019))
- Add an [lnav](https://lnav.org) config file for Synapse logs to `/contrib/lnav`. ([\#14953](https://github.com/matrix-org/synapse/issues/14953))
- Faster joins: Refactor internal handling of servers in room to never store an empty list. ([\#14954](https://github.com/matrix-org/synapse/issues/14954))
- Faster joins: tag `v2/send_join/` requests to indicate if they served a partial join response. ([\#14950](https://github.com/matrix-org/synapse/issues/14950))
- Allow running `cargo` without the `extension-module` option. ([\#14965](https://github.com/matrix-org/synapse/issues/14965))
- Preparatory work for adding a denormalised event stream ordering column in the future. Contributed by Nick @ Beeper (@fizzadar). ([\#14979](https://github.com/matrix-org/synapse/issues/14979), [9cd7610](https://github.com/matrix-org/synapse/commit/9cd7610f86ab5051c9365dd38d1eec405a5f8ca6), [f10caa7](https://github.com/matrix-org/synapse/commit/f10caa73eee0caa91cf373966104d1ededae2aee); see [\#15014](https://github.com/matrix-org/synapse/issues/15014))
- Add tests for `_flatten_dict`. ([\#14981](https://github.com/matrix-org/synapse/issues/14981), [\#15002](https://github.com/matrix-org/synapse/issues/15002))

<details><summary>Locked dependency updates</summary>

- Bump dtolnay/rust-toolchain from e645b0cf01249a964ec099494d38d2da0f0b349f to 9cd00a88a73addc8617065438eff914dd08d0955. ([\#14968](https://github.com/matrix-org/synapse/issues/14968))
- Bump docker/build-push-action from 3 to 4. ([\#14952](https://github.com/matrix-org/synapse/issues/14952))
- Bump ijson from 3.1.4 to 3.2.0.post0. ([\#14935](https://github.com/matrix-org/synapse/issues/14935))
- Bump types-pyyaml from 6.0.12.2 to 6.0.12.3. ([\#14936](https://github.com/matrix-org/synapse/issues/14936))
- Bump types-jsonschema from 4.17.0.2 to 4.17.0.3. ([\#14937](https://github.com/matrix-org/synapse/issues/14937))
- Bump types-pillow from 9.4.0.3 to 9.4.0.5. ([\#14938](https://github.com/matrix-org/synapse/issues/14938))
- Bump hiredis from 2.0.0 to 2.1.1. ([\#14939](https://github.com/matrix-org/synapse/issues/14939))
- Bump hiredis from 2.1.1 to 2.2.1. ([\#14993](https://github.com/matrix-org/synapse/issues/14993))
- Bump types-setuptools from 65.6.0.3 to 67.1.0.0. ([\#14994](https://github.com/matrix-org/synapse/issues/14994))
- Bump prometheus-client from 0.15.0 to 0.16.0. ([\#14995](https://github.com/matrix-org/synapse/issues/14995))
- Bump anyhow from 1.0.68 to 1.0.69. ([\#14996](https://github.com/matrix-org/synapse/issues/14996))
- Bump serde_json from 1.0.91 to 1.0.92. ([\#14997](https://github.com/matrix-org/synapse/issues/14997))
- Bump isort from 5.11.4 to 5.11.5. ([\#14998](https://github.com/matrix-org/synapse/issues/14998))
- Bump phonenumbers from 8.13.4 to 8.13.5. ([\#14999](https://github.com/matrix-org/synapse/issues/14999))
</details>

Synapse 1.76.0 (2023-01-31)
===========================

The 1.76 release is the first to enable faster joins ([MSC3706](https://github.com/matrix-org/matrix-spec-proposals/pull/3706) and [MSC3902](https://github.com/matrix-org/matrix-spec-proposals/pull/3902)) by default. Admins can opt-out: see [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.76/docs/upgrade.md#faster-joins-are-enabled-by-default) for more details.

The upgrade from 1.75 to 1.76 changes the account data replication streams in a backwards-incompatible manner. Server operators running a multi-worker deployment should consult [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.76/docs/upgrade.md#changes-to-the-account-data-replication-streams).

Those who are `poetry install`ing from source using our lockfile should ensure their poetry version is 1.3.2 or higher; [see upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.76/docs/upgrade.md#minimum-version-of-poetry-is-now-132).


Notes on faster joins
---------------------

The faster joins project sees the most benefit when joining a room with a large number of members (joined or historical). We expect it to be particularly useful for joining large public rooms like the [Matrix HQ](https://matrix.to/#/#matrix:matrix.org) or [Synapse Admins](https://matrix.to/#/#synapse:matrix.org) rooms.

After a faster join, Synapse considers that room "partially joined". In this state, you should be able to

- read incoming messages;
- see incoming state changes, e.g. room topic changes; and
- send messages, if the room is unencrypted.

Synapse has to spend more effort to complete the join in the background. Once this finishes, you will be able to

- send messages, if the room is in encrypted;
- retrieve room history from before your join, if permitted by the room settings; and
- access the full list of room members.


Improved Documentation
----------------------

- Describe the ideas and the internal machinery behind faster joins. ([\#14677](https://github.com/matrix-org/synapse/issues/14677))


Synapse 1.76.0rc2 (2023-01-27)
==============================

Bugfixes
--------

- Faster joins: Fix a bug introduced in Synapse 1.69 where device list EDUs could fail to be handled after a restart when a faster join sync is in progress. ([\#14914](https://github.com/matrix-org/synapse/issues/14914))


Internal Changes
----------------

- Faster joins: Improve performance of looking up partial-state status of rooms. ([\#14917](https://github.com/matrix-org/synapse/issues/14917))


Synapse 1.76.0rc1 (2023-01-25)
==============================

Features
--------

- Update the default room version to [v10](https://spec.matrix.org/v1.5/rooms/v10/) ([MSC 3904](https://github.com/matrix-org/matrix-spec-proposals/pull/3904)). Contributed by @FSG-Cat. ([\#14111](https://github.com/matrix-org/synapse/issues/14111))
- Add a `set_displayname()` method to the module API for setting a user's display name. ([\#14629](https://github.com/matrix-org/synapse/issues/14629))
- Add a dedicated listener configuration for `health` endpoint. ([\#14747](https://github.com/matrix-org/synapse/issues/14747))
- Implement support for [MSC3890](https://github.com/matrix-org/matrix-spec-proposals/pull/3890): Remotely silence local notifications. ([\#14775](https://github.com/matrix-org/synapse/issues/14775))
- Implement experimental support for [MSC3930](https://github.com/matrix-org/matrix-spec-proposals/pull/3930): Push rules for ([MSC3381](https://github.com/matrix-org/matrix-spec-proposals/pull/3381)) Polls. ([\#14787](https://github.com/matrix-org/synapse/issues/14787))
- Per [MSC3925](https://github.com/matrix-org/matrix-spec-proposals/pull/3925), bundle the whole of the replacement with any edited events, and optionally inhibit server-side replacement. ([\#14811](https://github.com/matrix-org/synapse/issues/14811))
- Faster joins: always serve a partial join response to servers that request it with the stable query param. ([\#14839](https://github.com/matrix-org/synapse/issues/14839))
- Faster joins: allow non-lazy-loading ("eager") syncs to complete after a partial join by omitting partial state rooms until they become fully stated. ([\#14870](https://github.com/matrix-org/synapse/issues/14870))
- Faster joins: request partial joins by default. Admins can opt-out of this for the time being---see the upgrade notes. ([\#14905](https://github.com/matrix-org/synapse/issues/14905))


Bugfixes
--------

- Add index to improve performance of the `/timestamp_to_event` endpoint used for jumping to a specific date in the timeline of a room. ([\#14799](https://github.com/matrix-org/synapse/issues/14799))
- Fix a long-standing bug where Synapse would exhaust the stack when processing many federation requests where the remote homeserver has disconencted early. ([\#14812](https://github.com/matrix-org/synapse/issues/14812), [\#14842](https://github.com/matrix-org/synapse/issues/14842))
- Fix rare races when using workers. ([\#14820](https://github.com/matrix-org/synapse/issues/14820))
- Fix a bug introduced in Synapse 1.64.0 when using room version 10 with frozen events enabled. ([\#14864](https://github.com/matrix-org/synapse/issues/14864))
- Fix a long-standing bug where the `populate_room_stats` background job could fail on broken rooms. ([\#14873](https://github.com/matrix-org/synapse/issues/14873))
- Faster joins: Fix a bug in worker deployments where the room stats and user directory would not get updated when finishing a fast join until another event is sent or received. ([\#14874](https://github.com/matrix-org/synapse/issues/14874))
- Faster joins: Fix incompatibility with joins into restricted rooms where no local users have the ability to invite. ([\#14882](https://github.com/matrix-org/synapse/issues/14882))
- Fix a regression introduced in Synapse 1.69.0 which can result in database corruption when database migrations are interrupted on sqlite. ([\#14910](https://github.com/matrix-org/synapse/issues/14910))


Updates to the Docker image
---------------------------

- Bump default Python version in the Dockerfile from 3.9 to 3.11. ([\#14875](https://github.com/matrix-org/synapse/issues/14875))


Improved Documentation
----------------------

- Include `x_forwarded` entry in the HTTP listener example configs and remove the remaining `worker_main_http_uri` entries. ([\#14667](https://github.com/matrix-org/synapse/issues/14667))
- Remove duplicate commands from the Code Style documentation page; point to the Contributing Guide instead. ([\#14773](https://github.com/matrix-org/synapse/issues/14773))
- Add missing documentation for `tag` to `listeners` section. ([\#14803](https://github.com/matrix-org/synapse/issues/14803))
- Updated documentation in configuration manual for `user_directory.search_all_users`. ([\#14818](https://github.com/matrix-org/synapse/issues/14818))
- Add `worker_manhole` to configuration manual. ([\#14824](https://github.com/matrix-org/synapse/issues/14824))
- Fix the example config missing the `id` field in [application service documentation](https://matrix-org.github.io/synapse/latest/application_services.html). ([\#14845](https://github.com/matrix-org/synapse/issues/14845))
- Minor corrections to the logging configuration documentation. ([\#14868](https://github.com/matrix-org/synapse/issues/14868))
- Document the export user data command. Contributed by @thezaidbintariq. ([\#14883](https://github.com/matrix-org/synapse/issues/14883))


Deprecations and Removals
-------------------------

- Poetry 1.3.2 or higher is now required when `poetry install`ing from source. ([\#14860](https://github.com/matrix-org/synapse/issues/14860))


Internal Changes
----------------

- Faster remote room joins (worker mode): do not populate external hosts-in-room cache when sending events as this requires blocking for full state. ([\#14749](https://github.com/matrix-org/synapse/issues/14749))
- Enable Complement tests for Faster Remote Room Joins against worker-mode Synapse. ([\#14752](https://github.com/matrix-org/synapse/issues/14752))
- Add some clarifying comments and refactor a portion of the `Keyring` class for readability. ([\#14804](https://github.com/matrix-org/synapse/issues/14804))
- Add local poetry config files (`poetry.toml`) to `.gitignore`. ([\#14807](https://github.com/matrix-org/synapse/issues/14807))
- Add missing type hints. ([\#14816](https://github.com/matrix-org/synapse/issues/14816), [\#14885](https://github.com/matrix-org/synapse/issues/14885), [\#14889](https://github.com/matrix-org/synapse/issues/14889))
- Refactor push tests. ([\#14819](https://github.com/matrix-org/synapse/issues/14819))
- Re-enable some linting that was disabled when we switched to ruff. ([\#14821](https://github.com/matrix-org/synapse/issues/14821))
- Add `cargo fmt` and `cargo clippy` to the lint script. ([\#14822](https://github.com/matrix-org/synapse/issues/14822))
- Drop unused table `presence`. ([\#14825](https://github.com/matrix-org/synapse/issues/14825))
- Merge the two account data and the two device list replication streams. ([\#14826](https://github.com/matrix-org/synapse/issues/14826), [\#14833](https://github.com/matrix-org/synapse/issues/14833))
- Faster joins: use stable identifiers from [MSC3706](https://github.com/matrix-org/matrix-spec-proposals/pull/3706). ([\#14832](https://github.com/matrix-org/synapse/issues/14832), [\#14841](https://github.com/matrix-org/synapse/issues/14841))
- Add a parameter to control whether the federation client performs a partial state join. ([\#14843](https://github.com/matrix-org/synapse/issues/14843))
- Add check to avoid starting duplicate partial state syncs. ([\#14844](https://github.com/matrix-org/synapse/issues/14844))
- Add an early return when handling no-op presence updates. ([\#14855](https://github.com/matrix-org/synapse/issues/14855))
- Fix `wait_for_stream_position` to correctly wait for the right instance to advance its token. ([\#14856](https://github.com/matrix-org/synapse/issues/14856), [\#14872](https://github.com/matrix-org/synapse/issues/14872))
- Always notify replication when a stream advances automatically. ([\#14877](https://github.com/matrix-org/synapse/issues/14877))
- Reduce max time we wait for stream positions. ([\#14881](https://github.com/matrix-org/synapse/issues/14881))
- Faster joins: allow the resync process more time to fetch `/state` ids. ([\#14912](https://github.com/matrix-org/synapse/issues/14912))
- Bump regex from 1.7.0 to 1.7.1. ([\#14848](https://github.com/matrix-org/synapse/issues/14848))
- Bump peaceiris/actions-gh-pages from 3.9.1 to 3.9.2. ([\#14861](https://github.com/matrix-org/synapse/issues/14861))
- Bump ruff from 0.0.215 to 0.0.224. ([\#14862](https://github.com/matrix-org/synapse/issues/14862))
- Bump types-pillow from 9.4.0.0 to 9.4.0.3. ([\#14863](https://github.com/matrix-org/synapse/issues/14863))
- Bump types-opentracing from 2.4.10 to 2.4.10.1. ([\#14896](https://github.com/matrix-org/synapse/issues/14896))
- Bump ruff from 0.0.224 to 0.0.230. ([\#14897](https://github.com/matrix-org/synapse/issues/14897))
- Bump types-requests from 2.28.11.7 to 2.28.11.8. ([\#14899](https://github.com/matrix-org/synapse/issues/14899))
- Bump types-psycopg2 from 2.9.21.2 to 2.9.21.4. ([\#14900](https://github.com/matrix-org/synapse/issues/14900))
- Bump types-commonmark from 0.9.2 to 0.9.2.1. ([\#14901](https://github.com/matrix-org/synapse/issues/14901))


Synapse 1.75.0 (2023-01-17)
===========================

No significant changes since 1.75.0rc2.


Synapse 1.75.0rc2 (2023-01-12)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.75.0rc1 where device lists could be miscalculated with some sync filters. ([\#14810](https://github.com/matrix-org/synapse/issues/14810))
- Fix race where calling `/members` or `/state` with an `at` parameter could fail for newly created rooms, when using multiple workers. ([\#14817](https://github.com/matrix-org/synapse/issues/14817))


Synapse 1.75.0rc1 (2023-01-10)
==============================

Features
--------

- Add a `cached` function to `synapse.module_api` that returns a decorator to cache return values of functions. ([\#14663](https://github.com/matrix-org/synapse/issues/14663))
- Add experimental support for [MSC3391](https://github.com/matrix-org/matrix-spec-proposals/pull/3391) (removing account data). ([\#14714](https://github.com/matrix-org/synapse/issues/14714))
- Support [RFC7636](https://datatracker.ietf.org/doc/html/rfc7636) Proof Key for Code Exchange for OAuth single sign-on. ([\#14750](https://github.com/matrix-org/synapse/issues/14750))
- Support non-OpenID compliant userinfo claims for subject and picture. ([\#14753](https://github.com/matrix-org/synapse/issues/14753))
- Improve performance of `/sync` when filtering all rooms, message types, or senders. ([\#14786](https://github.com/matrix-org/synapse/issues/14786))
- Improve performance of the `/hierarchy` endpoint. ([\#14263](https://github.com/matrix-org/synapse/issues/14263))


Bugfixes
--------

- Fix the *MAU Limits* section of the Grafana dashboard relying on a specific `job` name for the workers of a Synapse deployment. ([\#14644](https://github.com/matrix-org/synapse/issues/14644))
- Fix a bug introduced in Synapse 1.70.0 which could cause spurious `UNIQUE constraint failed` errors in the `rotate_notifs` background job. ([\#14669](https://github.com/matrix-org/synapse/issues/14669))
- Ensure stream IDs are always updated after caches get invalidated with workers. Contributed by Nick @ Beeper (@fizzadar). ([\#14723](https://github.com/matrix-org/synapse/issues/14723))
- Remove the unspecced `device` field from `/pushrules` responses. ([\#14727](https://github.com/matrix-org/synapse/issues/14727))
- Fix a bug introduced in Synapse 1.73.0 where the `picture_claim` configured under `oidc_providers` was unused (the default value of `"picture"` was used instead). ([\#14751](https://github.com/matrix-org/synapse/issues/14751))
- Unescape HTML entities in URL preview titles making use of oEmbed responses. ([\#14781](https://github.com/matrix-org/synapse/issues/14781))
- Disable sending confirmation email when 3pid is disabled. ([\#14725](https://github.com/matrix-org/synapse/issues/14725))


Improved Documentation
----------------------

- Declare support for Python 3.11. ([\#14673](https://github.com/matrix-org/synapse/issues/14673))
- Fix `target_memory_usage` being used in the description for the actual `cache_autotune` sub-option `target_cache_memory_usage`. ([\#14674](https://github.com/matrix-org/synapse/issues/14674))
- Move `email` to Server section in config file documentation. ([\#14730](https://github.com/matrix-org/synapse/issues/14730))
- Fix broken links in the Synapse documentation. ([\#14744](https://github.com/matrix-org/synapse/issues/14744))
- Add missing worker settings to shared configuration documentation. ([\#14748](https://github.com/matrix-org/synapse/issues/14748))
- Document using Twitter as a OAuth 2.0 authentication provider. ([\#14778](https://github.com/matrix-org/synapse/issues/14778))
- Fix Synapse 1.74 upgrade notes to correctly explain how to install pyICU when installing Synapse from PyPI. ([\#14797](https://github.com/matrix-org/synapse/issues/14797))
- Update link to towncrier in contribution guide. ([\#14801](https://github.com/matrix-org/synapse/issues/14801))
- Use `htmltest` to check links in the Synapse documentation. ([\#14743](https://github.com/matrix-org/synapse/issues/14743))


Internal Changes
----------------

- Faster remote room joins: stream the un-partial-stating of events over replication. ([\#14545](https://github.com/matrix-org/synapse/issues/14545), [\#14546](https://github.com/matrix-org/synapse/issues/14546))
- Use [ruff](https://github.com/charliermarsh/ruff/) instead of flake8. ([\#14633](https://github.com/matrix-org/synapse/issues/14633), [\#14741](https://github.com/matrix-org/synapse/issues/14741))
- Change `handle_new_client_event` signature so that a 429 does not reach clients on `PartialStateConflictError`, and internally retry when needed instead. ([\#14665](https://github.com/matrix-org/synapse/issues/14665))
- Remove dependency on jQuery on reCAPTCHA page. ([\#14672](https://github.com/matrix-org/synapse/issues/14672))
- Faster joins: make `compute_state_after_events` consistent with other state-fetching functions that take a `StateFilter`. ([\#14676](https://github.com/matrix-org/synapse/issues/14676))
- Add missing type hints. ([\#14680](https://github.com/matrix-org/synapse/issues/14680), [\#14681](https://github.com/matrix-org/synapse/issues/14681), [\#14687](https://github.com/matrix-org/synapse/issues/14687))
- Improve type annotations for the helper methods on a `CachedFunction`. ([\#14685](https://github.com/matrix-org/synapse/issues/14685))
- Check that the SQLite database file exists before porting to PostgreSQL. ([\#14692](https://github.com/matrix-org/synapse/issues/14692))
- Add `.direnv/` directory to .gitignore to prevent local state generated by the [direnv](https://direnv.net/) development tool from being committed. ([\#14707](https://github.com/matrix-org/synapse/issues/14707))
- Batch up replication requests to request the resyncing of remote users's devices. ([\#14716](https://github.com/matrix-org/synapse/issues/14716))
- If debug logging is enabled, log the `msgid`s of any to-device messages that are returned over `/sync`. ([\#14724](https://github.com/matrix-org/synapse/issues/14724))
- Change GHA CI job to follow best practices. ([\#14772](https://github.com/matrix-org/synapse/issues/14772))
- Switch to our fork of `dh-virtualenv` to work around an upstream Python 3.11 incompatibility. ([\#14774](https://github.com/matrix-org/synapse/issues/14774))
- Skip testing built wheels for PyPy 3.7 on Linux x86_64 as we lack new required dependencies in the build environment. ([\#14802](https://github.com/matrix-org/synapse/issues/14802))

### Dependabot updates

<details>

- Bump JasonEtco/create-an-issue from 2.8.1 to 2.8.2. ([\#14693](https://github.com/matrix-org/synapse/issues/14693))
- Bump anyhow from 1.0.66 to 1.0.68. ([\#14694](https://github.com/matrix-org/synapse/issues/14694))
- Bump blake2 from 0.10.5 to 0.10.6. ([\#14695](https://github.com/matrix-org/synapse/issues/14695))
- Bump serde_json from 1.0.89 to 1.0.91. ([\#14696](https://github.com/matrix-org/synapse/issues/14696))
- Bump serde from 1.0.150 to 1.0.151. ([\#14697](https://github.com/matrix-org/synapse/issues/14697))
- Bump lxml from 4.9.1 to 4.9.2. ([\#14698](https://github.com/matrix-org/synapse/issues/14698))
- Bump types-jsonschema from 4.17.0.1 to 4.17.0.2. ([\#14700](https://github.com/matrix-org/synapse/issues/14700))
- Bump sentry-sdk from 1.11.1 to 1.12.0. ([\#14701](https://github.com/matrix-org/synapse/issues/14701))
- Bump types-setuptools from 65.6.0.1 to 65.6.0.2. ([\#14702](https://github.com/matrix-org/synapse/issues/14702))
- Bump minimum PyYAML to 3.13. ([\#14720](https://github.com/matrix-org/synapse/issues/14720))
- Bump JasonEtco/create-an-issue from 2.8.2 to 2.9.1. ([\#14731](https://github.com/matrix-org/synapse/issues/14731))
- Bump towncrier from 22.8.0 to 22.12.0. ([\#14732](https://github.com/matrix-org/synapse/issues/14732))
- Bump isort from 5.10.1 to 5.11.4. ([\#14733](https://github.com/matrix-org/synapse/issues/14733))
- Bump attrs from 22.1.0 to 22.2.0. ([\#14734](https://github.com/matrix-org/synapse/issues/14734))
- Bump black from 22.10.0 to 22.12.0. ([\#14735](https://github.com/matrix-org/synapse/issues/14735))
- Bump sentry-sdk from 1.12.0 to 1.12.1. ([\#14736](https://github.com/matrix-org/synapse/issues/14736))
- Bump setuptools from 65.3.0 to 65.5.1. ([\#14738](https://github.com/matrix-org/synapse/issues/14738))
- Bump serde from 1.0.151 to 1.0.152. ([\#14758](https://github.com/matrix-org/synapse/issues/14758))
- Bump ruff from 0.0.189 to 0.0.206. ([\#14759](https://github.com/matrix-org/synapse/issues/14759))
- Bump pydantic from 1.10.2 to 1.10.4. ([\#14760](https://github.com/matrix-org/synapse/issues/14760))
- Bump gitpython from 3.1.29 to 3.1.30. ([\#14761](https://github.com/matrix-org/synapse/issues/14761))
- Bump pillow from 9.3.0 to 9.4.0. ([\#14762](https://github.com/matrix-org/synapse/issues/14762))
- Bump types-requests from 2.28.11.5 to 2.28.11.7. ([\#14763](https://github.com/matrix-org/synapse/issues/14763))
- Bump dawidd6/action-download-artifact from 2.24.2 to 2.24.3. ([\#14779](https://github.com/matrix-org/synapse/issues/14779))
- Bump peaceiris/actions-gh-pages from 3.9.0 to 3.9.1. ([\#14791](https://github.com/matrix-org/synapse/issues/14791))
- Bump types-pillow from 9.3.0.4 to 9.4.0.0. ([\#14792](https://github.com/matrix-org/synapse/issues/14792))
- Bump pyopenssl from 22.1.0 to 23.0.0. ([\#14793](https://github.com/matrix-org/synapse/issues/14793))
- Bump types-setuptools from 65.6.0.2 to 65.6.0.3. ([\#14794](https://github.com/matrix-org/synapse/issues/14794))
- Bump importlib-metadata from 4.2.0 to 6.0.0. ([\#14795](https://github.com/matrix-org/synapse/issues/14795))
- Bump ruff from 0.0.206 to 0.0.215. ([\#14796](https://github.com/matrix-org/synapse/issues/14796))
</details>

**Changelogs for older versions can be found [here](docs/changelogs/).**
