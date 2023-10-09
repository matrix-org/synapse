
Synapse 1.74.0 (2022-12-20)
===========================

Improved Documentation
----------------------

- Add release note and update documentation regarding optional ICU support in user search. ([\#14712](https://github.com/matrix-org/synapse/issues/14712))


Synapse 1.74.0rc1 (2022-12-13)
==============================

Features
--------

- Improve user search for international display names. ([\#14464](https://github.com/matrix-org/synapse/issues/14464))
- Stop using deprecated `keyIds` parameter when calling `/_matrix/key/v2/server`. ([\#14490](https://github.com/matrix-org/synapse/issues/14490), [\#14525](https://github.com/matrix-org/synapse/issues/14525))
- Add new `push.enabled` config option to allow opting out of push notification calculation. ([\#14551](https://github.com/matrix-org/synapse/issues/14551), [\#14619](https://github.com/matrix-org/synapse/issues/14619))
- Advertise support for Matrix 1.5 on `/_matrix/client/versions`. ([\#14576](https://github.com/matrix-org/synapse/issues/14576))
- Improve opentracing and logging for to-device message handling. ([\#14598](https://github.com/matrix-org/synapse/issues/14598))
- Allow selecting "prejoin" events by state keys in addition to event types. ([\#14642](https://github.com/matrix-org/synapse/issues/14642))


Bugfixes
--------

- Fix a long-standing bug where a device list update might not be sent to clients in certain circumstances. ([\#14435](https://github.com/matrix-org/synapse/issues/14435), [\#14592](https://github.com/matrix-org/synapse/issues/14592), [\#14604](https://github.com/matrix-org/synapse/issues/14604))
- Suppress a spurious warning when `POST /rooms/<room_id>/<membership>/`, `POST /join/<room_id_or_alias`, or the unspecced `PUT /join/<room_id_or_alias>/<txn_id>` receive an empty HTTP request body. ([\#14600](https://github.com/matrix-org/synapse/issues/14600))
- Return spec-compliant JSON errors when unknown endpoints are requested. ([\#14620](https://github.com/matrix-org/synapse/issues/14620), [\#14621](https://github.com/matrix-org/synapse/issues/14621))
- Update html templates to load images over HTTPS. Contributed by @ashfame. ([\#14625](https://github.com/matrix-org/synapse/issues/14625))
- Fix a long-standing bug where the user directory would return 1 more row than requested. ([\#14631](https://github.com/matrix-org/synapse/issues/14631))
- Reject invalid read receipt requests with empty room or event IDs. Contributed by Nick @ Beeper (@fizzadar). ([\#14632](https://github.com/matrix-org/synapse/issues/14632))
- Fix a bug introduced in Synapse 1.67.0 where not specifying a config file or a server URL would lead to the `register_new_matrix_user` script failing. ([\#14637](https://github.com/matrix-org/synapse/issues/14637))
- Fix a long-standing bug where the user directory and room/user stats might be out of sync. ([\#14639](https://github.com/matrix-org/synapse/issues/14639), [\#14643](https://github.com/matrix-org/synapse/issues/14643))
- Fix a bug introduced in Synapse 1.72.0 where the background updates to add non-thread unique indexes on receipts would fail if they were previously interrupted. ([\#14650](https://github.com/matrix-org/synapse/issues/14650))
- Improve validation of field size limits in events. ([\#14664](https://github.com/matrix-org/synapse/issues/14664))
- Fix bugs introduced in Synapse 1.55.0 and 1.69.0 where application services would not be notified of events in the correct rooms, due to stale caches. ([\#14670](https://github.com/matrix-org/synapse/issues/14670))


Improved Documentation
----------------------

- Update worker settings for `pusher` and `federation_sender` functionality. ([\#14493](https://github.com/matrix-org/synapse/issues/14493))
- Add links to third party package repositories, and point to the bug which highlights Ubuntu's out-of-date packages. ([\#14517](https://github.com/matrix-org/synapse/issues/14517))
- Remove old, incorrect minimum postgres version note and replace with a link to the [Dependency Deprecation Policy](https://matrix-org.github.io/synapse/v1.73/deprecation_policy.html). ([\#14590](https://github.com/matrix-org/synapse/issues/14590))
- Add Single-Sign On setup instructions for Mastodon-based instances. ([\#14594](https://github.com/matrix-org/synapse/issues/14594))
- Change `turn_allow_guests` example value to lowercase `true`. ([\#14634](https://github.com/matrix-org/synapse/issues/14634))


Internal Changes
----------------

- Optimise push badge count calculations. Contributed by Nick @ Beeper (@fizzadar). ([\#14255](https://github.com/matrix-org/synapse/issues/14255))
- Faster remote room joins: stream the un-partial-stating of rooms over replication. ([\#14473](https://github.com/matrix-org/synapse/issues/14473), [\#14474](https://github.com/matrix-org/synapse/issues/14474))
- Share the `ClientRestResource` for both workers and the main process. ([\#14528](https://github.com/matrix-org/synapse/issues/14528))
- Add `--editable` flag to `complement.sh` which uses an editable install of Synapse for faster turn-around times whilst developing iteratively. ([\#14548](https://github.com/matrix-org/synapse/issues/14548))
- Faster joins: use servers list approximation to send read receipts when in partial state instead of waiting for the full state of the room. ([\#14549](https://github.com/matrix-org/synapse/issues/14549))
- Modernize unit tests configuration related to workers. ([\#14568](https://github.com/matrix-org/synapse/issues/14568))
- Bump jsonschema from 4.17.0 to 4.17.3. ([\#14591](https://github.com/matrix-org/synapse/issues/14591))
- Fix Rust lint CI. ([\#14602](https://github.com/matrix-org/synapse/issues/14602))
- Bump JasonEtco/create-an-issue from 2.5.0 to 2.8.1. ([\#14607](https://github.com/matrix-org/synapse/issues/14607))
- Alter some unit test environment parameters to decrease time spent running tests. ([\#14610](https://github.com/matrix-org/synapse/issues/14610))
- Switch to Go recommended installation method for `gotestfmt` template in CI. ([\#14611](https://github.com/matrix-org/synapse/issues/14611))
- Bump phonenumbers from 8.13.0 to 8.13.1. ([\#14612](https://github.com/matrix-org/synapse/issues/14612))
- Bump types-setuptools from 65.5.0.3 to 65.6.0.1. ([\#14613](https://github.com/matrix-org/synapse/issues/14613))
- Bump twine from 4.0.1 to 4.0.2. ([\#14614](https://github.com/matrix-org/synapse/issues/14614))
- Bump types-requests from 2.28.11.2 to 2.28.11.5. ([\#14615](https://github.com/matrix-org/synapse/issues/14615))
- Bump cryptography from 38.0.3 to 38.0.4. ([\#14616](https://github.com/matrix-org/synapse/issues/14616))
- Remove useless cargo install with apt from Dockerfile. ([\#14636](https://github.com/matrix-org/synapse/issues/14636))
- Bump certifi from 2021.10.8 to 2022.12.7. ([\#14645](https://github.com/matrix-org/synapse/issues/14645))
- Bump flake8-bugbear from 22.10.27 to 22.12.6. ([\#14656](https://github.com/matrix-org/synapse/issues/14656))
- Bump packaging from 21.3 to 22.0. ([\#14657](https://github.com/matrix-org/synapse/issues/14657))
- Bump types-pillow from 9.3.0.1 to 9.3.0.4. ([\#14658](https://github.com/matrix-org/synapse/issues/14658))
- Bump serde from 1.0.148 to 1.0.150. ([\#14659](https://github.com/matrix-org/synapse/issues/14659))
- Bump phonenumbers from 8.13.1 to 8.13.2. ([\#14660](https://github.com/matrix-org/synapse/issues/14660))
- Bump authlib from 1.1.0 to 1.2.0. ([\#14661](https://github.com/matrix-org/synapse/issues/14661))
- Move `StateFilter` to `synapse.types`. ([\#14668](https://github.com/matrix-org/synapse/issues/14668))
- Improve type hints. ([\#14597](https://github.com/matrix-org/synapse/issues/14597), [\#14646](https://github.com/matrix-org/synapse/issues/14646), [\#14671](https://github.com/matrix-org/synapse/issues/14671))


Synapse 1.73.0 (2022-12-06)
===========================

Please note that legacy Prometheus metric names have been removed in this release; see [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.73/docs/upgrade.md#legacy-prometheus-metric-names-have-now-been-removed) for more details.

No significant changes since 1.73.0rc2.


Synapse 1.73.0rc2 (2022-12-01)
==============================

Bugfixes
--------

- Fix a regression in Synapse 1.73.0rc1 where Synapse's main process would stop responding to HTTP requests when a user with a large number of devices logs in. ([\#14582](https://github.com/matrix-org/synapse/issues/14582))


Synapse 1.73.0rc1 (2022-11-29)
==============================

Features
--------

- Speed-up `/messages` with `filter_events_for_client` optimizations. ([\#14527](https://github.com/matrix-org/synapse/issues/14527))
- Improve DB performance by reducing amount of data that gets read in `device_lists_changes_in_room`. ([\#14534](https://github.com/matrix-org/synapse/issues/14534))
- Add support for handling avatar in SSO OIDC login. Contributed by @ashfame. ([\#13917](https://github.com/matrix-org/synapse/issues/13917))
- Move MSC3030 `/timestamp_to_event` endpoints to stable `v1` location (`/_matrix/client/v1/rooms/<roomID>/timestamp_to_event?ts=<timestamp>&dir=<direction>`, `/_matrix/federation/v1/timestamp_to_event/<roomID>?ts=<timestamp>&dir=<direction>`). ([\#14471](https://github.com/matrix-org/synapse/issues/14471))
- Reduce database load of [Client-Server endpoints](https://spec.matrix.org/v1.5/client-server-api/#aggregations) which return bundled aggregations. ([\#14491](https://github.com/matrix-org/synapse/issues/14491), [\#14508](https://github.com/matrix-org/synapse/issues/14508), [\#14510](https://github.com/matrix-org/synapse/issues/14510))
- Add unstable support for an Extensible Events room version (`org.matrix.msc1767.10`) via [MSC1767](https://github.com/matrix-org/matrix-spec-proposals/pull/1767), [MSC3931](https://github.com/matrix-org/matrix-spec-proposals/pull/3931), [MSC3932](https://github.com/matrix-org/matrix-spec-proposals/pull/3932), and [MSC3933](https://github.com/matrix-org/matrix-spec-proposals/pull/3933). ([\#14520](https://github.com/matrix-org/synapse/issues/14520), [\#14521](https://github.com/matrix-org/synapse/issues/14521), [\#14524](https://github.com/matrix-org/synapse/issues/14524))
- Prune user's old devices on login if they have too many. ([\#14038](https://github.com/matrix-org/synapse/issues/14038), [\#14580](https://github.com/matrix-org/synapse/issues/14580))


Bugfixes
--------

- Fix a long-standing bug where paginating from the start of a room did not work. Contributed by @gnunicorn. ([\#14149](https://github.com/matrix-org/synapse/issues/14149))
- Fix a bug introduced in Synapse 1.58.0 where a user with presence state `org.matrix.msc3026.busy` would mistakenly be set to `online` when calling `/sync` or `/events` on a worker process. ([\#14393](https://github.com/matrix-org/synapse/issues/14393))
- Fix a bug introduced in Synapse 1.70.0 where a receipt's thread ID was not sent over federation. ([\#14466](https://github.com/matrix-org/synapse/issues/14466))
- Fix a long-standing bug where the [List media admin API](https://matrix-org.github.io/synapse/latest/admin_api/media_admin_api.html#list-all-media-in-a-room) would fail when processing an image with broken thumbnail information. ([\#14537](https://github.com/matrix-org/synapse/issues/14537))
- Fix a bug introduced in Synapse 1.67.0 where two logging context warnings would be logged on startup. ([\#14574](https://github.com/matrix-org/synapse/issues/14574))
- In application service transactions that include the experimental `org.matrix.msc3202.device_one_time_key_counts` key, include a duplicate key of `org.matrix.msc3202.device_one_time_keys_count` to match the name proposed by [MSC3202](https://github.com/matrix-org/matrix-spec-proposals/pull/3202). ([\#14565](https://github.com/matrix-org/synapse/issues/14565))
- Fix a bug introduced in Synapse 0.9 where Synapse would fail to fetch server keys whose IDs contain a forward slash. ([\#14490](https://github.com/matrix-org/synapse/issues/14490))


Improved Documentation
----------------------

- Fixed link to 'Synapse administration endpoints'. ([\#14499](https://github.com/matrix-org/synapse/issues/14499))


Deprecations and Removals
-------------------------

- Remove legacy Prometheus metrics names. They were deprecated in Synapse v1.69.0 and disabled by default in Synapse v1.71.0. ([\#14538](https://github.com/matrix-org/synapse/issues/14538))


Internal Changes
----------------

- Improve type hinting throughout Synapse. ([\#14055](https://github.com/matrix-org/synapse/issues/14055), [\#14412](https://github.com/matrix-org/synapse/issues/14412), [\#14529](https://github.com/matrix-org/synapse/issues/14529), [\#14452](https://github.com/matrix-org/synapse/issues/14452)).
- Remove old stream ID tracking code. Contributed by Nick @Beeper (@fizzadar). ([\#14376](https://github.com/matrix-org/synapse/issues/14376), [\#14468](https://github.com/matrix-org/synapse/issues/14468))
- Remove the `worker_main_http_uri` configuration setting. This is now handled via internal replication. ([\#14400](https://github.com/matrix-org/synapse/issues/14400), [\#14476](https://github.com/matrix-org/synapse/issues/14476))
- Refactor `federation_sender` and `pusher` configuration loading. ([\#14496](https://github.com/matrix-org/synapse/issues/14496))
([\#14509](https://github.com/matrix-org/synapse/issues/14509), [\#14573](https://github.com/matrix-org/synapse/issues/14573))
- Faster joins: do not wait for full state when creating events to send. ([\#14403](https://github.com/matrix-org/synapse/issues/14403))
- Faster joins: filter out non local events when a room doesn't have its full state. ([\#14404](https://github.com/matrix-org/synapse/issues/14404))
- Faster joins: send events to initial list of servers if we don't have the full state yet. ([\#14408](https://github.com/matrix-org/synapse/issues/14408))
- Faster joins: use servers list approximation received during `send_join` (potentially updated with received membership events) in `assert_host_in_room`. ([\#14515](https://github.com/matrix-org/synapse/issues/14515))
- Fix type logic in TCP replication code that prevented correctly ignoring blank commands. ([\#14449](https://github.com/matrix-org/synapse/issues/14449))
- Remove option to skip locking of tables when performing emulated upserts, to avoid a class of bugs in future. ([\#14469](https://github.com/matrix-org/synapse/issues/14469))
- `scripts-dev/federation_client`: Fix routing on servers with `.well-known` files. ([\#14479](https://github.com/matrix-org/synapse/issues/14479))
- Reduce default third party invite rate limit to 216 invites per day. ([\#14487](https://github.com/matrix-org/synapse/issues/14487))
- Refactor conversion of device list changes in room to outbound pokes to track unconverted rows using a `(stream ID, room ID)` position instead of updating the `converted_to_destinations` flag on every row. ([\#14516](https://github.com/matrix-org/synapse/issues/14516))
- Add more prompts to the bug report form. ([\#14522](https://github.com/matrix-org/synapse/issues/14522))
- Extend editorconfig rules on indent and line length to `.pyi` files. ([\#14526](https://github.com/matrix-org/synapse/issues/14526))
- Run Rust CI when `Cargo.lock` changes. This is particularly useful for dependabot updates. ([\#14571](https://github.com/matrix-org/synapse/issues/14571))
- Fix a possible variable shadow in `create_new_client_event`. ([\#14575](https://github.com/matrix-org/synapse/issues/14575))
- Bump various dependencies in the `poetry.lock` file and in CI scripts. ([\#14557](https://github.com/matrix-org/synapse/issues/14557), [\#14559](https://github.com/matrix-org/synapse/issues/14559), [\#14560](https://github.com/matrix-org/synapse/issues/14560), [\#14500](https://github.com/matrix-org/synapse/issues/14500), [\#14501](https://github.com/matrix-org/synapse/issues/14501), [\#14502](https://github.com/matrix-org/synapse/issues/14502), [\#14503](https://github.com/matrix-org/synapse/issues/14503), [\#14504](https://github.com/matrix-org/synapse/issues/14504), [\#14505](https://github.com/matrix-org/synapse/issues/14505)).


Synapse 1.72.0 (2022-11-22)
===========================

Please note that Synapse now only supports PostgreSQL 11+, because PostgreSQL 10 has reached end-of-life, c.f. our [Deprecation Policy](https://github.com/matrix-org/synapse/blob/develop/docs/deprecation_policy.md).

Bugfixes
--------

- Update forgotten references to legacy metrics in the included Grafana dashboard. ([\#14477](https://github.com/matrix-org/synapse/issues/14477))


Synapse 1.72.0rc1 (2022-11-16)
==============================

Features
--------

- Add experimental support for [MSC3912](https://github.com/matrix-org/matrix-spec-proposals/pull/3912): Relation-based redactions. ([\#14260](https://github.com/matrix-org/synapse/issues/14260))
- Build Debian packages for Ubuntu 22.10 (Kinetic Kudu). ([\#14396](https://github.com/matrix-org/synapse/issues/14396))
- Add an [Admin API](https://matrix-org.github.io/synapse/latest/usage/administration/admin_api/index.html) endpoint for user lookup based on third-party ID (3PID). Contributed by @ashfame. ([\#14405](https://github.com/matrix-org/synapse/issues/14405))
- Faster joins: include heroes' membership events in the partial join response, for rooms without a name or canonical alias. ([\#14442](https://github.com/matrix-org/synapse/issues/14442))


Bugfixes
--------

- Faster joins: do not block creation of or queries for room aliases during the resync. ([\#14292](https://github.com/matrix-org/synapse/issues/14292))
- Fix a bug introduced in Synapse 1.64.0rc1 which could cause log spam when fetching events from other homeservers. ([\#14347](https://github.com/matrix-org/synapse/issues/14347))
- Fix a bug introduced in 1.66 which would not send certain pushrules to clients. Contributed by Nico. ([\#14356](https://github.com/matrix-org/synapse/issues/14356))
- Fix a bug introduced in v1.71.0rc1 where the power level event was incorrectly created during initial room creation. ([\#14361](https://github.com/matrix-org/synapse/issues/14361))
- Fix the refresh token endpoint to be under /r0 and /v3 instead of /v1. Contributed by Tulir @ Beeper. ([\#14364](https://github.com/matrix-org/synapse/issues/14364))
- Fix a long-standing bug where Synapse would raise an error when encountering an unrecognised field in a `/sync` filter, instead of ignoring it for forward compatibility. ([\#14369](https://github.com/matrix-org/synapse/issues/14369))
- Fix a background database update, introduced in Synapse 1.64.0, which could cause poor database performance. ([\#14374](https://github.com/matrix-org/synapse/issues/14374))
- Fix PostgreSQL sometimes using table scans for queries against the `event_search` table, taking a long time and a large amount of IO. ([\#14409](https://github.com/matrix-org/synapse/issues/14409))
- Fix rendering of some HTML templates (including emails). Introduced in v1.71.0. ([\#14448](https://github.com/matrix-org/synapse/issues/14448))
- Fix a bug introduced in Synapse 1.70.0 where the background updates to add non-thread unique indexes on receipts could fail when upgrading from 1.67.0 or earlier. ([\#14453](https://github.com/matrix-org/synapse/issues/14453))


Updates to the Docker image
---------------------------

- Add all Stream Writer worker types to `configure_workers_and_start.py`. ([\#14197](https://github.com/matrix-org/synapse/issues/14197))
- Remove references to legacy worker types in the multi-worker Dockerfile. ([\#14294](https://github.com/matrix-org/synapse/issues/14294))


Improved Documentation
----------------------

- Upload documentation PRs to Netlify. ([\#12947](https://github.com/matrix-org/synapse/issues/12947), [\#14370](https://github.com/matrix-org/synapse/issues/14370))
- Add additional TURN server configuration example based on [eturnal](https://github.com/processone/eturnal) and adjust general TURN server doc structure. ([\#14293](https://github.com/matrix-org/synapse/issues/14293))
- Add example on how to load balance /sync requests. Contributed by [aceArt](https://aceart.de). ([\#14297](https://github.com/matrix-org/synapse/issues/14297))
- Edit sample Nginx reverse proxy configuration to use HTTP/1.1. Contributed by Brad Jones. ([\#14414](https://github.com/matrix-org/synapse/issues/14414))


Deprecations and Removals
-------------------------

- Remove support for PostgreSQL 10. ([\#14392](https://github.com/matrix-org/synapse/issues/14392), [\#14397](https://github.com/matrix-org/synapse/issues/14397))


Internal Changes
----------------

- Run unit tests against Python 3.11. ([\#13812](https://github.com/matrix-org/synapse/issues/13812))
- Add TLS support for generic worker endpoints. ([\#14128](https://github.com/matrix-org/synapse/issues/14128), [\#14455](https://github.com/matrix-org/synapse/issues/14455))
- Switch to a maintained action for installing Rust in CI. ([\#14313](https://github.com/matrix-org/synapse/issues/14313))
- Add override ability to `complement.sh` command line script to request certain types of workers. ([\#14324](https://github.com/matrix-org/synapse/issues/14324))
- Enabling testing of [MSC3874](https://github.com/matrix-org/matrix-spec-proposals/pull/3874) (filtering of `/messages` by relation type) in complement. ([\#14339](https://github.com/matrix-org/synapse/issues/14339))
- Concisely log a failure to resolve state due to missing `prev_events`. ([\#14346](https://github.com/matrix-org/synapse/issues/14346))
- Use a maintained Github action to install Rust. ([\#14351](https://github.com/matrix-org/synapse/issues/14351))
- Cleanup old worker datastore classes. Contributed by Nick @ Beeper (@fizzadar). ([\#14375](https://github.com/matrix-org/synapse/issues/14375))
- Test against PostgreSQL 15 in CI. ([\#14394](https://github.com/matrix-org/synapse/issues/14394))
- Remove unreachable code. ([\#14410](https://github.com/matrix-org/synapse/issues/14410))
- Clean-up event persistence code. ([\#14411](https://github.com/matrix-org/synapse/issues/14411))
- Update docstring to clarify that `get_partial_state_events_batch` does not just give you completely arbitrary partial-state events. ([\#14417](https://github.com/matrix-org/synapse/issues/14417))
- Fix mypy errors introduced by bumping the locked version of `attrs` and `gitpython`. ([\#14433](https://github.com/matrix-org/synapse/issues/14433))
- Make Dependabot only bump Rust deps in the lock file. ([\#14434](https://github.com/matrix-org/synapse/issues/14434))
- Fix an incorrect stub return type for `PushRuleEvaluator.run`. ([\#14451](https://github.com/matrix-org/synapse/issues/14451))
- Improve performance of `/context` in large rooms. ([\#14461](https://github.com/matrix-org/synapse/issues/14461))


Synapse 1.71.0 (2022-11-08)
===========================

Please note that, as announced in the release notes for Synapse 1.69.0, legacy Prometheus metric names are now disabled by default.
They will be removed altogether in Synapse 1.73.0.
If not already done, server administrators should update their dashboards and alerting rules to avoid using the deprecated metric names.
See the [upgrade notes](https://matrix-org.github.io/synapse/v1.71/upgrade.html#upgrading-to-v1710) for more details.

**Note:** in line with our [deprecation policy](https://matrix-org.github.io/synapse/latest/deprecation_policy.html) for platform dependencies, this will be the last release to support PostgreSQL 10, which reaches upstream end-of-life on November 10th, 2022. Future releases of Synapse will require PostgreSQL 11+.

No significant changes since 1.71.0rc2.


Synapse 1.71.0rc2 (2022-11-04)
==============================

Improved Documentation
----------------------

- Document the changes to monthly active user metrics due to deprecation of legacy Prometheus metric names. ([\#14358](https://github.com/matrix-org/synapse/issues/14358), [\#14360](https://github.com/matrix-org/synapse/issues/14360))


Deprecations and Removals
-------------------------

- Disable legacy Prometheus metric names by default. They can still be re-enabled for now, but they will be removed altogether in Synapse 1.73.0. ([\#14353](https://github.com/matrix-org/synapse/issues/14353))


Internal Changes
----------------

- Run unit tests against Python 3.11. ([\#13812](https://github.com/matrix-org/synapse/issues/13812))


Synapse 1.71.0rc1 (2022-11-01)
==============================

Features
--------

- Support back-channel logouts from OpenID Connect providers. ([\#11414](https://github.com/matrix-org/synapse/issues/11414))
- Allow use of Postgres and SQLlite full-text search operators in search queries. ([\#11635](https://github.com/matrix-org/synapse/issues/11635), [\#14310](https://github.com/matrix-org/synapse/issues/14310), [\#14311](https://github.com/matrix-org/synapse/issues/14311))
- Implement [MSC3664](https://github.com/matrix-org/matrix-doc/pull/3664), Pushrules for relations. Contributed by Nico. ([\#11804](https://github.com/matrix-org/synapse/issues/11804))
- Improve aesthetics of HTML templates. Note that these changes do not retroactively apply to templates which have been [customised](https://matrix-org.github.io/synapse/latest/templates.html#templates) by server admins. ([\#13652](https://github.com/matrix-org/synapse/issues/13652))
- Enable write-ahead logging for SQLite installations. Contributed by [@asymmetric](https://github.com/asymmetric). ([\#13897](https://github.com/matrix-org/synapse/issues/13897))
- Show erasure status when [listing users](https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html#query-user-account) in the Admin API. ([\#14205](https://github.com/matrix-org/synapse/issues/14205))
- Provide a specific error code when a `/sync` request provides a filter which doesn't represent a JSON object. ([\#14262](https://github.com/matrix-org/synapse/issues/14262))


Bugfixes
--------

- Fix a long-standing bug where the `update_synapse_database` script could not be run with multiple databases. Contributed by @thefinn93 @ Beeper. ([\#13422](https://github.com/matrix-org/synapse/issues/13422))
- Fix a bug which prevented setting an avatar on homeservers which have an explicit port in their `server_name` and have `max_avatar_size` and/or `allowed_avatar_mimetypes` configuration. Contributed by @ashfame. ([\#13927](https://github.com/matrix-org/synapse/issues/13927))
- Check appservice user interest against the local users instead of all users in the room to align with [MSC3905](https://github.com/matrix-org/matrix-spec-proposals/pull/3905). ([\#13958](https://github.com/matrix-org/synapse/issues/13958))
- Fix a long-standing bug where Synapse would accidentally include extra information in the response to [`PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`](https://spec.matrix.org/v1.4/server-server-api/#put_matrixfederationv2inviteroomideventid). ([\#14064](https://github.com/matrix-org/synapse/issues/14064))
- Fix a bug introduced in Synapse 1.64.0 where presence updates could be missing from `/sync` responses. ([\#14243](https://github.com/matrix-org/synapse/issues/14243))
- Fix a bug introduced in Synapse 1.60.0 which caused an error to be logged when Synapse received a SIGHUP signal if debug logging was enabled. ([\#14258](https://github.com/matrix-org/synapse/issues/14258))
- Prevent history insertion ([MSC2716](https://github.com/matrix-org/matrix-spec-proposals/pull/2716)) during an partial join ([MSC3706](https://github.com/matrix-org/matrix-spec-proposals/pull/3706)). ([\#14291](https://github.com/matrix-org/synapse/issues/14291))
- Fix a bug introduced in Synapse 1.34.0 where device names would be returned via a federation user key query request when `allow_device_name_lookup_over_federation` was set to `false`. ([\#14304](https://github.com/matrix-org/synapse/issues/14304))
- Fix a bug introduced in Synapse 0.34.0 where logs could include error spam when background processes are measured as taking a negative amount of time. ([\#14323](https://github.com/matrix-org/synapse/issues/14323))
- Fix a bug introduced in Synapse 1.70.0 where clients were unable to PUT new [dehydrated devices](https://github.com/matrix-org/matrix-spec-proposals/pull/2697). ([\#14336](https://github.com/matrix-org/synapse/issues/14336))


Improved Documentation
----------------------

- Explain how to disable the use of [`trusted_key_servers`](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#trusted_key_servers). ([\#13999](https://github.com/matrix-org/synapse/issues/13999))
- Add workers settings to [configuration manual](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#individual-worker-configuration). ([\#14086](https://github.com/matrix-org/synapse/issues/14086))
- Correct the name of the config option [`encryption_enabled_by_default_for_room_type`](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#encryption_enabled_by_default_for_room_type). ([\#14110](https://github.com/matrix-org/synapse/issues/14110))
- Update docstrings of `SynapseError` and `FederationError` to bettter describe what they are used for and the effects of using them are. ([\#14191](https://github.com/matrix-org/synapse/issues/14191))


Internal Changes
----------------

- Remove unused `@lru_cache` decorator. ([\#13595](https://github.com/matrix-org/synapse/issues/13595))
- Save login tokens in database and prevent login token reuse. ([\#13844](https://github.com/matrix-org/synapse/issues/13844))
- Refactor OIDC tests to better mimic an actual OIDC provider. ([\#13910](https://github.com/matrix-org/synapse/issues/13910))
- Fix type annotation causing import time error in the Complement forking launcher. ([\#14084](https://github.com/matrix-org/synapse/issues/14084))
- Refactor [MSC3030](https://github.com/matrix-org/matrix-spec-proposals/pull/3030) `/timestamp_to_event` endpoint to loop over federation destinations with standard pattern and error handling. ([\#14096](https://github.com/matrix-org/synapse/issues/14096))
- Add initial power level event to batch of bulk persisted events when creating a new room. ([\#14228](https://github.com/matrix-org/synapse/issues/14228))
- Refactor `/key/` endpoints to use `RestServlet` classes. ([\#14229](https://github.com/matrix-org/synapse/issues/14229))
- Switch to using the `matrix-org/backend-meta` version of `triage-incoming` for new issues in CI. ([\#14230](https://github.com/matrix-org/synapse/issues/14230))
- Build wheels on macos 11, not 10.15. ([\#14249](https://github.com/matrix-org/synapse/issues/14249))
- Add debugging to help diagnose lost device list updates. ([\#14268](https://github.com/matrix-org/synapse/issues/14268))
- Add Rust cache to CI for `trial` runs. ([\#14287](https://github.com/matrix-org/synapse/issues/14287))
- Improve type hinting of `RawHeaders`. ([\#14303](https://github.com/matrix-org/synapse/issues/14303))
- Use Poetry 1.2.0 in the Twisted Trunk CI job. ([\#14305](https://github.com/matrix-org/synapse/issues/14305))

<details>
<summary>Dependency updates</summary>

Runtime:

- Bump anyhow from 1.0.65 to 1.0.66. ([\#14278](https://github.com/matrix-org/synapse/issues/14278))
- Bump jinja2 from 3.0.3 to 3.1.2. ([\#14271](https://github.com/matrix-org/synapse/issues/14271))
- Bump prometheus-client from 0.14.0 to 0.15.0. ([\#14274](https://github.com/matrix-org/synapse/issues/14274))
- Bump psycopg2 from 2.9.4 to 2.9.5. ([\#14331](https://github.com/matrix-org/synapse/issues/14331))
- Bump pysaml2 from 7.1.2 to 7.2.1. ([\#14270](https://github.com/matrix-org/synapse/issues/14270))
- Bump sentry-sdk from 1.5.11 to 1.10.1. ([\#14330](https://github.com/matrix-org/synapse/issues/14330))
- Bump serde from 1.0.145 to 1.0.147. ([\#14277](https://github.com/matrix-org/synapse/issues/14277))
- Bump serde_json from 1.0.86 to 1.0.87. ([\#14279](https://github.com/matrix-org/synapse/issues/14279))

Tooling and CI:

- Bump black from 22.3.0 to 22.10.0. ([\#14328](https://github.com/matrix-org/synapse/issues/14328))
- Bump flake8-bugbear from 21.3.2 to 22.9.23. ([\#14042](https://github.com/matrix-org/synapse/issues/14042))
- Bump peaceiris/actions-gh-pages from 3.8.0 to 3.9.0. ([\#14276](https://github.com/matrix-org/synapse/issues/14276))
- Bump peaceiris/actions-mdbook from 1.1.14 to 1.2.0. ([\#14275](https://github.com/matrix-org/synapse/issues/14275))
- Bump setuptools-rust from 1.5.1 to 1.5.2. ([\#14273](https://github.com/matrix-org/synapse/issues/14273))
- Bump twine from 3.8.0 to 4.0.1. ([\#14332](https://github.com/matrix-org/synapse/issues/14332))
- Bump types-opentracing from 2.4.7 to 2.4.10. ([\#14133](https://github.com/matrix-org/synapse/issues/14133))
- Bump types-requests from 2.28.11 to 2.28.11.2. ([\#14272](https://github.com/matrix-org/synapse/issues/14272))
</details>

Synapse 1.70.1 (2022-10-28)
===========================

This release fixes some regressions that were discovered in 1.70.0.

[#14300](https://github.com/matrix-org/synapse/issues/14300)
was previously reported to be a regression in 1.70.0 as well. However, we have
since concluded that it was limited to the reporter and thus have not needed
to include any fix for it in 1.70.1.


Bugfixes
--------

- Fix a bug introduced in Synapse 1.70.0rc1 where the access tokens sent to application services as headers were malformed. Application services which were obtaining access tokens from query parameters were not affected. ([\#14301](https://github.com/matrix-org/synapse/issues/14301))
- Fix room creation being rate limited too aggressively since Synapse v1.69.0. ([\#14314](https://github.com/matrix-org/synapse/issues/14314))


Synapse 1.70.0 (2022-10-26)
===========================

No significant changes since 1.70.0rc2.


Synapse 1.70.0rc2 (2022-10-25)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.70.0rc1 where the information returned from the `/threads` API could be stale when threaded events are redacted. ([\#14248](https://github.com/matrix-org/synapse/issues/14248))
- Fix a bug introduced in Synapse 1.70.0rc1 leading to broken outbound federation when using Python 3.7. ([\#14280](https://github.com/matrix-org/synapse/issues/14280))
- Fix a bug introduced in Synapse 1.70.0rc1 where edits to non-message events were aggregated by the homeserver. ([\#14283](https://github.com/matrix-org/synapse/issues/14283))


Internal Changes
----------------

- Build ABI3 wheels for CPython. ([\#14253](https://github.com/matrix-org/synapse/issues/14253))
- For the aarch64 architecture, only build wheels for CPython manylinux. ([\#14259](https://github.com/matrix-org/synapse/issues/14259))


Synapse 1.70.0rc1 (2022-10-19)
==============================

Features
--------

- Support for [MSC3856](https://github.com/matrix-org/matrix-spec-proposals/pull/3856): threads list API. ([\#13394](https://github.com/matrix-org/synapse/issues/13394), [\#14171](https://github.com/matrix-org/synapse/issues/14171), [\#14175](https://github.com/matrix-org/synapse/issues/14175))
- Support for thread-specific notifications & receipts ([MSC3771](https://github.com/matrix-org/matrix-spec-proposals/pull/3771) and [MSC3773](https://github.com/matrix-org/matrix-spec-proposals/pull/3773)). ([\#13776](https://github.com/matrix-org/synapse/issues/13776), [\#13824](https://github.com/matrix-org/synapse/issues/13824), [\#13877](https://github.com/matrix-org/synapse/issues/13877), [\#13878](https://github.com/matrix-org/synapse/issues/13878), [\#14050](https://github.com/matrix-org/synapse/issues/14050), [\#14140](https://github.com/matrix-org/synapse/issues/14140), [\#14159](https://github.com/matrix-org/synapse/issues/14159), [\#14163](https://github.com/matrix-org/synapse/issues/14163), [\#14174](https://github.com/matrix-org/synapse/issues/14174), [\#14222](https://github.com/matrix-org/synapse/issues/14222))
- Stop fetching missing `prev_events` after we already know their signature is invalid. ([\#13816](https://github.com/matrix-org/synapse/issues/13816))
- Send application service access tokens as a header (and query parameter). Implements [MSC2832](https://github.com/matrix-org/matrix-spec-proposals/pull/2832). ([\#13996](https://github.com/matrix-org/synapse/issues/13996))
- Ignore server ACL changes when generating pushes. Implements [MSC3786](https://github.com/matrix-org/matrix-spec-proposals/pull/3786). ([\#13997](https://github.com/matrix-org/synapse/issues/13997))
- Experimental support for redirecting to an implementation of a [MSC3886](https://github.com/matrix-org/matrix-spec-proposals/pull/3886) HTTP rendezvous service. ([\#14018](https://github.com/matrix-org/synapse/issues/14018))
- The `/relations` endpoint can now be used on workers. ([\#14028](https://github.com/matrix-org/synapse/issues/14028))
- Advertise support for Matrix 1.3 and 1.4 on `/_matrix/client/versions`. ([\#14032](https://github.com/matrix-org/synapse/issues/14032), [\#14184](https://github.com/matrix-org/synapse/issues/14184))
- Improve validation of request bodies for the [Device Management](https://spec.matrix.org/v1.4/client-server-api/#device-management) and [MSC2697 Device Dehyrdation](https://github.com/matrix-org/matrix-spec-proposals/pull/2697) client-server API endpoints. ([\#14054](https://github.com/matrix-org/synapse/issues/14054))
- Experimental support for [MSC3874](https://github.com/matrix-org/matrix-spec-proposals/pull/3874): Filtering threads from the `/messages` endpoint. ([\#14148](https://github.com/matrix-org/synapse/issues/14148))
- Improve the validation of the following PUT endpoints: [`/directory/room/{roomAlias}`](https://spec.matrix.org/v1.4/client-server-api/#put_matrixclientv3directoryroomroomalias), [`/directory/list/room/{roomId}`](https://spec.matrix.org/v1.4/client-server-api/#put_matrixclientv3directorylistroomroomid) and [`/directory/list/appservice/{networkId}/{roomId}`](https://spec.matrix.org/v1.4/application-service-api/#put_matrixclientv3directorylistappservicenetworkidroomid). ([\#14179](https://github.com/matrix-org/synapse/issues/14179))
- Build and publish binary wheels for `aarch64` platforms. ([\#14212](https://github.com/matrix-org/synapse/issues/14212))


Bugfixes
--------

- Prevent device names from appearing in device list updates in some situations when `allow_device_name_lookup_over_federation` is `false`. (This is not comprehensive: see [\#13114](https://github.com/matrix-org/synapse/issues/13114).) ([\#10015](https://github.com/matrix-org/synapse/issues/10015))
- Fix a long-standing bug where redactions were not being sent over federation if we did not have the original event. ([\#13813](https://github.com/matrix-org/synapse/issues/13813))
- Fix a long-standing bug where edits of non-`m.room.message` events would not be correctly bundled or have their new content applied. ([\#14034](https://github.com/matrix-org/synapse/issues/14034))
- Fix a bug introduced in Synapse 1.53.0 when querying `/publicRooms` with both a `room_type` filter and a `third_party_instance_id`. ([\#14053](https://github.com/matrix-org/synapse/issues/14053))
- Fix a bug introduced in Synapse 1.35.0 where errors parsing a `/send_join` or `/state` response would produce excessive, low-quality Sentry events. ([\#14065](https://github.com/matrix-org/synapse/issues/14065))
- Fix a long-standing bug where Synapse would error on the optional 'invite_room_state' field not being provided to [`PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`](https://spec.matrix.org/v1.4/server-server-api/#put_matrixfederationv2inviteroomideventid). ([\#14083](https://github.com/matrix-org/synapse/issues/14083))
- Fix a bug where invalid oEmbed fields would cause the entire response to be discarded. Introduced in Synapse 1.18.0. ([\#14089](https://github.com/matrix-org/synapse/issues/14089))
- Fix a bug introduced in Synapse 1.37.0 in which an incorrect key name was used for sending and receiving room metadata when knocking on a room. ([\#14102](https://github.com/matrix-org/synapse/issues/14102))
- Fix a bug introduced in v1.69.0rc1 where the joined hosts for a given event were not being properly cached. ([\#14125](https://github.com/matrix-org/synapse/issues/14125))
- Fix a bug introduced in Synapse 1.30.0 where purging and rejoining a room without restarting in-between would result in a broken room. ([\#14161](https://github.com/matrix-org/synapse/issues/14161), [\#14164](https://github.com/matrix-org/synapse/issues/14164))
- Fix [MSC3030](https://github.com/matrix-org/matrix-spec-proposals/pull/3030) `/timestamp_to_event` endpoint returning potentially inaccurate closest events with `outliers` present. ([\#14215](https://github.com/matrix-org/synapse/issues/14215))


Updates to the Docker image
---------------------------

- Update the version of frozendict in Docker images and Debian packages from 2.3.3 to 2.3.4, which may fix memory leak problems. ([\#13955](https://github.com/matrix-org/synapse/issues/13955))
- Use the `minimal` Rust profile when building Synapse. ([\#14141](https://github.com/matrix-org/synapse/issues/14141))
- Prevent a class of database sharding errors when using `Dockerfile-workers` to spawn multiple instances of the same worker. Contributed by Jason Little. ([\#14165](https://github.com/matrix-org/synapse/issues/14165))
- Set `LD_PRELOAD` to use jemalloc memory allocator in Dockerfile-workers. ([\#14182](https://github.com/matrix-org/synapse/issues/14182))
- Fix pre-startup logging being lost when using the `Dockerfile-workers` image. ([\#14195](https://github.com/matrix-org/synapse/issues/14195))


Improved Documentation
----------------------

- Add sample worker files for `pusher` and `federation_sender`. ([\#14077](https://github.com/matrix-org/synapse/issues/14077))
- Improve the listener example on the metrics documentation. ([\#14078](https://github.com/matrix-org/synapse/issues/14078))
- Expand Google OpenID Connect example config to map email attribute. Contributed by @ptman. ([\#14081](https://github.com/matrix-org/synapse/issues/14081))
- The changelog entry ending in a full stop or exclamation mark is not optional. ([\#14087](https://github.com/matrix-org/synapse/issues/14087))
- Fix links to jemalloc documentation, which were broken in [#13491](https://github.com/matrix-org/synapse/pull/14124). ([\#14093](https://github.com/matrix-org/synapse/issues/14093))
- Remove not needed `replication` listener in docker compose example. ([\#14107](https://github.com/matrix-org/synapse/issues/14107))
- Fix name of `alias_creation_rules` option in the config manual documentation. ([\#14124](https://github.com/matrix-org/synapse/issues/14124))
- Clarify comment on event contexts. ([\#14145](https://github.com/matrix-org/synapse/issues/14145))
- Fix dead link to the [Admin Registration API](https://matrix-org.github.io/synapse/latest/admin_api/register_api.html). ([\#14189](https://github.com/matrix-org/synapse/issues/14189))


Deprecations and Removals
-------------------------

- Remove the experimental implementation of [MSC3772](https://github.com/matrix-org/matrix-spec-proposals/pull/3772). ([\#14094](https://github.com/matrix-org/synapse/issues/14094))
- Remove the unstable identifier for [MSC3715](https://github.com/matrix-org/matrix-doc/pull/3715). ([\#14106](https://github.com/matrix-org/synapse/issues/14106), [\#14146](https://github.com/matrix-org/synapse/issues/14146))


Internal Changes
----------------

- Optimise queries used to get a users rooms during sync. Contributed by Nick @ Beeper (@fizzadar). ([\#13991](https://github.com/matrix-org/synapse/issues/13991))
- Update authlib from 0.15.5 to 1.1.0. ([\#14006](https://github.com/matrix-org/synapse/issues/14006))
- Make `parse_server_name` consistent in handling invalid server names. ([\#14007](https://github.com/matrix-org/synapse/issues/14007))
- Don't repeatedly wake up the same users for batched events. ([\#14033](https://github.com/matrix-org/synapse/issues/14033))
- Complement test image: capture logs from nginx. ([\#14063](https://github.com/matrix-org/synapse/issues/14063))
- Don't create noisy Sentry events when a requester drops connection to the metrics server mid-request. ([\#14072](https://github.com/matrix-org/synapse/issues/14072))
- Run the integration test suites with the asyncio reactor enabled in CI. ([\#14092](https://github.com/matrix-org/synapse/issues/14092))
- Add debug logs to figure out why an event was filtered out of the client response. ([\#14095](https://github.com/matrix-org/synapse/issues/14095))
- Indicate what endpoint came back with a JSON response we were unable to parse. ([\#14097](https://github.com/matrix-org/synapse/issues/14097))
- Break up calls to fetch rooms for many users. Contributed by Nick @ Beeper (@fizzadar). ([\#14109](https://github.com/matrix-org/synapse/issues/14109))
- Faster joins: prioritise the server we joined by when restarting a partial join resync. ([\#14126](https://github.com/matrix-org/synapse/issues/14126))
- Cache Rust build cache when building docker images. ([\#14130](https://github.com/matrix-org/synapse/issues/14130))
- Enable dependabot for Rust dependencies. ([\#14132](https://github.com/matrix-org/synapse/issues/14132))
- Bump typing-extensions from 4.1.1 to 4.4.0. ([\#14134](https://github.com/matrix-org/synapse/issues/14134))
- Use the `minimal` Rust profile when building Synapse. ([\#14141](https://github.com/matrix-org/synapse/issues/14141))
- Remove unused configuration code. ([\#14142](https://github.com/matrix-org/synapse/issues/14142))
- Prepare for the [`gotestfmt` repository move](https://github.com/GoTestTools/gotestfmt/discussions/46). ([\#14144](https://github.com/matrix-org/synapse/issues/14144))
- Invalidate rooms for user caches on replicated event, fix sync cache race in synapse workers. Contributed by Nick @ Beeper (@fizzadar). ([\#14155](https://github.com/matrix-org/synapse/issues/14155))
- Enable url previews when testing with complement. ([\#14198](https://github.com/matrix-org/synapse/issues/14198))
- When authenticating batched events, check for auth events in batch as well as DB. ([\#14214](https://github.com/matrix-org/synapse/issues/14214))
- Update CI config to avoid GitHub Actions deprecation warnings. ([\#14216](https://github.com/matrix-org/synapse/issues/14216), [\#14224](https://github.com/matrix-org/synapse/issues/14224))
- Update dependency requirements to allow building with poetry-core 1.3.2. ([\#14217](https://github.com/matrix-org/synapse/issues/14217))
- Rename the `cache_memory` extra to `cache-memory`, for compatibility with poetry-core 1.3.0 and [PEP 685](https://peps.python.org/pep-0685/). From-source installations using this extra will need to install using the new name. ([\#14221](https://github.com/matrix-org/synapse/issues/14221))
- Specify dev-dependencies using lower bounds, to reduce the likelihood of a dependabot merge conflict. The lockfile continues to pin to specific versions. ([\#14227](https://github.com/matrix-org/synapse/issues/14227))


Synapse 1.69.0 (2022-10-17)
===========================

Please note that legacy Prometheus metric names are now deprecated and will be removed in Synapse 1.73.0.
Server administrators should update their dashboards and alerting rules to avoid using the deprecated metric names.
See the [upgrade notes](https://matrix-org.github.io/synapse/v1.69/upgrade.html#upgrading-to-v1690) for more details.


No significant changes since 1.69.0rc4.


Synapse 1.69.0rc4 (2022-10-14)
==============================

Bugfixes
--------

- Fix poor performance of the `event_push_backfill_thread_id` background update, which was introduced in Synapse 1.68.0rc1. ([\#14172](https://github.com/matrix-org/synapse/issues/14172), [\#14181](https://github.com/matrix-org/synapse/issues/14181))


Updates to the Docker image
---------------------------

- Fix docker build OOMing in CI for arm64 builds. ([\#14173](https://github.com/matrix-org/synapse/issues/14173))


Synapse 1.69.0rc3 (2022-10-12)
==============================

Bugfixes
--------

- Fix an issue with Docker images causing the Rust dependencies to not be pinned correctly. Introduced in v1.68.0 ([\#14129](https://github.com/matrix-org/synapse/issues/14129))
- Fix a bug introduced in Synapse 1.69.0rc1 which would cause registration replication requests to fail if the worker sending the request is not running Synapse 1.69. ([\#14135](https://github.com/matrix-org/synapse/issues/14135))
- Fix error in background update when rotating existing notifications. Introduced in v1.69.0rc2. ([\#14138](https://github.com/matrix-org/synapse/issues/14138))


Internal Changes
----------------

- Rename the `url_preview` extra to `url-preview`, for compatibility with poetry-core 1.3.0 and [PEP 685](https://peps.python.org/pep-0685/). From-source installations using this extra will need to install using the new name. ([\#14085](https://github.com/matrix-org/synapse/issues/14085))


Synapse 1.69.0rc2 (2022-10-06)
==============================

Deprecations and Removals
-------------------------

- Deprecate the `generate_short_term_login_token` method in favor of an async `create_login_token` method in the Module API. ([\#13842](https://github.com/matrix-org/synapse/issues/13842))


Internal Changes
----------------

- Ensure Synapse v1.69 works with upcoming database changes in v1.70. ([\#14045](https://github.com/matrix-org/synapse/issues/14045))
- Fix a bug introduced in Synapse v1.68.0 where messages could not be sent in rooms with non-integer `notifications` power level. ([\#14073](https://github.com/matrix-org/synapse/issues/14073))
- Temporarily pin build-system requirements to workaround an incompatibility with poetry-core 1.3.0. This will be reverted before the v1.69.0 release proper, see [\#14079](https://github.com/matrix-org/synapse/issues/14079). ([\#14080](https://github.com/matrix-org/synapse/issues/14080))


Synapse 1.69.0rc1 (2022-10-04)
==============================

Features
--------

- Allow application services to set the `origin_server_ts` of a state event by providing the query parameter `ts` in [`PUT /_matrix/client/r0/rooms/{roomId}/state/{eventType}/{stateKey}`](https://spec.matrix.org/v1.4/client-server-api/#put_matrixclientv3roomsroomidstateeventtypestatekey), per [MSC3316](https://github.com/matrix-org/matrix-doc/pull/3316). Contributed by @lukasdenk. ([\#11866](https://github.com/matrix-org/synapse/issues/11866))
- Allow server admins to require a manual approval process before new accounts can be used (using [MSC3866](https://github.com/matrix-org/matrix-spec-proposals/pull/3866)). ([\#13556](https://github.com/matrix-org/synapse/issues/13556))
- Exponentially backoff from backfilling the same event over and over. ([\#13635](https://github.com/matrix-org/synapse/issues/13635), [\#13936](https://github.com/matrix-org/synapse/issues/13936))
- Add cache invalidation across workers to module API. ([\#13667](https://github.com/matrix-org/synapse/issues/13667), [\#13947](https://github.com/matrix-org/synapse/issues/13947))
- Experimental implementation of [MSC3882](https://github.com/matrix-org/matrix-spec-proposals/pull/3882) to allow an existing device/session to generate a login token for use on a new device/session. ([\#13722](https://github.com/matrix-org/synapse/issues/13722), [\#13868](https://github.com/matrix-org/synapse/issues/13868))
- Experimental support for thread-specific receipts ([MSC3771](https://github.com/matrix-org/matrix-spec-proposals/pull/3771)). ([\#13782](https://github.com/matrix-org/synapse/issues/13782), [\#13893](https://github.com/matrix-org/synapse/issues/13893), [\#13932](https://github.com/matrix-org/synapse/issues/13932), [\#13937](https://github.com/matrix-org/synapse/issues/13937), [\#13939](https://github.com/matrix-org/synapse/issues/13939))
- Add experimental support for [MSC3881: Remotely toggle push notifications for another client](https://github.com/matrix-org/matrix-spec-proposals/pull/3881). ([\#13799](https://github.com/matrix-org/synapse/issues/13799), [\#13831](https://github.com/matrix-org/synapse/issues/13831), [\#13860](https://github.com/matrix-org/synapse/issues/13860))
- Keep track when an event pulled over federation fails its signature check so we can intelligently back-off in the future. ([\#13815](https://github.com/matrix-org/synapse/issues/13815))
- Improve validation for the unspecced, internal-only `_matrix/client/unstable/add_threepid/msisdn/submit_token` endpoint. ([\#13832](https://github.com/matrix-org/synapse/issues/13832))
- Faster remote room joins: record _when_ we first partial-join to a room. ([\#13892](https://github.com/matrix-org/synapse/issues/13892))
- Support a `dir` parameter on the `/relations` endpoint per [MSC3715](https://github.com/matrix-org/matrix-doc/pull/3715). ([\#13920](https://github.com/matrix-org/synapse/issues/13920))
- Ask mail servers receiving emails from Synapse to not send automatic replies (e.g. out-of-office responses). ([\#13957](https://github.com/matrix-org/synapse/issues/13957))


Bugfixes
--------

- Send push notifications for invites received over federation. ([\#13719](https://github.com/matrix-org/synapse/issues/13719), [\#14014](https://github.com/matrix-org/synapse/issues/14014))
- Fix a long-standing bug where typing events would be accepted from remote servers not present in a room. Also fix a bug where incoming typing events would cause other incoming events to get stuck during a fast join. ([\#13830](https://github.com/matrix-org/synapse/issues/13830))
- Fix a bug introduced in Synapse v1.53.0 where the experimental implementation of [MSC3715](https://github.com/matrix-org/matrix-spec-proposals/pull/3715) would give incorrect results when paginating forward. ([\#13840](https://github.com/matrix-org/synapse/issues/13840))
- Fix access token leak to logs from proxy agent. ([\#13855](https://github.com/matrix-org/synapse/issues/13855))
- Fix `have_seen_event` cache not being invalidated after we persist an event which causes inefficiency effects like extra `/state` federation calls. ([\#13863](https://github.com/matrix-org/synapse/issues/13863))
- Faster room joins: Fix a bug introduced in 1.66.0 where an error would be logged when syncing after joining a room. ([\#13872](https://github.com/matrix-org/synapse/issues/13872))
- Fix a bug introduced in 1.66.0 where some required fields in the pushrules sent to clients were not present anymore. Contributed by Nico. ([\#13904](https://github.com/matrix-org/synapse/issues/13904))
- Fix packaging to include `Cargo.lock` in `sdist`. ([\#13909](https://github.com/matrix-org/synapse/issues/13909))
- Fix a long-standing bug where device updates could cause delays sending out to-device messages over federation. ([\#13922](https://github.com/matrix-org/synapse/issues/13922))
- Fix a bug introduced in v1.68.0 where Synapse would require `setuptools_rust` at runtime, even though the package is only required at build time. ([\#13952](https://github.com/matrix-org/synapse/issues/13952))
- Fix a long-standing bug where `POST /_matrix/client/v3/keys/query` requests could result in excessively large SQL queries. ([\#13956](https://github.com/matrix-org/synapse/issues/13956))
- Fix a performance regression in the `get_users_in_room` database query. Introduced in v1.67.0. ([\#13972](https://github.com/matrix-org/synapse/issues/13972))
- Fix a bug introduced in v1.68.0 bug where Rust extension wasn't built in `release` mode when using `poetry install`. ([\#14009](https://github.com/matrix-org/synapse/issues/14009))
- Do not return an unspecified `original_event` field when using the stable `/relations` endpoint. Introduced in Synapse v1.57.0. ([\#14025](https://github.com/matrix-org/synapse/issues/14025))
- Correctly handle a race with device lists when a remote user leaves during a partial join. ([\#13885](https://github.com/matrix-org/synapse/issues/13885))
- Correctly handle sending local device list updates to remote servers during a partial join. ([\#13934](https://github.com/matrix-org/synapse/issues/13934))


Improved Documentation
----------------------

- Add `worker_main_http_uri` for the worker generator bash script. ([\#13772](https://github.com/matrix-org/synapse/issues/13772))
- Update URL for the NixOS module for Synapse. ([\#13818](https://github.com/matrix-org/synapse/issues/13818))
- Fix a mistake in sso_mapping_providers.md: `map_user_attributes` is expected to return `display_name`, not `displayname`. ([\#13836](https://github.com/matrix-org/synapse/issues/13836))
- Fix a cross-link from the registration admin API to the `registration_shared_secret` configuration documentation. ([\#13870](https://github.com/matrix-org/synapse/issues/13870))
- Update the man page for the `hash_password` script to correct the default number of bcrypt rounds performed. ([\#13911](https://github.com/matrix-org/synapse/issues/13911), [\#13930](https://github.com/matrix-org/synapse/issues/13930))
- Emphasize the right reasons when to use `(room_id, event_id)` in a database schema. ([\#13915](https://github.com/matrix-org/synapse/issues/13915))
- Add instruction to contributing guide for running unit tests in parallel. Contributed by @ashfame. ([\#13928](https://github.com/matrix-org/synapse/issues/13928))
- Clarify that the `auto_join_rooms` config option can also be used with Space aliases. ([\#13931](https://github.com/matrix-org/synapse/issues/13931))
- Add some cross references to worker documentation. ([\#13974](https://github.com/matrix-org/synapse/issues/13974))
- Linkify urls in config documentation. ([\#14003](https://github.com/matrix-org/synapse/issues/14003))


Deprecations and Removals
-------------------------

- Remove the `complete_sso_login` method from the Module API which was deprecated in Synapse 1.13.0. ([\#13843](https://github.com/matrix-org/synapse/issues/13843))
- Announce that legacy metric names are deprecated, will be turned off by default in Synapse v1.71.0 and removed altogether in Synapse v1.73.0. See the upgrade notes for more information. ([\#14024](https://github.com/matrix-org/synapse/issues/14024))


Internal Changes
----------------

- Speed up creation of DM rooms. ([\#13487](https://github.com/matrix-org/synapse/issues/13487), [\#13800](https://github.com/matrix-org/synapse/issues/13800))
- Port push rules to using Rust. ([\#13768](https://github.com/matrix-org/synapse/issues/13768), [\#13838](https://github.com/matrix-org/synapse/issues/13838), [\#13889](https://github.com/matrix-org/synapse/issues/13889))
- Optimise get rooms for user calls. Contributed by Nick @ Beeper (@fizzadar). ([\#13787](https://github.com/matrix-org/synapse/issues/13787))
- Update the script which makes full schema dumps. ([\#13792](https://github.com/matrix-org/synapse/issues/13792))
- Use shared methods for cache invalidation when persisting events, remove duplicate codepaths. Contributed by Nick @ Beeper (@fizzadar). ([\#13796](https://github.com/matrix-org/synapse/issues/13796))
- Improve the `synapse.api.auth.Auth` mock used in unit tests. ([\#13809](https://github.com/matrix-org/synapse/issues/13809))
- Faster Remote Room Joins: tell remote homeservers that we are unable to authorise them if they query a room which has partial state on our server. ([\#13823](https://github.com/matrix-org/synapse/issues/13823))
- Carry IdP Session IDs through user-mapping sessions. ([\#13839](https://github.com/matrix-org/synapse/issues/13839))
- Fix the release script not publishing binary wheels. ([\#13850](https://github.com/matrix-org/synapse/issues/13850))
- Raise issue if complement fails with latest deps. ([\#13859](https://github.com/matrix-org/synapse/issues/13859))
- Correct the comments in the complement dockerfile. ([\#13867](https://github.com/matrix-org/synapse/issues/13867))
- Create a new snapshot of the database schema. ([\#13873](https://github.com/matrix-org/synapse/issues/13873))
- Faster room joins: Send device list updates to most servers in rooms with partial state. ([\#13874](https://github.com/matrix-org/synapse/issues/13874), [\#14013](https://github.com/matrix-org/synapse/issues/14013))
- Add comments to the Prometheus recording rules to make it clear which set of rules you need for Grafana or Prometheus Console. ([\#13876](https://github.com/matrix-org/synapse/issues/13876))
- Only pull relevant backfill points from the database based on the current depth and limit (instead of all) every time we want to `/backfill`. ([\#13879](https://github.com/matrix-org/synapse/issues/13879))
- Faster room joins: Avoid waiting for full state when processing `/keys/changes` requests. ([\#13888](https://github.com/matrix-org/synapse/issues/13888))
- Improve backfill robustness by trying more servers when we get a `4xx` error back. ([\#13890](https://github.com/matrix-org/synapse/issues/13890))
- Fix mypy errors with canonicaljson 1.6.3. ([\#13905](https://github.com/matrix-org/synapse/issues/13905))
- Faster remote room joins: correctly handle remote device list updates during a partial join. ([\#13913](https://github.com/matrix-org/synapse/issues/13913))
- Complement image: propagate SIGTERM to all workers. ([\#13914](https://github.com/matrix-org/synapse/issues/13914))
- Update an innaccurate comment in Synapse's upsert database helper. ([\#13924](https://github.com/matrix-org/synapse/issues/13924))
- Update mypy (0.950 -> 0.981) and mypy-zope (0.3.7 -> 0.3.11). ([\#13925](https://github.com/matrix-org/synapse/issues/13925), [\#13993](https://github.com/matrix-org/synapse/issues/13993))
- Use dedicated `get_local_users_in_room(room_id)` function to find local users when calculating users to copy over during a room upgrade. ([\#13960](https://github.com/matrix-org/synapse/issues/13960))
- Refactor language in user directory `_track_user_joined_room` code to make it more clear that we use both local and remote users. ([\#13966](https://github.com/matrix-org/synapse/issues/13966))
- Revert catch-all exceptions being recorded as event pull attempt failures (only handle what we know about). ([\#13969](https://github.com/matrix-org/synapse/issues/13969))
- Speed up calculating push actions in large rooms. ([\#13973](https://github.com/matrix-org/synapse/issues/13973), [\#13992](https://github.com/matrix-org/synapse/issues/13992))
- Enable update notifications from Github's dependabot. ([\#13976](https://github.com/matrix-org/synapse/issues/13976))
- Prototype a workflow to automatically add changelogs to dependabot PRs. ([\#13998](https://github.com/matrix-org/synapse/issues/13998), [\#14011](https://github.com/matrix-org/synapse/issues/14011), [\#14017](https://github.com/matrix-org/synapse/issues/14017), [\#14021](https://github.com/matrix-org/synapse/issues/14021), [\#14027](https://github.com/matrix-org/synapse/issues/14027))
- Fix type annotations to be compatible with new annotations in development versions of twisted. ([\#14012](https://github.com/matrix-org/synapse/issues/14012))
- Clear out stale entries in `event_push_actions_staging` table. ([\#14020](https://github.com/matrix-org/synapse/issues/14020))
- Bump versions of GitHub actions. ([\#13978](https://github.com/matrix-org/synapse/issues/13978), [\#13979](https://github.com/matrix-org/synapse/issues/13979), [\#13980](https://github.com/matrix-org/synapse/issues/13980), [\#13982](https://github.com/matrix-org/synapse/issues/13982), [\#14015](https://github.com/matrix-org/synapse/issues/14015), [\#14019](https://github.com/matrix-org/synapse/issues/14019), [\#14022](https://github.com/matrix-org/synapse/issues/14022), [\#14023](https://github.com/matrix-org/synapse/issues/14023))


Synapse 1.68.0 (2022-09-27)
===========================

Please note that Synapse will now refuse to start if configured to use a version of SQLite older than 3.27.

In addition, please note that installing Synapse from a source checkout now requires a recent Rust compiler.
Those using packages will not be affected. On most platforms, installing with `pip install matrix-synapse` will not be affected.
See the [upgrade notes](https://matrix-org.github.io/synapse/v1.68/upgrade.html#upgrading-to-v1680).

Bugfixes
--------

- Fix packaging to include `Cargo.lock` in `sdist`. ([\#13909](https://github.com/matrix-org/synapse/issues/13909))


Synapse 1.68.0rc2 (2022-09-23)
==============================

Bugfixes
--------

- Fix building from packaged sdist. Broken in v1.68.0rc1. ([\#13866](https://github.com/matrix-org/synapse/issues/13866))


Internal Changes
----------------

- Fix the release script not publishing binary wheels. ([\#13850](https://github.com/matrix-org/synapse/issues/13850))
- Lower minimum supported rustc version to 1.58.1. ([\#13857](https://github.com/matrix-org/synapse/issues/13857))
- Lock Rust dependencies' versions. ([\#13858](https://github.com/matrix-org/synapse/issues/13858))


Synapse 1.68.0rc1 (2022-09-20)
==============================

Features
--------

- Keep track of when we fail to process a pulled event over federation so we can intelligently back off in the future. ([\#13589](https://github.com/matrix-org/synapse/issues/13589), [\#13814](https://github.com/matrix-org/synapse/issues/13814))
- Add an [admin API endpoint to fetch messages within a particular window of time](https://matrix-org.github.io/synapse/v1.68/admin_api/rooms.html#room-messages-api). ([\#13672](https://github.com/matrix-org/synapse/issues/13672))
- Add an [admin API endpoint to find a user based on their external ID in an auth provider](https://matrix-org.github.io/synapse/v1.68/admin_api/user_admin_api.html#find-a-user-based-on-their-id-in-an-auth-provider). ([\#13810](https://github.com/matrix-org/synapse/issues/13810))
- Cancel the processing of key query requests when they time out. ([\#13680](https://github.com/matrix-org/synapse/issues/13680))
- Improve validation of request bodies for the following client-server API endpoints: [`/account/3pid/msisdn/requestToken`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3pidmsisdnrequesttoken), [`/org.matrix.msc3720/account_status`](https://github.com/matrix-org/matrix-spec-proposals/blob/babolivier/user_status/proposals/3720-account-status.md#post-_matrixclientv1account_status), [`/account/3pid/add`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3pidadd), [`/account/3pid/bind`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3pidbind), [`/account/3pid/delete`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3piddelete) and [`/account/3pid/unbind`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3pidunbind). ([\#13687](https://github.com/matrix-org/synapse/issues/13687), [\#13736](https://github.com/matrix-org/synapse/issues/13736))
- Document the timestamp when a user accepts the consent, if [consent tracking](https://matrix-org.github.io/synapse/latest/consent_tracking.html) is used. ([\#13741](https://github.com/matrix-org/synapse/issues/13741))
- Add a `listeners[x].request_id_header` configuration option to specify which request header to extract and use as the request ID in order to correlate requests from a reverse proxy. ([\#13801](https://github.com/matrix-org/synapse/issues/13801))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.41.0 where the `/hierarchy` API returned non-standard information (a `room_id` field under each entry in `children_state`). ([\#13506](https://github.com/matrix-org/synapse/issues/13506))
- Fix a long-standing bug where previously rejected events could end up in room state because they pass auth checks given the current state of the room. ([\#13723](https://github.com/matrix-org/synapse/issues/13723))
- Fix a long-standing bug where Synapse fails to start if a signing key file contains an empty line. ([\#13738](https://github.com/matrix-org/synapse/issues/13738))
- Fix a long-standing bug where Synapse would fail to handle malformed user IDs or room aliases gracefully in certain cases. ([\#13746](https://github.com/matrix-org/synapse/issues/13746))
- Fix a long-standing bug where device lists would remain cached when remote users left and rejoined the last room shared with the local homeserver. ([\#13749](https://github.com/matrix-org/synapse/issues/13749), [\#13826](https://github.com/matrix-org/synapse/issues/13826))
- Fix a long-standing bug that could cause stale caches in some rare cases on the first startup of Synapse with replication. ([\#13766](https://github.com/matrix-org/synapse/issues/13766))
- Fix a long-standing spec compliance bug where Synapse would accept a trailing slash on the end of `/get_missing_events` federation requests. ([\#13789](https://github.com/matrix-org/synapse/issues/13789))
- Delete associated data from `event_failed_pull_attempts`, `insertion_events`, `insertion_event_extremities`, `insertion_event_extremities`, `insertion_event_extremities` when purging the room. ([\#13825](https://github.com/matrix-org/synapse/issues/13825))


Improved Documentation
----------------------

- Note that `libpq` is required on ARM-based Macs. ([\#13480](https://github.com/matrix-org/synapse/issues/13480))
- Fix a mistake in the config manual introduced in Synapse 1.22.0: the `event_cache_size` _is_ scaled by `caches.global_factor`. ([\#13726](https://github.com/matrix-org/synapse/issues/13726))
- Fix a typo in the documentation for the login ratelimiting configuration. ([\#13727](https://github.com/matrix-org/synapse/issues/13727))
- Define Synapse's compatibility policy for SQLite versions. ([\#13728](https://github.com/matrix-org/synapse/issues/13728))
- Add docs for the common fix of deleting the `matrix_synapse.egg-info/` directory for fixing Python dependency problems. ([\#13785](https://github.com/matrix-org/synapse/issues/13785))
- Update request log format documentation to mention the format used when the authenticated user is controlling another user. ([\#13794](https://github.com/matrix-org/synapse/issues/13794))


Deprecations and Removals
-------------------------

- Synapse will now refuse to start if configured to use SQLite < 3.27. ([\#13760](https://github.com/matrix-org/synapse/issues/13760))
- Don't include redundant `prev_state` in new events. Contributed by Denis Kariakin (@dakariakin). ([\#13791](https://github.com/matrix-org/synapse/issues/13791))


Internal Changes
----------------

- Add a stub Rust crate. ([\#12595](https://github.com/matrix-org/synapse/issues/12595), [\#13734](https://github.com/matrix-org/synapse/issues/13734), [\#13735](https://github.com/matrix-org/synapse/issues/13735), [\#13743](https://github.com/matrix-org/synapse/issues/13743), [\#13763](https://github.com/matrix-org/synapse/issues/13763), [\#13769](https://github.com/matrix-org/synapse/issues/13769), [\#13778](https://github.com/matrix-org/synapse/issues/13778))
- Bump the minimum dependency of `matrix_common` to 1.3.0 to make use of the `MXCUri` class. Use `MXCUri` to simplify media retention test code. ([\#13162](https://github.com/matrix-org/synapse/issues/13162))
- Add and populate the `event_stream_ordering` column on the `receipts` table for future optimisation of push action processing. Contributed by Nick @ Beeper (@fizzadar). ([\#13703](https://github.com/matrix-org/synapse/issues/13703))
- Rename the `EventFormatVersions` enum values so that they line up with room version numbers. ([\#13706](https://github.com/matrix-org/synapse/issues/13706))
- Update trial old deps CI to use Poetry 1.2.0. ([\#13707](https://github.com/matrix-org/synapse/issues/13707), [\#13725](https://github.com/matrix-org/synapse/issues/13725))
- Add experimental configuration option to allow disabling legacy Prometheus metric names. ([\#13714](https://github.com/matrix-org/synapse/issues/13714), [\#13717](https://github.com/matrix-org/synapse/issues/13717), [\#13718](https://github.com/matrix-org/synapse/issues/13718))
- Fix typechecking with latest types-jsonschema. ([\#13724](https://github.com/matrix-org/synapse/issues/13724))
- Strip number suffix from instance name to consolidate services that traces are spread over. ([\#13729](https://github.com/matrix-org/synapse/issues/13729))
- Instrument `get_metadata_for_events` for understandable traces in Jaeger. ([\#13730](https://github.com/matrix-org/synapse/issues/13730))
- Remove old queries to join room memberships to current state events. Contributed by Nick @ Beeper (@fizzadar). ([\#13745](https://github.com/matrix-org/synapse/issues/13745))
- Avoid raising an error due to malformed user IDs in `get_current_hosts_in_room`. Malformed user IDs cannot currently join a room, so this error would not be hit. ([\#13748](https://github.com/matrix-org/synapse/issues/13748))
- Update the docstrings for `get_users_in_room` and `get_current_hosts_in_room` to explain the impact of partial state. ([\#13750](https://github.com/matrix-org/synapse/issues/13750))
- Use an additional database query when persisting receipts. ([\#13752](https://github.com/matrix-org/synapse/issues/13752))
- Preparatory work for storing thread IDs for notifications and receipts. ([\#13753](https://github.com/matrix-org/synapse/issues/13753))
- Re-type hint some collections as read-only. ([\#13754](https://github.com/matrix-org/synapse/issues/13754))
- Remove unused Prometheus recording rules from `synapse-v2.rules` and add comments describing where the rest are used. ([\#13756](https://github.com/matrix-org/synapse/issues/13756))
- Add a check for editable installs if the Rust library needs rebuilding. ([\#13759](https://github.com/matrix-org/synapse/issues/13759))
- Tag traces with the instance name to be able to easily jump into the right logs and filter traces by instance. ([\#13761](https://github.com/matrix-org/synapse/issues/13761))
- Concurrently fetch room push actions when calculating badge counts. Contributed by Nick @ Beeper (@fizzadar). ([\#13765](https://github.com/matrix-org/synapse/issues/13765))
- Update the script which makes full schema dumps. ([\#13770](https://github.com/matrix-org/synapse/issues/13770))
- Deduplicate `is_server_notices_room`. ([\#13780](https://github.com/matrix-org/synapse/issues/13780))
- Simplify the dependency DAG in the tests workflow. ([\#13784](https://github.com/matrix-org/synapse/issues/13784))
- Remove an old, incorrect migration file. ([\#13788](https://github.com/matrix-org/synapse/issues/13788))
- Remove unused method in `synapse.api.auth.Auth`. ([\#13795](https://github.com/matrix-org/synapse/issues/13795))
- Fix a memory leak when running the unit tests. ([\#13798](https://github.com/matrix-org/synapse/issues/13798))
- Use partial indices on SQLite. ([\#13802](https://github.com/matrix-org/synapse/issues/13802))
- Check that portdb generates the same postgres schema as that in the source tree. ([\#13808](https://github.com/matrix-org/synapse/issues/13808))
- Fix Docker build when Rust .so has been built locally first. ([\#13811](https://github.com/matrix-org/synapse/issues/13811))
- Complement: Initialise the Postgres database directly inside the target image instead of the base Postgres image to fix building using Buildah. ([\#13819](https://github.com/matrix-org/synapse/issues/13819))
- Support providing an index predicate clause when doing upserts. ([\#13822](https://github.com/matrix-org/synapse/issues/13822))
- Minor speedups to linting in CI. ([\#13827](https://github.com/matrix-org/synapse/issues/13827))


Synapse 1.67.0 (2022-09-13)
===========================

This release removes using the deprecated direct TCP replication configuration
for workers. Server admins should use Redis instead. See the [upgrade
notes](https://matrix-org.github.io/synapse/v1.67/upgrade.html#upgrading-to-v1670).

The minimum version of `poetry` supported for managing source checkouts is now
1.2.0.

**Notice:** from the next major release (1.68.0) installing Synapse from a source
checkout will require a recent Rust compiler. Those using packages or
`pip install matrix-synapse` will not be affected. See the [upgrade
notes](https://matrix-org.github.io/synapse/v1.67/upgrade.html#upgrading-to-v1670).

**Notice:** from the next major release (1.68.0), running Synapse with a SQLite
database will require SQLite version 3.27.0 or higher. (The [current minimum
 version is SQLite 3.22.0](https://github.com/matrix-org/synapse/blob/release-v1.67/synapse/storage/engines/sqlite.py#L69-L78).)
See [#12983](https://github.com/matrix-org/synapse/issues/12983) and the [upgrade notes](https://matrix-org.github.io/synapse/v1.67/upgrade.html#upgrading-to-v1670) for more details.


No significant changes since 1.67.0rc1.


Synapse 1.67.0rc1 (2022-09-06)
==============================

Features
--------

- Support setting the registration shared secret in a file, via a new `registration_shared_secret_path` configuration option. ([\#13614](https://github.com/matrix-org/synapse/issues/13614))
- Change the default startup behaviour so that any missing "additional" configuration files (signing key, etc) are generated automatically. ([\#13615](https://github.com/matrix-org/synapse/issues/13615))
- Improve performance of sending messages in rooms with thousands of local users. ([\#13634](https://github.com/matrix-org/synapse/issues/13634))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.13 where the [List Rooms admin API](https://matrix-org.github.io/synapse/develop/admin_api/rooms.html#list-room-api) would return integers instead of booleans for the `federatable` and `public` fields when using a Sqlite database. ([\#13509](https://github.com/matrix-org/synapse/issues/13509))
- Fix bug that user cannot `/forget` rooms after the last member has left the room. ([\#13546](https://github.com/matrix-org/synapse/issues/13546))
- Faster Room Joins: fix `/make_knock` blocking indefinitely when the room in question is a partial-stated room. ([\#13583](https://github.com/matrix-org/synapse/issues/13583))
- Fix loading the current stream position behind the actual position. ([\#13585](https://github.com/matrix-org/synapse/issues/13585))
- Fix a longstanding bug in `register_new_matrix_user` which meant it was always necessary to explicitly give a server URL. ([\#13616](https://github.com/matrix-org/synapse/issues/13616))
- Fix the running of [MSC1763](https://github.com/matrix-org/matrix-spec-proposals/pull/1763) retention purge_jobs in deployments with background jobs running on a worker by forcing them back onto the main worker. Contributed by Brad @ Beeper. ([\#13632](https://github.com/matrix-org/synapse/issues/13632))
- Fix a long-standing bug that downloaded media for URL previews was not deleted while database background updates were running. ([\#13657](https://github.com/matrix-org/synapse/issues/13657))
- Fix [MSC3030](https://github.com/matrix-org/matrix-spec-proposals/pull/3030) `/timestamp_to_event` endpoint to return the correct next event when the events have the same timestamp. ([\#13658](https://github.com/matrix-org/synapse/issues/13658))
- Fix bug where we wedge media plugins if clients disconnect early. Introduced in v1.22.0. ([\#13660](https://github.com/matrix-org/synapse/issues/13660))
- Fix a long-standing bug which meant that keys for unwhitelisted servers were not returned by `/_matrix/key/v2/query`. ([\#13683](https://github.com/matrix-org/synapse/issues/13683))
- Fix a bug introduced in Synapse 1.20.0 that would cause the unstable unread counts from [MSC2654](https://github.com/matrix-org/matrix-spec-proposals/pull/2654) to be calculated even if the feature is disabled. ([\#13694](https://github.com/matrix-org/synapse/issues/13694))


Updates to the Docker image
---------------------------

- Update docker image to use a stable version of poetry. ([\#13688](https://github.com/matrix-org/synapse/issues/13688))


Improved Documentation
----------------------

- Improve the description of the ["chain cover index"](https://matrix-org.github.io/synapse/latest/auth_chain_difference_algorithm.html) used internally by Synapse. ([\#13602](https://github.com/matrix-org/synapse/issues/13602))
- Document how ["monthly active users"](https://matrix-org.github.io/synapse/latest/usage/administration/monthly_active_users.html) is calculated and used. ([\#13617](https://github.com/matrix-org/synapse/issues/13617))
- Improve documentation around user registration. ([\#13640](https://github.com/matrix-org/synapse/issues/13640))
- Remove documentation of legacy `frontend_proxy` worker app. ([\#13645](https://github.com/matrix-org/synapse/issues/13645))
- Clarify documentation that HTTP replication traffic can be protected with a shared secret. ([\#13656](https://github.com/matrix-org/synapse/issues/13656))
- Remove unintentional colons from [config manual](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html) headers. ([\#13665](https://github.com/matrix-org/synapse/issues/13665))
- Update docs to make enabling metrics more clear. ([\#13678](https://github.com/matrix-org/synapse/issues/13678))
- Clarify `(room_id, event_id)` global uniqueness and how we should scope our database schemas. ([\#13701](https://github.com/matrix-org/synapse/issues/13701))


Deprecations and Removals
-------------------------

- Drop support for calling `/_matrix/client/v3/rooms/{roomId}/invite` without an `id_access_token`, which was not permitted by the spec. Contributed by @Vetchu. ([\#13241](https://github.com/matrix-org/synapse/issues/13241))
- Remove redundant `_get_joined_users_from_context` cache. Contributed by Nick @ Beeper (@fizzadar). ([\#13569](https://github.com/matrix-org/synapse/issues/13569))
- Remove the ability to use direct TCP replication with workers. Direct TCP replication was deprecated in Synapse 1.18.0. Workers now require using Redis. ([\#13647](https://github.com/matrix-org/synapse/issues/13647))
- Remove support for unstable [private read receipts](https://github.com/matrix-org/matrix-spec-proposals/pull/2285). ([\#13653](https://github.com/matrix-org/synapse/issues/13653), [\#13692](https://github.com/matrix-org/synapse/issues/13692))


Internal Changes
----------------

- Extend the release script to wait for GitHub Actions to finish and to be usable as a guide for the whole process. ([\#13483](https://github.com/matrix-org/synapse/issues/13483))
- Add experimental configuration option to allow disabling legacy Prometheus metric names. ([\#13540](https://github.com/matrix-org/synapse/issues/13540))
- Cache user IDs instead of profiles to reduce cache memory usage. Contributed by Nick @ Beeper (@fizzadar). ([\#13573](https://github.com/matrix-org/synapse/issues/13573), [\#13600](https://github.com/matrix-org/synapse/issues/13600))
- Optimize how Synapse calculates domains to fetch from during backfill. ([\#13575](https://github.com/matrix-org/synapse/issues/13575))
- Comment about a better future where we can get the state diff between two events. ([\#13586](https://github.com/matrix-org/synapse/issues/13586))
- Instrument `_check_sigs_and_hash_and_fetch` to trace time spent in child concurrent calls for understandable traces in Jaeger. ([\#13588](https://github.com/matrix-org/synapse/issues/13588))
- Improve performance of `@cachedList`. ([\#13591](https://github.com/matrix-org/synapse/issues/13591))
- Minor speed up of fetching large numbers of push rules. ([\#13592](https://github.com/matrix-org/synapse/issues/13592))
- Optimise push action fetching queries. Contributed by Nick @ Beeper (@fizzadar). ([\#13597](https://github.com/matrix-org/synapse/issues/13597))
- Rename `event_map` to `unpersisted_events` when computing the auth differences. ([\#13603](https://github.com/matrix-org/synapse/issues/13603))
- Refactor `get_users_in_room(room_id)` mis-use with dedicated `get_current_hosts_in_room(room_id)` function. ([\#13605](https://github.com/matrix-org/synapse/issues/13605))
- Use dedicated `get_local_users_in_room(room_id)` function to find local users when calculating `join_authorised_via_users_server` of a `/make_join` request. ([\#13606](https://github.com/matrix-org/synapse/issues/13606))
- Refactor `get_users_in_room(room_id)` mis-use to lookup single local user with dedicated `check_local_user_in_room(...)` function. ([\#13608](https://github.com/matrix-org/synapse/issues/13608))
- Drop unused column `application_services_state.last_txn`. ([\#13627](https://github.com/matrix-org/synapse/issues/13627))
- Improve readability of Complement CI logs by printing failure results last. ([\#13639](https://github.com/matrix-org/synapse/issues/13639))
- Generalise the `@cancellable` annotation so it can be used on functions other than just servlet methods. ([\#13662](https://github.com/matrix-org/synapse/issues/13662))
- Introduce a `CommonUsageMetrics` class to share some usage metrics between the Prometheus exporter and the phone home stats. ([\#13671](https://github.com/matrix-org/synapse/issues/13671))
- Add some logging to help track down #13444. ([\#13679](https://github.com/matrix-org/synapse/issues/13679))
- Update poetry lock file for v1.2.0. ([\#13689](https://github.com/matrix-org/synapse/issues/13689))
- Add cache to `is_partial_state_room`. ([\#13693](https://github.com/matrix-org/synapse/issues/13693))
- Update the Grafana dashboard that is included with Synapse in the `contrib` directory. ([\#13697](https://github.com/matrix-org/synapse/issues/13697))
- Only run trial CI on all python versions on non-PRs. ([\#13698](https://github.com/matrix-org/synapse/issues/13698))
- Fix typechecking with latest types-jsonschema. ([\#13712](https://github.com/matrix-org/synapse/issues/13712))
- Reduce number of CI checks we run for PRs. ([\#13713](https://github.com/matrix-org/synapse/issues/13713))


Synapse 1.66.0 (2022-08-31)
===========================

No significant changes since 1.66.0rc2.

This release removes the ability for homeservers to delegate email ownership
verification and password reset confirmation to identity servers. This removal
was originally planned for Synapse 1.64, but was later deferred until now. See
the [upgrade notes](https://matrix-org.github.io/synapse/v1.66/upgrade.html#upgrading-to-v1660) for more details.

Deployments with multiple workers should note that the direct TCP replication
configuration was deprecated in Synapse 1.18.0 and will be removed in Synapse
v1.67.0. In particular, the TCP `replication` [listener](https://matrix-org.github.io/synapse/v1.66/usage/configuration/config_documentation.html#listeners)
type (not to be confused with the `replication` resource on the `http` listener
type) and the `worker_replication_port` config option will be removed .

To migrate to Redis, add the [`redis` config](https://matrix-org.github.io/synapse/v1.66/workers.html#shared-configuration),
then remove the TCP `replication` listener from config of the master and
`worker_replication_port` from worker config. Note that a HTTP listener with a
`replication` resource is still required. See the
[worker documentation](https://matrix-org.github.io/synapse/v1.66/workers.html)
for more details.


Synapse 1.66.0rc2 (2022-08-30)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.66.0rc1 where the new rate limit metrics were misreported (`synapse_rate_limit_sleep_affected_hosts`, `synapse_rate_limit_reject_affected_hosts`). ([\#13649](https://github.com/matrix-org/synapse/issues/13649))


Synapse 1.66.0rc1 (2022-08-23)
==============================

Features
--------

- Improve validation of request bodies for the following client-server API endpoints: [`/account/password`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3accountpassword), [`/account/password/email/requestToken`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3accountpasswordemailrequesttoken), [`/account/deactivate`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3accountdeactivate) and [`/account/3pid/email/requestToken`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3account3pidemailrequesttoken). ([\#13188](https://github.com/matrix-org/synapse/issues/13188), [\#13563](https://github.com/matrix-org/synapse/issues/13563))
- Add forgotten status to [Room Details Admin API](https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#room-details-api). ([\#13503](https://github.com/matrix-org/synapse/issues/13503))
- Add an experimental implementation for [MSC3852 (Expose user agents on `Device`)](https://github.com/matrix-org/matrix-spec-proposals/pull/3852). ([\#13549](https://github.com/matrix-org/synapse/issues/13549))
- Add `org.matrix.msc2716v4` experimental room version with updated content fields. Part of [MSC2716 (Importing history)](https://github.com/matrix-org/matrix-spec-proposals/pull/2716).  ([\#13551](https://github.com/matrix-org/synapse/issues/13551))
- Add support for compression to federation responses. ([\#13537](https://github.com/matrix-org/synapse/issues/13537))
- Improve performance of sending messages in rooms with thousands of local users. ([\#13522](https://github.com/matrix-org/synapse/issues/13522), [\#13547](https://github.com/matrix-org/synapse/issues/13547))


Bugfixes
--------

- Faster room joins: make `/joined_members` block whilst the room is partial stated. ([\#13514](https://github.com/matrix-org/synapse/issues/13514))
- Fix a bug introduced in Synapse 1.21.0 where the [`/event_reports` Admin API](https://matrix-org.github.io/synapse/develop/admin_api/event_reports.html) could return a total count which was larger than the number of results you can actually query for. ([\#13525](https://github.com/matrix-org/synapse/issues/13525))
- Fix a bug introduced in Synapse 1.52.0 where sending server notices fails if `max_avatar_size` or `allowed_avatar_mimetypes` is set and not `system_mxid_avatar_url`. ([\#13566](https://github.com/matrix-org/synapse/issues/13566))
- Fix a bug where the `opentracing.force_tracing_for_users` config option would not apply to [`/sendToDevice`](https://spec.matrix.org/v1.3/client-server-api/#put_matrixclientv3sendtodeviceeventtypetxnid) and [`/keys/upload`](https://spec.matrix.org/v1.3/client-server-api/#post_matrixclientv3keysupload) requests. ([\#13574](https://github.com/matrix-org/synapse/issues/13574))


Improved Documentation
----------------------

- Add `openssl` example for generating registration HMAC digest. ([\#13472](https://github.com/matrix-org/synapse/issues/13472))
- Tidy up Synapse's README. ([\#13491](https://github.com/matrix-org/synapse/issues/13491))
- Document that event purging related to the `redaction_retention_period` config option is executed only every 5 minutes. ([\#13492](https://github.com/matrix-org/synapse/issues/13492))
- Add a warning to retention documentation regarding the possibility of database corruption. ([\#13497](https://github.com/matrix-org/synapse/issues/13497))
- Document that the `DOCKER_BUILDKIT=1` flag is needed to build the docker image. ([\#13515](https://github.com/matrix-org/synapse/issues/13515))
- Add missing links in `user_consent` section of configuration manual. ([\#13536](https://github.com/matrix-org/synapse/issues/13536))
- Fix the doc and some warnings that were referring to the nonexistent `custom_templates_directory` setting (instead of `custom_template_directory`). ([\#13538](https://github.com/matrix-org/synapse/issues/13538))


Deprecations and Removals
-------------------------

- Remove the ability for homeservers to delegate email ownership verification
  and password reset confirmation to identity servers. See [upgrade notes](https://matrix-org.github.io/synapse/v1.66/upgrade.html#upgrading-to-v1660) for more details.

Internal Changes
----------------

### Faster room joins

- Update the rejected state of events during de-partial-stating. ([\#13459](https://github.com/matrix-org/synapse/issues/13459))
- Avoid blocking lazy-loading `/sync`s during partial joins due to remote memberships. Pull remote memberships from auth events instead of the room state. ([\#13477](https://github.com/matrix-org/synapse/issues/13477))
- Refuse to start when faster joins is enabled on a deployment with workers, since worker configurations are not currently supported. ([\#13531](https://github.com/matrix-org/synapse/issues/13531))

### Metrics and tracing

- Allow use of both `@trace` and `@tag_args` stacked on the same function. ([\#13453](https://github.com/matrix-org/synapse/issues/13453))
- Instrument the federation/backfill part of `/messages` for understandable traces in Jaeger. ([\#13489](https://github.com/matrix-org/synapse/issues/13489))
- Instrument `FederationStateIdsServlet` (`/state_ids`) for understandable traces in Jaeger. ([\#13499](https://github.com/matrix-org/synapse/issues/13499), [\#13554](https://github.com/matrix-org/synapse/issues/13554))
- Track HTTP response times over 10 seconds from `/messages` (`synapse_room_message_list_rest_servlet_response_time_seconds`). ([\#13533](https://github.com/matrix-org/synapse/issues/13533))
- Add metrics to track how the rate limiter is affecting requests (sleep/reject). ([\#13534](https://github.com/matrix-org/synapse/issues/13534), [\#13541](https://github.com/matrix-org/synapse/issues/13541))
- Add metrics to time how long it takes us to do backfill processing (`synapse_federation_backfill_processing_before_time_seconds`, `synapse_federation_backfill_processing_after_time_seconds`). ([\#13535](https://github.com/matrix-org/synapse/issues/13535), [\#13584](https://github.com/matrix-org/synapse/issues/13584))
- Add metrics to track rate limiter queue timing (`synapse_rate_limit_queue_wait_time_seconds`). ([\#13544](https://github.com/matrix-org/synapse/issues/13544))
- Update metrics to track `/messages` response time by room size. ([\#13545](https://github.com/matrix-org/synapse/issues/13545))

### Everything else

- Refactor methods in `synapse.api.auth.Auth` to use `Requester` objects everywhere instead of user IDs. ([\#13024](https://github.com/matrix-org/synapse/issues/13024))
- Clean-up tests for notifications. ([\#13471](https://github.com/matrix-org/synapse/issues/13471))
- Add some miscellaneous comments to document sync, especially around `compute_state_delta`. ([\#13474](https://github.com/matrix-org/synapse/issues/13474))
- Use literals in place of `HTTPStatus` constants in tests. ([\#13479](https://github.com/matrix-org/synapse/issues/13479), [\#13488](https://github.com/matrix-org/synapse/issues/13488))
- Add comments about how event push actions are rotated. ([\#13485](https://github.com/matrix-org/synapse/issues/13485))
- Modify HTML template content to better support mobile devices' screen sizes. ([\#13493](https://github.com/matrix-org/synapse/issues/13493))
- Add a linter script which will reject non-strict types in Pydantic models. ([\#13502](https://github.com/matrix-org/synapse/issues/13502))
- Reduce the number of tests using legacy TCP replication. ([\#13543](https://github.com/matrix-org/synapse/issues/13543))
- Allow specifying additional request fields when using the `HomeServerTestCase.login` helper method. ([\#13549](https://github.com/matrix-org/synapse/issues/13549))
- Make `HomeServerTestCase` load any configured homeserver modules automatically. ([\#13558](https://github.com/matrix-org/synapse/issues/13558))


Synapse 1.65.0 (2022-08-16)
===========================

No significant changes since 1.65.0rc2.


Synapse 1.65.0rc2 (2022-08-11)
==============================

Internal Changes
----------------

- Revert 'Remove the unspecced `room_id` field in the `/hierarchy` response. ([\#13365](https://github.com/matrix-org/synapse/issues/13365))' to give more time for clients to update. ([\#13501](https://github.com/matrix-org/synapse/issues/13501))


Synapse 1.65.0rc1 (2022-08-09)
==============================

Features
--------

- Add support for stable prefixes for [MSC2285 (private read receipts)](https://github.com/matrix-org/matrix-spec-proposals/pull/2285). ([\#13273](https://github.com/matrix-org/synapse/issues/13273))
- Add new unstable error codes `ORG.MATRIX.MSC3848.ALREADY_JOINED`, `ORG.MATRIX.MSC3848.NOT_JOINED`, and `ORG.MATRIX.MSC3848.INSUFFICIENT_POWER` described in [MSC3848](https://github.com/matrix-org/matrix-spec-proposals/pull/3848). ([\#13343](https://github.com/matrix-org/synapse/issues/13343))
- Use stable prefixes for [MSC3827](https://github.com/matrix-org/matrix-spec-proposals/pull/3827). ([\#13370](https://github.com/matrix-org/synapse/issues/13370))
- Add a new module API method to translate a room alias into a room ID. ([\#13428](https://github.com/matrix-org/synapse/issues/13428))
- Add a new module API method to create a room. ([\#13429](https://github.com/matrix-org/synapse/issues/13429))
- Add remote join capability to the module API's `update_room_membership` method (in a backwards compatible manner). ([\#13441](https://github.com/matrix-org/synapse/issues/13441))


Bugfixes
--------

- Update the version of the LDAP3 auth provider module included in the `matrixdotorg/synapse` DockerHub images and the Debian packages hosted on packages.matrix.org to 0.2.2. This version fixes a regression in the module. ([\#13470](https://github.com/matrix-org/synapse/issues/13470))
- Fix a bug introduced in Synapse 1.41.0 where the `/hierarchy` API returned non-standard information (a `room_id` field under each entry in `children_state`) (this was reverted in v1.65.0rc2, see changelog notes above). ([\#13365](https://github.com/matrix-org/synapse/issues/13365))
- Fix a bug introduced in Synapse 0.24.0 that would respond with the wrong error status code to `/joined_members` requests when the requester is not a current member of the room. Contributed by @andrewdoh. ([\#13374](https://github.com/matrix-org/synapse/issues/13374))
- Fix bug in handling of typing events for appservices. Contributed by Nick @ Beeper (@fizzadar). ([\#13392](https://github.com/matrix-org/synapse/issues/13392))
- Fix a bug introduced in Synapse 1.57.0 where rooms listed in `exclude_rooms_from_sync` in the configuration file would not be properly excluded from incremental syncs. ([\#13408](https://github.com/matrix-org/synapse/issues/13408))
- Fix a bug in the experimental faster-room-joins support which could cause it to get stuck in an infinite loop. ([\#13353](https://github.com/matrix-org/synapse/issues/13353))
- Faster room joins: fix a bug which caused rejected events to become un-rejected during state syncing. ([\#13413](https://github.com/matrix-org/synapse/issues/13413))
- Faster room joins: fix error when running out of servers to sync partial state with, so that Synapse raises the intended error instead. ([\#13432](https://github.com/matrix-org/synapse/issues/13432))


Updates to the Docker image
---------------------------

- Make Docker images build on armv7 by installing cryptography dependencies in the 'requirements' stage. Contributed by Jasper Spaans. ([\#13372](https://github.com/matrix-org/synapse/issues/13372))


Improved Documentation
----------------------

- Update the 'registration tokens' page to acknowledge that the relevant MSC was merged into version 1.2 of the Matrix specification. Contributed by @moan0s. ([\#11897](https://github.com/matrix-org/synapse/issues/11897))
- Document which HTTP resources support gzip compression. ([\#13221](https://github.com/matrix-org/synapse/issues/13221))
- Add steps describing how to elevate an existing user to administrator by manipulating the database. ([\#13230](https://github.com/matrix-org/synapse/issues/13230))
- Fix wrong headline for `url_preview_accept_language` in documentation. ([\#13437](https://github.com/matrix-org/synapse/issues/13437))
- Remove redundant 'Contents' section from the Configuration Manual. Contributed by @dklimpel. ([\#13438](https://github.com/matrix-org/synapse/issues/13438))
- Update documentation for config setting `macaroon_secret_key`. ([\#13443](https://github.com/matrix-org/synapse/issues/13443))
- Update outdated information on `sso_mapping_providers` documentation. ([\#13449](https://github.com/matrix-org/synapse/issues/13449))
- Fix example code in module documentation of `password_auth_provider_callbacks`. ([\#13450](https://github.com/matrix-org/synapse/issues/13450))
- Make the configuration for the cache clearer. ([\#13481](https://github.com/matrix-org/synapse/issues/13481))


Internal Changes
----------------

- Extend the release script to automatically push a new SyTest branch, rather than having that be a manual process. ([\#12978](https://github.com/matrix-org/synapse/issues/12978))
- Make minor clarifications to the error messages given when we fail to join a room via any server. ([\#13160](https://github.com/matrix-org/synapse/issues/13160))
- Enable Complement CI tests in the 'latest deps' test run. ([\#13213](https://github.com/matrix-org/synapse/issues/13213))
- Fix long-standing bugged logic which was never hit in `get_pdu` asking every remote destination even after it finds an event. ([\#13346](https://github.com/matrix-org/synapse/issues/13346))
- Faster room joins: avoid blocking when pulling events with partially missing prev events. ([\#13355](https://github.com/matrix-org/synapse/issues/13355))
- Instrument `/messages` for understandable traces in Jaeger. ([\#13368](https://github.com/matrix-org/synapse/issues/13368))
- Remove an unused argument to `get_relations_for_event`. ([\#13383](https://github.com/matrix-org/synapse/issues/13383))
- Add a `merge-back` command to the release script, which automates merging the correct branches after a release. ([\#13393](https://github.com/matrix-org/synapse/issues/13393))
- Adding missing type hints to tests. ([\#13397](https://github.com/matrix-org/synapse/issues/13397))
- Faster Room Joins: don't leave a stuck room partial state flag if the join fails. ([\#13403](https://github.com/matrix-org/synapse/issues/13403))
- Refactor `_resolve_state_at_missing_prevs` to compute an `EventContext` instead. ([\#13404](https://github.com/matrix-org/synapse/issues/13404), [\#13431](https://github.com/matrix-org/synapse/issues/13431))
- Faster Room Joins: prevent Synapse from answering federated join requests for a room which it has not fully joined yet. ([\#13416](https://github.com/matrix-org/synapse/issues/13416))
- Re-enable running Complement tests against Synapse with workers. ([\#13420](https://github.com/matrix-org/synapse/issues/13420))
- Prevent unnecessary lookups to any external `get_event` cache. Contributed by Nick @ Beeper (@fizzadar). ([\#13435](https://github.com/matrix-org/synapse/issues/13435))
- Add some tracing to give more insight into local room joins. ([\#13439](https://github.com/matrix-org/synapse/issues/13439))
- Rename class `RateLimitConfig` to `RatelimitSettings` and `FederationRateLimitConfig` to `FederationRatelimitSettings`. ([\#13442](https://github.com/matrix-org/synapse/issues/13442))
- Add some comments about how event push actions are stored. ([\#13445](https://github.com/matrix-org/synapse/issues/13445), [\#13455](https://github.com/matrix-org/synapse/issues/13455))
- Improve rebuild speed for the "synapse-workers" docker image. ([\#13447](https://github.com/matrix-org/synapse/issues/13447))
- Fix `@tag_args` being off-by-one with the arguments when tagging a span (tracing). ([\#13452](https://github.com/matrix-org/synapse/issues/13452))
- Update type of `EventContext.rejected`. ([\#13460](https://github.com/matrix-org/synapse/issues/13460))
- Use literals in place of `HTTPStatus` constants in tests. ([\#13463](https://github.com/matrix-org/synapse/issues/13463), [\#13469](https://github.com/matrix-org/synapse/issues/13469))
- Correct a misnamed argument in state res v2 internals. ([\#13467](https://github.com/matrix-org/synapse/issues/13467))


Synapse 1.64.0 (2022-08-02)
===========================

No significant changes since 1.64.0rc2.


Deprecation Warning
-------------------

Synapse 1.66.0 will remove the ability to delegate the tasks of verifying email address ownership, and password reset confirmation, to an identity server.

If you require your homeserver to verify e-mail addresses or to support password resets via e-mail, please configure your homeserver with SMTP access so that it can send e-mails on its own behalf.
[Consult the configuration documentation for more information.](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#email)


Synapse 1.64.0rc2 (2022-07-29)
==============================

This RC reintroduces support for `account_threepid_delegates.email`, which was removed in 1.64.0rc1. It remains deprecated and will be removed altogether in Synapse 1.66.0. ([\#13406](https://github.com/matrix-org/synapse/issues/13406))


Synapse 1.64.0rc1 (2022-07-26)
==============================

This RC removed the ability to delegate the tasks of verifying email address ownership, and password reset confirmation, to an identity server.

We have also stopped building `.deb` packages for Ubuntu 21.10 as it is no longer an active version of Ubuntu.


Features
--------

- Improve error messages when media thumbnails cannot be served. ([\#13038](https://github.com/matrix-org/synapse/issues/13038))
- Allow pagination from remote event after discovering it from [MSC3030](https://github.com/matrix-org/matrix-spec-proposals/pull/3030) `/timestamp_to_event`. ([\#13205](https://github.com/matrix-org/synapse/issues/13205))
- Add a `room_type` field in the responses for the list room and room details admin APIs. Contributed by @andrewdoh. ([\#13208](https://github.com/matrix-org/synapse/issues/13208))
- Add support for room version 10. ([\#13220](https://github.com/matrix-org/synapse/issues/13220))
- Add per-room rate limiting for room joins. For each room, Synapse now monitors the rate of join events in that room, and throttles additional joins if that rate grows too large. ([\#13253](https://github.com/matrix-org/synapse/issues/13253), [\#13254](https://github.com/matrix-org/synapse/issues/13254), [\#13255](https://github.com/matrix-org/synapse/issues/13255), [\#13276](https://github.com/matrix-org/synapse/issues/13276))
- Support Implicit TLS (TLS without using a STARTTLS upgrade, typically on port 465) for sending emails, enabled by the new option `force_tls`. Contributed by Jan Schär. ([\#13317](https://github.com/matrix-org/synapse/issues/13317))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.15.0 where adding a user through the Synapse Admin API with a phone number would fail if the `enable_email_notifs` and `email_notifs_for_new_users` options were enabled. Contributed by @thomasweston12. ([\#13263](https://github.com/matrix-org/synapse/issues/13263))
- Fix a bug introduced in Synapse 1.40.0 where a user invited to a restricted room would be briefly unable to join. ([\#13270](https://github.com/matrix-org/synapse/issues/13270))
- Fix a long-standing bug where, in rare instances, Synapse could store the incorrect state for a room after a state resolution. ([\#13278](https://github.com/matrix-org/synapse/issues/13278))
- Fix a bug introduced in v1.18.0 where the `synapse_pushers` metric would overcount pushers when they are replaced. ([\#13296](https://github.com/matrix-org/synapse/issues/13296))
- Disable autocorrection and autocapitalisation on the username text field shown during registration when using SSO. ([\#13350](https://github.com/matrix-org/synapse/issues/13350))
- Update locked version of `frozendict` to 2.3.3, which has fixes for memory leaks affecting `/sync`. ([\#13284](https://github.com/matrix-org/synapse/issues/13284), [\#13352](https://github.com/matrix-org/synapse/issues/13352))


Improved Documentation
----------------------

- Provide an example of using the Admin API. Contributed by @jejo86. ([\#13231](https://github.com/matrix-org/synapse/issues/13231))
- Move the documentation for how URL previews work to the URL preview module. ([\#13233](https://github.com/matrix-org/synapse/issues/13233), [\#13261](https://github.com/matrix-org/synapse/issues/13261))
- Add another `contrib` script to help set up worker processes. Contributed by @villepeh. ([\#13271](https://github.com/matrix-org/synapse/issues/13271))
- Document that certain config options were added or changed in Synapse 1.62. Contributed by @behrmann. ([\#13314](https://github.com/matrix-org/synapse/issues/13314))
- Document the new `rc_invites.per_issuer` throttling option added in Synapse 1.63. ([\#13333](https://github.com/matrix-org/synapse/issues/13333))
- Mention that BuildKit is needed when building Docker images for tests. ([\#13338](https://github.com/matrix-org/synapse/issues/13338))
- Improve Caddy reverse proxy documentation. ([\#13344](https://github.com/matrix-org/synapse/issues/13344))


Deprecations and Removals
-------------------------

- Drop tables that were formerly used for groups/communities. ([\#12967](https://github.com/matrix-org/synapse/issues/12967))
- Drop support for delegating email verification to an external server. ([\#13192](https://github.com/matrix-org/synapse/issues/13192))
- Drop support for calling `/_matrix/client/v3/account/3pid/bind` without an `id_access_token`, which was not permitted by the spec. Contributed by @Vetchu. ([\#13239](https://github.com/matrix-org/synapse/issues/13239))
- Stop building `.deb` packages for Ubuntu 21.10 (Impish Indri), which has reached end of life. ([\#13326](https://github.com/matrix-org/synapse/issues/13326))


Internal Changes
----------------

- Use lower transaction isolation level when purging rooms to avoid serialization errors. Contributed by Nick @ Beeper. ([\#12942](https://github.com/matrix-org/synapse/issues/12942))
- Remove code which incorrectly attempted to reconcile state with remote servers when processing incoming events. ([\#12943](https://github.com/matrix-org/synapse/issues/12943))
- Make the AS login method call `Auth.get_user_by_req` for checking the AS token. ([\#13094](https://github.com/matrix-org/synapse/issues/13094))
- Always use a version of canonicaljson that supports the C implementation of frozendict. ([\#13172](https://github.com/matrix-org/synapse/issues/13172))
- Add prometheus counters for ephemeral events and to device messages pushed to app services. Contributed by Brad @ Beeper. ([\#13175](https://github.com/matrix-org/synapse/issues/13175))
- Refactor receipts servlet logic to avoid duplicated code. ([\#13198](https://github.com/matrix-org/synapse/issues/13198))
- Preparation for database schema simplifications: populate `state_key` and `rejection_reason` for existing rows in the `events` table. ([\#13215](https://github.com/matrix-org/synapse/issues/13215))
- Remove unused database table `event_reference_hashes`. ([\#13218](https://github.com/matrix-org/synapse/issues/13218))
- Further reduce queries used sending events when creating new rooms. Contributed by Nick @ Beeper (@fizzadar). ([\#13224](https://github.com/matrix-org/synapse/issues/13224))
- Call the v2 identity service `/3pid/unbind` endpoint, rather than v1. Contributed by @Vetchu. ([\#13240](https://github.com/matrix-org/synapse/issues/13240))
- Use an asynchronous cache wrapper for the get event cache. Contributed by Nick @ Beeper (@fizzadar). ([\#13242](https://github.com/matrix-org/synapse/issues/13242), [\#13308](https://github.com/matrix-org/synapse/issues/13308))
- Optimise federation sender and appservice pusher event stream processing queries. Contributed by Nick @ Beeper (@fizzadar). ([\#13251](https://github.com/matrix-org/synapse/issues/13251))
- Log the stack when waiting for an entire room to be un-partial stated. ([\#13257](https://github.com/matrix-org/synapse/issues/13257))
- Fix spurious warning when fetching state after a missing prev event. ([\#13258](https://github.com/matrix-org/synapse/issues/13258))
- Clean-up tests for notifications. ([\#13260](https://github.com/matrix-org/synapse/issues/13260))
- Do not fail build if complement with workers fails. ([\#13266](https://github.com/matrix-org/synapse/issues/13266))
- Don't pull out state in `compute_event_context` for unconflicted state. ([\#13267](https://github.com/matrix-org/synapse/issues/13267), [\#13274](https://github.com/matrix-org/synapse/issues/13274))
- Reduce the rebuild time for the complement-synapse docker image. ([\#13279](https://github.com/matrix-org/synapse/issues/13279))
- Don't pull out the full state when creating an event. ([\#13281](https://github.com/matrix-org/synapse/issues/13281), [\#13307](https://github.com/matrix-org/synapse/issues/13307))
- Upgrade from Poetry 1.1.12 to 1.1.14, to fix bugs when locking packages. ([\#13285](https://github.com/matrix-org/synapse/issues/13285))
- Make `DictionaryCache` expire full entries if they haven't been queried in a while, even if specific keys have been queried recently. ([\#13292](https://github.com/matrix-org/synapse/issues/13292))
- Use `HTTPStatus` constants in place of literals in tests. ([\#13297](https://github.com/matrix-org/synapse/issues/13297))
- Improve performance of query  `_get_subset_users_in_room_with_profiles`. ([\#13299](https://github.com/matrix-org/synapse/issues/13299))
- Up batch size of `bulk_get_push_rules` and `_get_joined_profiles_from_event_ids`. ([\#13300](https://github.com/matrix-org/synapse/issues/13300))
- Remove unnecessary `json.dumps` from tests. ([\#13303](https://github.com/matrix-org/synapse/issues/13303))
- Reduce memory usage of sending dummy events. ([\#13310](https://github.com/matrix-org/synapse/issues/13310))
- Prevent formatting changes of [#3679](https://github.com/matrix-org/synapse/pull/3679) from appearing in `git blame`. ([\#13311](https://github.com/matrix-org/synapse/issues/13311))
- Change `get_users_in_room` and `get_rooms_for_user` caches to enable pruning of old entries. ([\#13313](https://github.com/matrix-org/synapse/issues/13313))
- Validate federation destinations and log an error if a destination is invalid. ([\#13318](https://github.com/matrix-org/synapse/issues/13318))
- Fix `FederationClient.get_pdu()` returning events from the cache as `outliers` instead of original events we saw over federation. ([\#13320](https://github.com/matrix-org/synapse/issues/13320))
- Reduce memory usage of state caches. ([\#13323](https://github.com/matrix-org/synapse/issues/13323))
- Reduce the amount of state we store in the `state_cache`. ([\#13324](https://github.com/matrix-org/synapse/issues/13324))
- Add missing type hints to open tracing module. ([\#13328](https://github.com/matrix-org/synapse/issues/13328), [\#13345](https://github.com/matrix-org/synapse/issues/13345), [\#13362](https://github.com/matrix-org/synapse/issues/13362))
- Remove old base slaved store and de-duplicate cache ID generators. Contributed by Nick @ Beeper (@fizzadar). ([\#13329](https://github.com/matrix-org/synapse/issues/13329), [\#13349](https://github.com/matrix-org/synapse/issues/13349))
- When reporting metrics is enabled, use ~8x less data to describe DB transaction metrics. ([\#13342](https://github.com/matrix-org/synapse/issues/13342))
- Faster room joins: skip soft fail checks while Synapse only has partial room state, since the current membership of event senders may not be accurately known. ([\#13354](https://github.com/matrix-org/synapse/issues/13354))


Synapse 1.63.1 (2022-07-20)
===========================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.63.0 where push actions were incorrectly calculated for appservice users. This caused performance issues on servers with large numbers of appservices. ([\#13332](https://github.com/matrix-org/synapse/issues/13332))


Synapse 1.63.0 (2022-07-19)
===========================

Improved Documentation
----------------------

- Clarify that homeserver server names are included in the reported data when the `report_stats` config option is enabled. ([\#13321](https://github.com/matrix-org/synapse/issues/13321))


Synapse 1.63.0rc1 (2022-07-12)
==============================

Features
--------

- Add a rate limit for local users sending invites. ([\#13125](https://github.com/matrix-org/synapse/issues/13125))
- Implement [MSC3827](https://github.com/matrix-org/matrix-spec-proposals/pull/3827): Filtering of `/publicRooms` by room type. ([\#13031](https://github.com/matrix-org/synapse/issues/13031))
- Improve validation logic in the account data REST endpoints. ([\#13148](https://github.com/matrix-org/synapse/issues/13148))


Bugfixes
--------

- Fix a long-standing bug where application services were not able to join remote federated rooms without a profile. ([\#13131](https://github.com/matrix-org/synapse/issues/13131))
- Fix a long-standing bug where `_get_state_map_for_room` might raise errors when third party event rules callbacks are present. ([\#13174](https://github.com/matrix-org/synapse/issues/13174))
- Fix a long-standing bug where the `synapse_port_db` script could fail to copy rows with negative row ids. ([\#13226](https://github.com/matrix-org/synapse/issues/13226))
- Fix a bug introduced in 1.54.0 where appservices would not receive room-less EDUs, like presence, when both [MSC2409](https://github.com/matrix-org/matrix-spec-proposals/pull/2409) and [MSC3202](https://github.com/matrix-org/matrix-spec-proposals/pull/3202) are enabled. ([\#13236](https://github.com/matrix-org/synapse/issues/13236))
- Fix a bug introduced in 1.62.0 where rows were not deleted from `event_push_actions` table on large servers. ([\#13194](https://github.com/matrix-org/synapse/issues/13194))
- Fix a bug introduced in 1.62.0 where notification counts would get stuck after a highlighted message. ([\#13223](https://github.com/matrix-org/synapse/issues/13223))
- Fix exception when using experimental [MSC3030](https://github.com/matrix-org/matrix-spec-proposals/pull/3030) `/timestamp_to_event` endpoint to look for remote federated imported events before room creation. ([\#13197](https://github.com/matrix-org/synapse/issues/13197))
- Fix [MSC3202](https://github.com/matrix-org/matrix-spec-proposals/pull/3202)-enabled appservices not receiving to-device messages, preventing messages from being decrypted. ([\#13235](https://github.com/matrix-org/synapse/issues/13235))


Updates to the Docker image
---------------------------

- Bump the version of `lxml` in matrix.org Docker images Debian packages from 4.8.0 to 4.9.1. ([\#13207](https://github.com/matrix-org/synapse/issues/13207))


Improved Documentation
----------------------

- Add an explanation of the `--report-stats` argument to the docs. ([\#13029](https://github.com/matrix-org/synapse/issues/13029))
- Add a helpful example bash script to the contrib directory for creating multiple worker configuration files of the same type. Contributed by @villepeh. ([\#13032](https://github.com/matrix-org/synapse/issues/13032))
- Add missing links to config options. ([\#13166](https://github.com/matrix-org/synapse/issues/13166))
- Add documentation for homeserver usage statistics collection. ([\#13086](https://github.com/matrix-org/synapse/issues/13086))
- Add documentation for the existing `databases` option in the homeserver configuration manual. ([\#13212](https://github.com/matrix-org/synapse/issues/13212))
- Clean up references to sample configuration and redirect users to the configuration manual instead. ([\#13077](https://github.com/matrix-org/synapse/issues/13077), [\#13139](https://github.com/matrix-org/synapse/issues/13139))
- Document how the Synapse team does reviews. ([\#13132](https://github.com/matrix-org/synapse/issues/13132))
- Fix wrong section header for `allow_public_rooms_over_federation` in the homeserver config documentation. ([\#13116](https://github.com/matrix-org/synapse/issues/13116))


Deprecations and Removals
-------------------------

- Remove obsolete and for 8 years unused `RoomEventsStoreTestCase`. Contributed by @arkamar. ([\#13200](https://github.com/matrix-org/synapse/issues/13200))


Internal Changes
----------------

- Add type annotations to `synapse.logging`, `tests.server` and `tests.utils`. ([\#13028](https://github.com/matrix-org/synapse/issues/13028), [\#13103](https://github.com/matrix-org/synapse/issues/13103), [\#13159](https://github.com/matrix-org/synapse/issues/13159), [\#13136](https://github.com/matrix-org/synapse/issues/13136))
- Enforce type annotations for `tests.test_server`. ([\#13135](https://github.com/matrix-org/synapse/issues/13135))
- Support temporary experimental return values for spam checker module callbacks. ([\#13044](https://github.com/matrix-org/synapse/issues/13044))
- Add support to `complement.sh` for skipping the docker build. ([\#13143](https://github.com/matrix-org/synapse/issues/13143), [\#13158](https://github.com/matrix-org/synapse/issues/13158))
- Add support to `complement.sh` for setting the log level using the `SYNAPSE_TEST_LOG_LEVEL` environment variable. ([\#13152](https://github.com/matrix-org/synapse/issues/13152))
- Enable Complement testing in the 'Twisted Trunk' CI runs. ([\#13079](https://github.com/matrix-org/synapse/issues/13079), [\#13157](https://github.com/matrix-org/synapse/issues/13157))
- Improve startup times in Complement test runs against workers, particularly in CPU-constrained environments. ([\#13127](https://github.com/matrix-org/synapse/issues/13127))
- Update config used by Complement to allow device name lookup over federation. ([\#13167](https://github.com/matrix-org/synapse/issues/13167))
- Faster room joins: handle race between persisting an event and un-partial stating a room. ([\#13100](https://github.com/matrix-org/synapse/issues/13100))
- Faster room joins: fix race in recalculation of current room state. ([\#13151](https://github.com/matrix-org/synapse/issues/13151))
- Faster room joins: skip waiting for full state when processing incoming events over federation. ([\#13144](https://github.com/matrix-org/synapse/issues/13144))
- Raise a `DependencyError` on missing dependencies instead of a `ConfigError`. ([\#13113](https://github.com/matrix-org/synapse/issues/13113))
- Avoid stripping line breaks from SQL sent to the database. ([\#13129](https://github.com/matrix-org/synapse/issues/13129))
- Apply ratelimiting earlier in processing of `/send` requests. ([\#13134](https://github.com/matrix-org/synapse/issues/13134))
- Improve exception handling when processing events received over federation. ([\#13145](https://github.com/matrix-org/synapse/issues/13145))
- Check that `auto_vacuum` is disabled when porting a SQLite database to Postgres, as `VACUUM`s must not be performed between runs of the script. ([\#13195](https://github.com/matrix-org/synapse/issues/13195))
- Reduce DB usage of `/sync` when a large number of unread messages have recently been sent in a room. ([\#13119](https://github.com/matrix-org/synapse/issues/13119), [\#13153](https://github.com/matrix-org/synapse/issues/13153))
- Reduce memory consumption when processing incoming events in large rooms. ([\#13078](https://github.com/matrix-org/synapse/issues/13078), [\#13222](https://github.com/matrix-org/synapse/issues/13222))
- Reduce number of queries used to get profile information. Contributed by Nick @ Beeper (@fizzadar). ([\#13209](https://github.com/matrix-org/synapse/issues/13209))
- Reduce number of events queried during room creation. Contributed by Nick @ Beeper (@fizzadar). ([\#13210](https://github.com/matrix-org/synapse/issues/13210))
- More aggressively rotate push actions. ([\#13211](https://github.com/matrix-org/synapse/issues/13211))
- Add `max_line_length` setting for Python files to the `.editorconfig`. Contributed by @sumnerevans @ Beeper. ([\#13228](https://github.com/matrix-org/synapse/issues/13228))

Synapse 1.62.0 (2022-07-05)
===========================

No significant changes since 1.62.0rc3.

Authors of spam-checker plugins should consult the [upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.62/docs/upgrade.md#upgrading-to-v1620) to learn about the enriched signatures for spam checker callbacks, which are supported with this release of Synapse.

## Security advisory

The following issue is fixed in 1.62.0.

* [GHSA-jhjh-776m-4765](https://github.com/matrix-org/synapse/security/advisories/GHSA-jhjh-776m-4765) / [CVE-2022-31152](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31152)

  Synapse instances prior to 1.62.0 did not implement the Matrix [event authorization rules](https://spec.matrix.org/v1.3/rooms/v10/#authorization-rules) correctly. An attacker could craft events which would be accepted by Synapse but not a spec-conformant server, potentially causing divergence in the room state between servers.

  Homeservers with federation disabled via the [`federation_domain_whitelist`](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#federation_domain_whitelist) config option are unaffected.

  Administrators of homeservers with federation enabled are advised to upgrade to v1.62.0 or higher.

  Fixed by [#13087](https://github.com/matrix-org/synapse/pull/13087) and [#13088](https://github.com/matrix-org/synapse/pull/13088).

Synapse 1.62.0rc3 (2022-07-04)
==============================

Bugfixes
--------

- Update the version of the [ldap3 plugin](https://github.com/matrix-org/matrix-synapse-ldap3/) included in the `matrixdotorg/synapse` DockerHub images and the Debian packages hosted on `packages.matrix.org` to 0.2.1. This fixes [a bug](https://github.com/matrix-org/matrix-synapse-ldap3/pull/163) with usernames containing uppercase characters. ([\#13156](https://github.com/matrix-org/synapse/issues/13156))
- Fix a bug introduced in Synapse 1.62.0rc1 affecting unread counts for users on small servers. ([\#13168](https://github.com/matrix-org/synapse/issues/13168))


Synapse 1.62.0rc2 (2022-07-01)
==============================

Bugfixes
--------

- Fix unread counts for users on large servers. Introduced in v1.62.0rc1. ([\#13140](https://github.com/matrix-org/synapse/issues/13140))
- Fix DB performance when deleting old push notifications. Introduced in v1.62.0rc1. ([\#13141](https://github.com/matrix-org/synapse/issues/13141))


Synapse 1.62.0rc1 (2022-06-28)
==============================

Features
--------

- Port the spam-checker API callbacks to a new, richer API. This is part of an ongoing change to let spam-checker modules inform users of the reason their event or operation is rejected. ([\#12857](https://github.com/matrix-org/synapse/issues/12857), [\#13047](https://github.com/matrix-org/synapse/issues/13047))
- Allow server admins to customise the response of the `/.well-known/matrix/client` endpoint. ([\#13035](https://github.com/matrix-org/synapse/issues/13035))
- Add metrics measuring the CPU and DB time spent in state resolution. ([\#13036](https://github.com/matrix-org/synapse/issues/13036))
- Speed up fetching of device list changes in `/sync` and `/keys/changes`. ([\#13045](https://github.com/matrix-org/synapse/issues/13045), [\#13098](https://github.com/matrix-org/synapse/issues/13098))
- Improve URL previews for sites which only provide Twitter Card metadata, e.g. LWN.net. ([\#13056](https://github.com/matrix-org/synapse/issues/13056))


Bugfixes
--------

- Update [MSC3786](https://github.com/matrix-org/matrix-spec-proposals/pull/3786) implementation to check `state_key`. ([\#12939](https://github.com/matrix-org/synapse/issues/12939))
- Fix a bug introduced in Synapse 1.58 where Synapse would not report full version information when installed from a git checkout. This is a best-effort affair and not guaranteed to be stable. ([\#12973](https://github.com/matrix-org/synapse/issues/12973))
- Fix a bug introduced in Synapse 1.60 where Synapse would fail to start if the `sqlite3` module was not available. ([\#12979](https://github.com/matrix-org/synapse/issues/12979))
- Fix a bug where non-standard information was required when requesting the `/hierarchy` API over federation. Introduced
  in Synapse 1.41.0. ([\#12991](https://github.com/matrix-org/synapse/issues/12991))
- Fix a long-standing bug which meant that rate limiting was not restrictive enough in some cases. ([\#13018](https://github.com/matrix-org/synapse/issues/13018))
- Fix a bug introduced in Synapse 1.58 where profile requests for a malformed user ID would ccause an internal error. Synapse now returns 400 Bad Request in this situation. ([\#13041](https://github.com/matrix-org/synapse/issues/13041))
- Fix some inconsistencies in the event authentication code. ([\#13087](https://github.com/matrix-org/synapse/issues/13087), [\#13088](https://github.com/matrix-org/synapse/issues/13088))
- Fix a long-standing bug where room directory requests would cause an internal server error if given a malformed room alias. ([\#13106](https://github.com/matrix-org/synapse/issues/13106))


Improved Documentation
----------------------

- Add documentation for how to configure Synapse with Workers using Docker Compose. Includes example worker config and docker-compose.yaml. Contributed by @Thumbscrew. ([\#12737](https://github.com/matrix-org/synapse/issues/12737))
- Ensure the [Poetry cheat sheet](https://matrix-org.github.io/synapse/develop/development/dependencies.html) is available in the online documentation. ([\#13022](https://github.com/matrix-org/synapse/issues/13022))
- Mention removed community/group worker endpoints in upgrade.md. Contributed by @olmari. ([\#13023](https://github.com/matrix-org/synapse/issues/13023))
- Add instructions for running Complement with `gotestfmt`-formatted output locally. ([\#13073](https://github.com/matrix-org/synapse/issues/13073))
- Update OpenTracing docs to reference the configuration manual rather than the configuration file. ([\#13076](https://github.com/matrix-org/synapse/issues/13076))
- Update information on downstream Debian packages. ([\#13095](https://github.com/matrix-org/synapse/issues/13095))
- Remove documentation for the Delete Group Admin API which no longer exists. ([\#13112](https://github.com/matrix-org/synapse/issues/13112))


Deprecations and Removals
-------------------------

- Remove the unspecced `DELETE /directory/list/room/{roomId}` endpoint, which hid rooms from the [public room directory](https://spec.matrix.org/v1.3/client-server-api/#listing-rooms). Instead, `PUT` to the same URL with a visibility of `"private"`. ([\#13123](https://github.com/matrix-org/synapse/issues/13123))


Internal Changes
----------------

- Add tests for cancellation of `GET /rooms/$room_id/members` and `GET /rooms/$room_id/state` requests. ([\#12674](https://github.com/matrix-org/synapse/issues/12674))
- Report login failures due to unknown third party identifiers in the same way as failures due to invalid passwords. This prevents an attacker from using the error response to determine if the identifier exists. Contributed by Daniel Aloni. ([\#12738](https://github.com/matrix-org/synapse/issues/12738))
- Merge the Complement testing Docker images into a single, multi-purpose image. ([\#12881](https://github.com/matrix-org/synapse/issues/12881), [\#13075](https://github.com/matrix-org/synapse/issues/13075))
- Simplify the database schema for `event_edges`. ([\#12893](https://github.com/matrix-org/synapse/issues/12893))
- Clean up the test code for client disconnection. ([\#12929](https://github.com/matrix-org/synapse/issues/12929))
- Remove code generating comments in configuration. ([\#12941](https://github.com/matrix-org/synapse/issues/12941))
- Add `Cross-Origin-Resource-Policy: cross-origin` header to content repository's thumbnail and download endpoints. ([\#12944](https://github.com/matrix-org/synapse/issues/12944))
- Replace noop background updates with `DELETE` delta. ([\#12954](https://github.com/matrix-org/synapse/issues/12954), [\#13050](https://github.com/matrix-org/synapse/issues/13050))
- Use lower isolation level when inserting read receipts to avoid serialization errors. Contributed by Nick @ Beeper. ([\#12957](https://github.com/matrix-org/synapse/issues/12957))
- Reduce the amount of state we pull from the DB. ([\#12963](https://github.com/matrix-org/synapse/issues/12963))
- Enable testing against PostgreSQL databases in Complement CI. ([\#12965](https://github.com/matrix-org/synapse/issues/12965), [\#13034](https://github.com/matrix-org/synapse/issues/13034))
- Fix an inaccurate comment. ([\#12969](https://github.com/matrix-org/synapse/issues/12969))
- Remove the `delete_device` method and always call `delete_devices`. ([\#12970](https://github.com/matrix-org/synapse/issues/12970))
- Use a GitHub form for issues rather than a hard-to-read, easy-to-ignore template. ([\#12982](https://github.com/matrix-org/synapse/issues/12982))
- Move [MSC3715](https://github.com/matrix-org/matrix-spec-proposals/pull/3715) behind an experimental config flag. ([\#12984](https://github.com/matrix-org/synapse/issues/12984))
- Add type hints to tests. ([\#12985](https://github.com/matrix-org/synapse/issues/12985), [\#13099](https://github.com/matrix-org/synapse/issues/13099))
- Refactor macaroon tokens generation and move the unsubscribe link in notification emails to `/_synapse/client/unsubscribe`. ([\#12986](https://github.com/matrix-org/synapse/issues/12986))
- Fix documentation for running complement tests. ([\#12990](https://github.com/matrix-org/synapse/issues/12990))
- Faster joins: add issue links to the TODO comments in the code. ([\#13004](https://github.com/matrix-org/synapse/issues/13004))
- Reduce DB usage of `/sync` when a large number of unread messages have recently been sent in a room. ([\#13005](https://github.com/matrix-org/synapse/issues/13005), [\#13096](https://github.com/matrix-org/synapse/issues/13096), [\#13118](https://github.com/matrix-org/synapse/issues/13118))
- Replaced usage of PyJWT with methods from Authlib in `org.matrix.login.jwt`. Contributed by Hannes Lerchl. ([\#13011](https://github.com/matrix-org/synapse/issues/13011))
- Modernize the `contrib/graph/` scripts. ([\#13013](https://github.com/matrix-org/synapse/issues/13013))
- Remove redundant `room_version` parameters from event auth functions. ([\#13017](https://github.com/matrix-org/synapse/issues/13017))
- Decouple `synapse.api.auth_blocking.AuthBlocking` from `synapse.api.auth.Auth`. ([\#13021](https://github.com/matrix-org/synapse/issues/13021))
- Add type annotations to `synapse.storage.databases.main.devices`. ([\#13025](https://github.com/matrix-org/synapse/issues/13025))
- Set default `sync_response_cache_duration` to two minutes. ([\#13042](https://github.com/matrix-org/synapse/issues/13042))
- Rename CI test runs. ([\#13046](https://github.com/matrix-org/synapse/issues/13046))
- Increase timeout of complement CI test runs. ([\#13048](https://github.com/matrix-org/synapse/issues/13048))
- Refactor entry points so that they all have a `main` function. ([\#13052](https://github.com/matrix-org/synapse/issues/13052))
- Refactor the Dockerfile-workers configuration script to use Jinja2 templates in Synapse workers' Supervisord blocks. ([\#13054](https://github.com/matrix-org/synapse/issues/13054))
- Add headers to individual options in config documentation to allow for linking. ([\#13055](https://github.com/matrix-org/synapse/issues/13055))
- Make Complement CI logs easier to read. ([\#13057](https://github.com/matrix-org/synapse/issues/13057), [\#13058](https://github.com/matrix-org/synapse/issues/13058), [\#13069](https://github.com/matrix-org/synapse/issues/13069))
- Don't instantiate modules with keyword arguments. ([\#13060](https://github.com/matrix-org/synapse/issues/13060))
- Fix type checking errors against Twisted trunk. ([\#13061](https://github.com/matrix-org/synapse/issues/13061))
- Allow MSC3030 `timestamp_to_event` calls from anyone on world-readable rooms. ([\#13062](https://github.com/matrix-org/synapse/issues/13062))
- Add a CI job to check that schema deltas are in the correct folder. ([\#13063](https://github.com/matrix-org/synapse/issues/13063))
- Avoid rechecking event auth rules which are independent of room state. ([\#13065](https://github.com/matrix-org/synapse/issues/13065))
- Reduce the duplication of code that invokes the rate limiter. ([\#13070](https://github.com/matrix-org/synapse/issues/13070))
- Add a Subject Alternative Name to the certificate generated for Complement tests. ([\#13071](https://github.com/matrix-org/synapse/issues/13071))
- Add more tests for room upgrades. ([\#13074](https://github.com/matrix-org/synapse/issues/13074))
- Pin dependencies maintained by matrix.org to [semantic version](https://semver.org/) bounds. ([\#13082](https://github.com/matrix-org/synapse/issues/13082))
- Correctly report prometheus DB stats for `get_earliest_token_for_stats`. ([\#13085](https://github.com/matrix-org/synapse/issues/13085))
- Fix a long-standing bug where a finished logging context would be re-started when Synapse failed to persist an event from federation. ([\#13089](https://github.com/matrix-org/synapse/issues/13089))
- Simplify the alias deletion logic as an application service. ([\#13093](https://github.com/matrix-org/synapse/issues/13093))
- Add type annotations to `tests.test_server`. ([\#13124](https://github.com/matrix-org/synapse/issues/13124))


Synapse 1.61.1 (2022-06-28)
===========================

This patch release fixes a security issue regarding URL previews, affecting all prior versions of Synapse. Server administrators are encouraged to update Synapse as soon as possible. We are not aware of these vulnerabilities being exploited in the wild.

Server administrators who are unable to update Synapse may use the workarounds described in the linked GitHub Security Advisory below.

## Security advisory

The following issue is fixed in 1.61.1.

* [GHSA-22p3-qrh9-cx32](https://github.com/matrix-org/synapse/security/advisories/GHSA-22p3-qrh9-cx32) / [CVE-2022-31052](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31052)

  Synapse instances with the [`url_preview_enabled`](https://matrix-org.github.io/synapse/v1.61/usage/configuration/config_documentation.html#media-store) homeserver config option set to `true` are affected. URL previews of some web pages can lead to unbounded recursion, causing the request to either fail, or in some cases crash the running Synapse process.

  Requesting URL previews requires authentication. Nevertheless, it is possible to exploit this maliciously, either by malicious users on the homeserver, or by remote users sending URLs that a local user's client may automatically request a URL preview for.

  Homeservers with the `url_preview_enabled` configuration option set to `false` (the default) are unaffected. Instances with the `enable_media_repo` configuration option set to `false` are also unaffected, as this also disables URL preview functionality.

  Fixed by [fa1308061802ac7b7d20e954ba7372c5ac292333](https://github.com/matrix-org/synapse/commit/fa1308061802ac7b7d20e954ba7372c5ac292333).

Synapse 1.61.0 (2022-06-14)
===========================

This release removes support for the non-standard feature known both as 'groups' and as 'communities', which have been superseded by *Spaces*.

See [the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1610)
for more details.

Improved Documentation
----------------------

- Mention removed community/group worker endpoints in [the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1610). Contributed by @olmari. ([\#13023](https://github.com/matrix-org/synapse/issues/13023))


Synapse 1.61.0rc1 (2022-06-07)
==============================

Features
--------

- Add new `media_retention` options to the homeserver config for routinely cleaning up non-recently accessed media. ([\#12732](https://github.com/matrix-org/synapse/issues/12732), [\#12972](https://github.com/matrix-org/synapse/issues/12972), [\#12977](https://github.com/matrix-org/synapse/issues/12977))
- Experimental support for [MSC3772](https://github.com/matrix-org/matrix-spec-proposals/pull/3772): Push rule for mutually related events. ([\#12740](https://github.com/matrix-org/synapse/issues/12740), [\#12859](https://github.com/matrix-org/synapse/issues/12859))
- Update to the `check_event_for_spam` module callback: Deprecate the current callback signature, replace it with a new signature that is both less ambiguous (replacing booleans with explicit allow/block) and more powerful (ability to return explicit error codes). ([\#12808](https://github.com/matrix-org/synapse/issues/12808))
- Add storage and module API methods to get monthly active users (and their corresponding appservices) within an optionally specified time range. ([\#12838](https://github.com/matrix-org/synapse/issues/12838), [\#12917](https://github.com/matrix-org/synapse/issues/12917))
- Support the new error code `ORG.MATRIX.MSC3823.USER_ACCOUNT_SUSPENDED` from [MSC3823](https://github.com/matrix-org/matrix-spec-proposals/pull/3823). ([\#12845](https://github.com/matrix-org/synapse/issues/12845), [\#12923](https://github.com/matrix-org/synapse/issues/12923))
- Add a configurable background job to delete stale devices. ([\#12855](https://github.com/matrix-org/synapse/issues/12855))
- Improve URL previews for pages with empty elements. ([\#12951](https://github.com/matrix-org/synapse/issues/12951))
- Allow updating a user's password using the admin API without logging out their devices. Contributed by @jcgruenhage. ([\#12952](https://github.com/matrix-org/synapse/issues/12952))


Bugfixes
--------

- Always send an `access_token` in `/thirdparty/` requests to appservices, as required by the [Application Service API specification](https://spec.matrix.org/v1.1/application-service-api/#third-party-networks). ([\#12746](https://github.com/matrix-org/synapse/issues/12746))
- Implement [MSC3816](https://github.com/matrix-org/matrix-spec-proposals/pull/3816): sending the root event in a thread should count as having 'participated' in it. ([\#12766](https://github.com/matrix-org/synapse/issues/12766))
- Delete events from the `federation_inbound_events_staging` table when a room is purged through the admin API. ([\#12784](https://github.com/matrix-org/synapse/issues/12784))
- Fix a bug where we did not correctly handle invalid device list updates over federation. Contributed by Carl Bordum Hansen. ([\#12829](https://github.com/matrix-org/synapse/issues/12829))
- Fix a bug which allowed multiple async operations to access database locks concurrently. Contributed by @sumnerevans @ Beeper. ([\#12832](https://github.com/matrix-org/synapse/issues/12832))
- Fix an issue introduced in Synapse 0.34 where the `/notifications` endpoint would only return notifications if a user registered at least one pusher. Contributed by Famedly. ([\#12840](https://github.com/matrix-org/synapse/issues/12840))
- Fix a bug where servers using a Postgres database would fail to backfill from an insertion event when MSC2716 is enabled (`experimental_features.msc2716_enabled`). ([\#12843](https://github.com/matrix-org/synapse/issues/12843))
- Fix [MSC3787](https://github.com/matrix-org/matrix-spec-proposals/pull/3787) rooms being omitted from room directory, room summary and space hierarchy responses. ([\#12858](https://github.com/matrix-org/synapse/issues/12858))
- Fix a bug introduced in Synapse 1.54.0 which could sometimes cause exceptions when handling federated traffic. ([\#12877](https://github.com/matrix-org/synapse/issues/12877))
- Fix a bug introduced in Synapse 1.59.0 which caused room deletion to fail with a foreign key violation error. ([\#12889](https://github.com/matrix-org/synapse/issues/12889))
- Fix a long-standing bug which caused the `/messages` endpoint to return an incorrect `end` attribute when there were no more events. Contributed by @Vetchu. ([\#12903](https://github.com/matrix-org/synapse/issues/12903))
- Fix a bug introduced in Synapse 1.58.0 where `/sync` would fail if the most recent event in a room was a redaction of an event that has since been purged. ([\#12905](https://github.com/matrix-org/synapse/issues/12905))
- Fix a potential memory leak when generating thumbnails. ([\#12932](https://github.com/matrix-org/synapse/issues/12932))
- Fix a long-standing bug where a URL preview would break if the image failed to download. ([\#12950](https://github.com/matrix-org/synapse/issues/12950))


Improved Documentation
----------------------

- Fix typographical errors in documentation. ([\#12863](https://github.com/matrix-org/synapse/issues/12863))
- Fix documentation incorrectly stating the `sendToDevice` endpoint can be directed at generic workers. Contributed by Nick @ Beeper. ([\#12867](https://github.com/matrix-org/synapse/issues/12867))


Deprecations and Removals
-------------------------

- Remove support for the non-standard groups/communities feature from Synapse. ([\#12553](https://github.com/matrix-org/synapse/issues/12553), [\#12558](https://github.com/matrix-org/synapse/issues/12558), [\#12563](https://github.com/matrix-org/synapse/issues/12563), [\#12895](https://github.com/matrix-org/synapse/issues/12895), [\#12897](https://github.com/matrix-org/synapse/issues/12897), [\#12899](https://github.com/matrix-org/synapse/issues/12899), [\#12900](https://github.com/matrix-org/synapse/issues/12900), [\#12936](https://github.com/matrix-org/synapse/issues/12936), [\#12966](https://github.com/matrix-org/synapse/issues/12966))
- Remove contributed `kick_users.py` script. This is broken under Python 3, and is not added to the environment when `pip install`ing Synapse. ([\#12908](https://github.com/matrix-org/synapse/issues/12908))
- Remove `contrib/jitsimeetbridge`. This was an unused experiment that hasn't been meaningfully changed since 2014. ([\#12909](https://github.com/matrix-org/synapse/issues/12909))
- Remove unused `contrib/experiements/cursesio.py` script, which fails to run under Python 3. ([\#12910](https://github.com/matrix-org/synapse/issues/12910))
- Remove unused `contrib/experiements/test_messaging.py` script. This fails to run on Python 3. ([\#12911](https://github.com/matrix-org/synapse/issues/12911))


Internal Changes
----------------

- Test Synapse against Complement with workers. ([\#12810](https://github.com/matrix-org/synapse/issues/12810), [\#12933](https://github.com/matrix-org/synapse/issues/12933))
- Reduce the amount of state we pull from the DB. ([\#12811](https://github.com/matrix-org/synapse/issues/12811), [\#12964](https://github.com/matrix-org/synapse/issues/12964))
- Try other homeservers when re-syncing state for rooms with partial state. ([\#12812](https://github.com/matrix-org/synapse/issues/12812))
- Resume state re-syncing for rooms with partial state after a Synapse restart. ([\#12813](https://github.com/matrix-org/synapse/issues/12813))
- Remove Mutual Rooms' ([MSC2666](https://github.com/matrix-org/matrix-spec-proposals/pull/2666)) endpoint dependency on the User Directory. ([\#12836](https://github.com/matrix-org/synapse/issues/12836))
- Experimental: expand `check_event_for_spam` with ability to return additional fields. This enables spam-checker implementations to experiment with mechanisms to give users more information about why they are blocked and whether any action is needed from them to be unblocked. ([\#12846](https://github.com/matrix-org/synapse/issues/12846))
- Remove `dont_notify` from the `.m.rule.room.server_acl` rule. ([\#12849](https://github.com/matrix-org/synapse/issues/12849))
- Remove the unstable `/hierarchy` endpoint from [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#12851](https://github.com/matrix-org/synapse/issues/12851))
- Pull out less state when handling gaps in room DAG. ([\#12852](https://github.com/matrix-org/synapse/issues/12852), [\#12904](https://github.com/matrix-org/synapse/issues/12904))
- Clean-up the push rules datastore. ([\#12856](https://github.com/matrix-org/synapse/issues/12856))
- Correct a type annotation in the URL preview source code. ([\#12860](https://github.com/matrix-org/synapse/issues/12860))
- Update `pyjwt` dependency to [2.4.0](https://github.com/jpadilla/pyjwt/releases/tag/2.4.0). ([\#12865](https://github.com/matrix-org/synapse/issues/12865))
- Enable the `/account/whoami` endpoint on synapse worker processes. Contributed by Nick @ Beeper. ([\#12866](https://github.com/matrix-org/synapse/issues/12866))
- Enable the `batch_send` endpoint on synapse worker processes. Contributed by Nick @ Beeper. ([\#12868](https://github.com/matrix-org/synapse/issues/12868))
- Don't generate empty AS transactions when the AS is flagged as down. Contributed by Nick @ Beeper. ([\#12869](https://github.com/matrix-org/synapse/issues/12869))
- Fix up the variable `state_store` naming. ([\#12871](https://github.com/matrix-org/synapse/issues/12871))
- Faster room joins: when querying the current state of the room, wait for state to be populated. ([\#12872](https://github.com/matrix-org/synapse/issues/12872))
- Avoid running queries which will never result in deletions. ([\#12879](https://github.com/matrix-org/synapse/issues/12879))
- Use constants for EDU types. ([\#12884](https://github.com/matrix-org/synapse/issues/12884))
- Reduce database load of `/sync` when presence is enabled. ([\#12885](https://github.com/matrix-org/synapse/issues/12885))
- Refactor `have_seen_events` to reduce memory consumed when processing federation traffic. ([\#12886](https://github.com/matrix-org/synapse/issues/12886))
- Refactor receipt linearization code. ([\#12888](https://github.com/matrix-org/synapse/issues/12888))
- Add type annotations to `synapse.logging.opentracing`. ([\#12894](https://github.com/matrix-org/synapse/issues/12894))
- Remove PyNaCl occurrences directly used in Synapse code. ([\#12902](https://github.com/matrix-org/synapse/issues/12902))
- Bump types-jsonschema from 4.4.1 to 4.4.6. ([\#12912](https://github.com/matrix-org/synapse/issues/12912))
- Rename storage classes. ([\#12913](https://github.com/matrix-org/synapse/issues/12913))
- Preparation for database schema simplifications: stop reading from `event_edges.room_id`. ([\#12914](https://github.com/matrix-org/synapse/issues/12914))
- Check if we are in a virtual environment before overriding the `PYTHONPATH` environment variable in the demo script. ([\#12916](https://github.com/matrix-org/synapse/issues/12916))
- Improve the logging when signature checks on events fail. ([\#12925](https://github.com/matrix-org/synapse/issues/12925))


Synapse 1.60.0 (2022-05-31)
===========================

This release of Synapse adds a unique index to the `state_group_edges` table, in
order to prevent accidentally introducing duplicate information (for example,
because a database backup was restored multiple times). If your Synapse database
already has duplicate rows in this table, this could fail with an error and
require manual remediation.

Additionally, the signature of the `check_event_for_spam` module callback has changed.
The previous signature has been deprecated and remains working for now. Module authors
should update their modules to use the new signature where possible.

See [the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1600)
for more details.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.60.0rc1 that would break some imports from `synapse.module_api`. ([\#12918](https://github.com/matrix-org/synapse/issues/12918))


Synapse 1.60.0rc2 (2022-05-27)
==============================

Features
--------

- Add an option allowing users to use their password to reauthenticate for privileged actions even though password login is disabled. ([\#12883](https://github.com/matrix-org/synapse/issues/12883))


Bugfixes
--------

- Explicitly close `ijson` coroutines once we are done with them, instead of leaving the garbage collector to close them. ([\#12875](https://github.com/matrix-org/synapse/issues/12875))


Internal Changes
----------------

- Improve URL previews by not including the content of media tags in the generated description. ([\#12887](https://github.com/matrix-org/synapse/issues/12887))


Synapse 1.60.0rc1 (2022-05-24)
==============================

Features
--------

- Measure the time taken in spam-checking callbacks and expose those measurements as metrics. ([\#12513](https://github.com/matrix-org/synapse/issues/12513))
- Add a `default_power_level_content_override` config option to set default room power levels per room preset. ([\#12618](https://github.com/matrix-org/synapse/issues/12618))
- Add support for [MSC3787: Allowing knocks to restricted rooms](https://github.com/matrix-org/matrix-spec-proposals/pull/3787). ([\#12623](https://github.com/matrix-org/synapse/issues/12623))
- Send `USER_IP` commands on a different Redis channel, in order to reduce traffic to workers that do not process these commands. ([\#12672](https://github.com/matrix-org/synapse/issues/12672), [\#12809](https://github.com/matrix-org/synapse/issues/12809))
- Synapse will now reload [cache config](https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html#caching) when it receives a [SIGHUP](https://en.wikipedia.org/wiki/SIGHUP) signal. ([\#12673](https://github.com/matrix-org/synapse/issues/12673))
- Add a config options to allow for auto-tuning of caches. ([\#12701](https://github.com/matrix-org/synapse/issues/12701))
- Update [MSC2716](https://github.com/matrix-org/matrix-spec-proposals/pull/2716) implementation to process marker events from the current state to avoid markers being lost in timeline gaps for federated servers which would cause the imported history to be undiscovered. ([\#12718](https://github.com/matrix-org/synapse/issues/12718))
- Add a `drop_federated_event` callback to `SpamChecker` to disregard inbound federated events before they take up much processing power, in an emergency. ([\#12744](https://github.com/matrix-org/synapse/issues/12744))
- Implement [MSC3818: Copy room type on upgrade](https://github.com/matrix-org/matrix-spec-proposals/pull/3818). ([\#12786](https://github.com/matrix-org/synapse/issues/12786), [\#12792](https://github.com/matrix-org/synapse/issues/12792))
- Update to the `check_event_for_spam` module callback. Deprecate the current callback signature, replace it with a new signature that is both less ambiguous (replacing booleans with explicit allow/block) and more powerful (ability to return explicit error codes). ([\#12808](https://github.com/matrix-org/synapse/issues/12808))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.7.0 that would prevent events from being sent to clients if there's a retention policy in the room when the support for retention policies is disabled. ([\#12611](https://github.com/matrix-org/synapse/issues/12611))
- Fix a bug introduced in Synapse 1.57.0 where `/messages` would throw a 500 error when querying for a non-existent room. ([\#12683](https://github.com/matrix-org/synapse/issues/12683))
- Add a unique index to `state_group_edges` to prevent duplicates being accidentally introduced and the consequential impact to performance. ([\#12687](https://github.com/matrix-org/synapse/issues/12687))
- Fix a long-standing bug where an empty room would be created when a user with an insufficient power level tried to upgrade a room. ([\#12696](https://github.com/matrix-org/synapse/issues/12696))
- Fix a bug introduced in Synapse 1.30.0 where empty rooms could be automatically created if a monthly active users limit is set. ([\#12713](https://github.com/matrix-org/synapse/issues/12713))
- Fix push to dismiss notifications when read on another client. Contributed by @SpiritCroc @ Beeper. ([\#12721](https://github.com/matrix-org/synapse/issues/12721))
- Fix poor database performance when reading the cache invalidation stream for large servers with lots of workers. ([\#12747](https://github.com/matrix-org/synapse/issues/12747))
- Fix a long-standing bug where the user directory background process would fail to make forward progress if a user included a null codepoint in their display name or avatar. ([\#12762](https://github.com/matrix-org/synapse/issues/12762))
- Delete events from the `federation_inbound_events_staging` table when a room is purged through the admin API. ([\#12770](https://github.com/matrix-org/synapse/issues/12770))
- Give a meaningful error message when a client tries to create a room with an invalid alias localpart. ([\#12779](https://github.com/matrix-org/synapse/issues/12779))
- Fix a bug introduced in 1.43.0 where a file (`providers.json`) was never closed. Contributed by @arkamar. ([\#12794](https://github.com/matrix-org/synapse/issues/12794))
- Fix a long-standing bug where finished log contexts would be re-started when failing to contact remote homeservers. ([\#12803](https://github.com/matrix-org/synapse/issues/12803))
- Fix a bug, introduced in Synapse 1.21.0, that led to media thumbnails being unusable before the index has been added in the background. ([\#12823](https://github.com/matrix-org/synapse/issues/12823))


Updates to the Docker image
---------------------------

- Fix the docker file after a dependency update. ([\#12853](https://github.com/matrix-org/synapse/issues/12853))


Improved Documentation
----------------------

- Fix a typo in the Media Admin API documentation. ([\#12715](https://github.com/matrix-org/synapse/issues/12715))
- Update the OpenID Connect example for Keycloak to be compatible with newer versions of Keycloak. Contributed by @nhh. ([\#12727](https://github.com/matrix-org/synapse/issues/12727))
- Fix typo in server listener documentation. ([\#12742](https://github.com/matrix-org/synapse/issues/12742))
- Link to the configuration manual from the welcome page of the documentation. ([\#12748](https://github.com/matrix-org/synapse/issues/12748))
- Fix typo in `run_background_tasks_on` option name in configuration manual documentation. ([\#12749](https://github.com/matrix-org/synapse/issues/12749))
- Add information regarding the `rc_invites` ratelimiting option to the configuration docs. ([\#12759](https://github.com/matrix-org/synapse/issues/12759))
- Add documentation for cancellation of request processing. ([\#12761](https://github.com/matrix-org/synapse/issues/12761))
- Recommend using docker to run tests against postgres. ([\#12765](https://github.com/matrix-org/synapse/issues/12765))
- Add missing user directory endpoint from the generic worker documentation. Contributed by @olmari. ([\#12773](https://github.com/matrix-org/synapse/issues/12773))
- Add additional info to documentation of config option `cache_autotuning`. ([\#12776](https://github.com/matrix-org/synapse/issues/12776))
- Update configuration manual documentation to document size-related suffixes. ([\#12777](https://github.com/matrix-org/synapse/issues/12777))
- Fix invalid YAML syntax in the example documentation for the `url_preview_accept_language` config option. ([\#12785](https://github.com/matrix-org/synapse/issues/12785))


Deprecations and Removals
-------------------------

- Require a body in POST requests to `/rooms/{roomId}/receipt/{receiptType}/{eventId}`, as required by the [Matrix specification](https://spec.matrix.org/v1.2/client-server-api/#post_matrixclientv3roomsroomidreceiptreceipttypeeventid). This breaks compatibility with Element Android 1.2.0 and earlier: users of those clients will be unable to send read receipts. ([\#12709](https://github.com/matrix-org/synapse/issues/12709))


Internal Changes
----------------

- Improve event caching mechanism to avoid having multiple copies of an event in memory at a time. ([\#10533](https://github.com/matrix-org/synapse/issues/10533))
- Preparation for faster-room-join work: return subsets of room state which we already have, immediately. ([\#12498](https://github.com/matrix-org/synapse/issues/12498))
- Add `@cancellable` decorator, for use on endpoint methods that can be cancelled when clients disconnect. ([\#12586](https://github.com/matrix-org/synapse/issues/12586), [\#12588](https://github.com/matrix-org/synapse/issues/12588), [\#12630](https://github.com/matrix-org/synapse/issues/12630), [\#12694](https://github.com/matrix-org/synapse/issues/12694), [\#12698](https://github.com/matrix-org/synapse/issues/12698), [\#12699](https://github.com/matrix-org/synapse/issues/12699), [\#12700](https://github.com/matrix-org/synapse/issues/12700), [\#12705](https://github.com/matrix-org/synapse/issues/12705))
- Enable cancellation of `GET /rooms/$room_id/members`, `GET /rooms/$room_id/state` and `GET /rooms/$room_id/state/$event_type/*` requests. ([\#12708](https://github.com/matrix-org/synapse/issues/12708))
- Improve documentation of the `synapse.push` module. ([\#12676](https://github.com/matrix-org/synapse/issues/12676))
- Refactor functions to on `PushRuleEvaluatorForEvent`. ([\#12677](https://github.com/matrix-org/synapse/issues/12677))
- Preparation for database schema simplifications: stop writing to `event_reference_hashes`. ([\#12679](https://github.com/matrix-org/synapse/issues/12679))
- Remove code which updates unused database column `application_services_state.last_txn`. ([\#12680](https://github.com/matrix-org/synapse/issues/12680))
- Refactor `EventContext` class. ([\#12689](https://github.com/matrix-org/synapse/issues/12689))
- Remove an unneeded class in the push code. ([\#12691](https://github.com/matrix-org/synapse/issues/12691))
- Consolidate parsing of relation information from events. ([\#12693](https://github.com/matrix-org/synapse/issues/12693))
- Convert namespace class `Codes` into a string enum. ([\#12703](https://github.com/matrix-org/synapse/issues/12703))
- Optimize private read receipt filtering. ([\#12711](https://github.com/matrix-org/synapse/issues/12711))
- Drop the logging level of status messages for the URL preview cache expiry job from INFO to DEBUG. ([\#12720](https://github.com/matrix-org/synapse/issues/12720))
- Downgrade some OIDC errors to warnings in the logs, to reduce the noise of Sentry reports. ([\#12723](https://github.com/matrix-org/synapse/issues/12723))
- Update configs used by Complement to allow more invites/3PID validations during tests. ([\#12731](https://github.com/matrix-org/synapse/issues/12731))
- Tweak the mypy plugin so that `@cached` can accept `on_invalidate=None`. ([\#12769](https://github.com/matrix-org/synapse/issues/12769))
- Move methods that call `add_push_rule` to the `PushRuleStore` class. ([\#12772](https://github.com/matrix-org/synapse/issues/12772))
- Make handling of federation Authorization header (more) compliant with RFC7230. ([\#12774](https://github.com/matrix-org/synapse/issues/12774))
- Refactor `resolve_state_groups_for_events` to not pull out full state when no state resolution happens. ([\#12775](https://github.com/matrix-org/synapse/issues/12775))
- Do not keep going if there are 5 back-to-back background update failures. ([\#12781](https://github.com/matrix-org/synapse/issues/12781))
- Fix federation when using the demo scripts. ([\#12783](https://github.com/matrix-org/synapse/issues/12783))
- The `hash_password` script now fails when it is called without specifying a config file. Contributed by @jae1911. ([\#12789](https://github.com/matrix-org/synapse/issues/12789))
- Improve and fix type hints. ([\#12567](https://github.com/matrix-org/synapse/issues/12567), [\#12477](https://github.com/matrix-org/synapse/issues/12477), [\#12717](https://github.com/matrix-org/synapse/issues/12717), [\#12753](https://github.com/matrix-org/synapse/issues/12753), [\#12695](https://github.com/matrix-org/synapse/issues/12695), [\#12734](https://github.com/matrix-org/synapse/issues/12734), [\#12716](https://github.com/matrix-org/synapse/issues/12716), [\#12726](https://github.com/matrix-org/synapse/issues/12726), [\#12790](https://github.com/matrix-org/synapse/issues/12790), [\#12833](https://github.com/matrix-org/synapse/issues/12833))
- Update EventContext `get_current_event_ids` and `get_prev_event_ids` to accept state filters and update calls where possible. ([\#12791](https://github.com/matrix-org/synapse/issues/12791))
- Remove Caddy from the Synapse workers image used in Complement. ([\#12818](https://github.com/matrix-org/synapse/issues/12818))
- Add Complement's shared registration secret to the Complement worker image. This fixes tests that depend on it. ([\#12819](https://github.com/matrix-org/synapse/issues/12819))
- Support registering Application Services when running with workers under Complement. ([\#12826](https://github.com/matrix-org/synapse/issues/12826))
- Disable 'faster room join' Complement tests when testing against Synapse with workers. ([\#12842](https://github.com/matrix-org/synapse/issues/12842))


Synapse 1.59.1 (2022-05-18)
===========================

This release fixes a long-standing issue which could prevent Synapse's user directory for updating properly.

Bugfixes
----------------

- Fix a long-standing bug where the user directory background process would fail to make forward progress if a user included a null codepoint in their display name or avatar. Contributed by Nick @ Beeper. ([\#12762](https://github.com/matrix-org/synapse/issues/12762))


Synapse 1.59.0 (2022-05-17)
===========================

Synapse 1.59 makes several changes that server administrators should be aware of:

- Device name lookup over federation is now disabled by default. ([\#12616](https://github.com/matrix-org/synapse/issues/12616))
- The `synapse.app.appservice` and `synapse.app.user_dir` worker application types are now deprecated. ([\#12452](https://github.com/matrix-org/synapse/issues/12452), [\#12654](https://github.com/matrix-org/synapse/issues/12654))

See [the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1590) for more details.

Additionally, this release removes the non-standard `m.login.jwt` login type from Synapse. It can be replaced with `org.matrix.login.jwt` for identical behaviour. This is only used if `jwt_config.enabled` is set to `true` in the configuration. ([\#12597](https://github.com/matrix-org/synapse/issues/12597))


Bugfixes
--------

- Fix DB performance regression introduced in Synapse 1.59.0rc2. ([\#12745](https://github.com/matrix-org/synapse/issues/12745))


Synapse 1.59.0rc2 (2022-05-16)
==============================

Note: this release candidate includes a performance regression which can cause database disruption. Other release candidates in the v1.59.0 series are not affected, and a fix will be included in the v1.59.0 final release.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.58.0 where `/sync` would fail if the most recent event in a room was rejected. ([\#12729](https://github.com/matrix-org/synapse/issues/12729))


Synapse 1.59.0rc1 (2022-05-10)
==============================

Features
--------

- Support [MSC3266](https://github.com/matrix-org/matrix-doc/pull/3266) room summaries over federation. ([\#11507](https://github.com/matrix-org/synapse/issues/11507))
- Implement [changes](https://github.com/matrix-org/matrix-spec-proposals/pull/2285/commits/4a77139249c2e830aec3c7d6bd5501a514d1cc27) to [MSC2285 (hidden read receipts)](https://github.com/matrix-org/matrix-spec-proposals/pull/2285). Contributed by @SimonBrandner. ([\#12168](https://github.com/matrix-org/synapse/issues/12168), [\#12635](https://github.com/matrix-org/synapse/issues/12635), [\#12636](https://github.com/matrix-org/synapse/issues/12636), [\#12670](https://github.com/matrix-org/synapse/issues/12670))
- Extend the [module API](https://github.com/matrix-org/synapse/blob/release-v1.59/synapse/module_api/__init__.py) to allow modules to change actions for existing push rules of local users. ([\#12406](https://github.com/matrix-org/synapse/issues/12406))
- Add the `notify_appservices_from_worker` configuration option (superseding `notify_appservices`) to allow a generic worker to be designated as the worker to send traffic to Application Services. ([\#12452](https://github.com/matrix-org/synapse/issues/12452))
- Add the `update_user_directory_from_worker` configuration option (superseding `update_user_directory`) to allow a generic worker to be designated as the worker to update the user directory. ([\#12654](https://github.com/matrix-org/synapse/issues/12654))
- Add new `enable_registration_token_3pid_bypass` configuration option to allow registrations via token as an alternative to verifying a 3pid. ([\#12526](https://github.com/matrix-org/synapse/issues/12526))
- Implement [MSC3786](https://github.com/matrix-org/matrix-spec-proposals/pull/3786): Add a default push rule to ignore `m.room.server_acl` events. ([\#12601](https://github.com/matrix-org/synapse/issues/12601))
- Add new `mau_appservice_trial_days` configuration option to specify a different trial period for users registered via an appservice. ([\#12619](https://github.com/matrix-org/synapse/issues/12619))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.48.0 where the latest thread reply provided failed to include the proper bundled aggregations. ([\#12273](https://github.com/matrix-org/synapse/issues/12273))
- Fix a bug introduced in Synapse 1.22.0 where attempting to send a large amount of read receipts to an application service all at once would result in duplicate content and abnormally high memory usage. Contributed by Brad & Nick @ Beeper. ([\#12544](https://github.com/matrix-org/synapse/issues/12544))
- Fix a bug introduced in Synapse 1.57.0 which could cause `Failed to calculate hosts in room` errors to be logged for outbound federation. ([\#12570](https://github.com/matrix-org/synapse/issues/12570))
- Fix a long-standing bug where status codes would almost always get logged as `200!`, irrespective of the actual status code, when clients disconnect before a request has finished processing. ([\#12580](https://github.com/matrix-org/synapse/issues/12580))
- Fix race when persisting an event and deleting a room that could lead to outbound federation breaking. ([\#12594](https://github.com/matrix-org/synapse/issues/12594))
- Fix a bug introduced in Synapse 1.53.0 where bundled aggregations for annotations/edits were incorrectly calculated. ([\#12633](https://github.com/matrix-org/synapse/issues/12633))
- Fix a long-standing bug where rooms containing power levels with string values could not be upgraded. ([\#12657](https://github.com/matrix-org/synapse/issues/12657))
- Prevent memory leak from reoccurring when presence is disabled. ([\#12656](https://github.com/matrix-org/synapse/issues/12656))


Updates to the Docker image
---------------------------

- Explicitly opt-in to using [BuildKit-specific features](https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md) in the Dockerfile. This fixes issues with building images in some GitLab CI environments. ([\#12541](https://github.com/matrix-org/synapse/issues/12541))
- Update the "Build docker images" GitHub Actions workflow to use `docker/metadata-action` to generate docker image tags, instead of a custom shell script. Contributed by @henryclw. ([\#12573](https://github.com/matrix-org/synapse/issues/12573))


Improved Documentation
----------------------

- Update SQL statements and replace use of old table `user_stats_historical` in docs for Synapse Admins. ([\#12536](https://github.com/matrix-org/synapse/issues/12536))
- Add missing linebreak to `pipx` install instructions. ([\#12579](https://github.com/matrix-org/synapse/issues/12579))
- Add information about the TCP replication module to docs. ([\#12621](https://github.com/matrix-org/synapse/issues/12621))
- Fixes to the formatting of `README.rst`. ([\#12627](https://github.com/matrix-org/synapse/issues/12627))
- Fix docs on how to run specific Complement tests using the `complement.sh` test runner. ([\#12664](https://github.com/matrix-org/synapse/issues/12664))


Deprecations and Removals
-------------------------

- Remove unstable identifiers from [MSC3069](https://github.com/matrix-org/matrix-doc/pull/3069). ([\#12596](https://github.com/matrix-org/synapse/issues/12596))
- Remove the unspecified `m.login.jwt` login type and the unstable `uk.half-shot.msc2778.login.application_service` from
  [MSC2778](https://github.com/matrix-org/matrix-doc/pull/2778). ([\#12597](https://github.com/matrix-org/synapse/issues/12597))
- Synapse now requires at least Python 3.7.1 (up from 3.7.0), for compatibility with the latest Twisted trunk. ([\#12613](https://github.com/matrix-org/synapse/issues/12613))


Internal Changes
----------------

- Use supervisord to supervise Postgres and Caddy in the Complement image to reduce restart time. ([\#12480](https://github.com/matrix-org/synapse/issues/12480))
- Immediately retry any requests that have backed off when a server comes back online. ([\#12500](https://github.com/matrix-org/synapse/issues/12500))
- Use `make_awaitable` instead of `defer.succeed` for return values of mocks in tests. ([\#12505](https://github.com/matrix-org/synapse/issues/12505))
- Consistently check if an object is a `frozendict`. ([\#12564](https://github.com/matrix-org/synapse/issues/12564))
- Protect module callbacks with read semantics against cancellation. ([\#12568](https://github.com/matrix-org/synapse/issues/12568))
- Improve comments and error messages around access tokens. ([\#12577](https://github.com/matrix-org/synapse/issues/12577))
- Improve docstrings for the receipts store. ([\#12581](https://github.com/matrix-org/synapse/issues/12581))
- Use constants for read-receipts in tests. ([\#12582](https://github.com/matrix-org/synapse/issues/12582))
- Log status code of cancelled requests as 499 and avoid logging stack traces for them. ([\#12587](https://github.com/matrix-org/synapse/issues/12587), [\#12663](https://github.com/matrix-org/synapse/issues/12663))
- Remove special-case for `twisted` logger from default log config. ([\#12589](https://github.com/matrix-org/synapse/issues/12589))
- Use `getClientAddress` instead of the deprecated `getClientIP`. ([\#12599](https://github.com/matrix-org/synapse/issues/12599))
- Add link to documentation in Grafana Dashboard. ([\#12602](https://github.com/matrix-org/synapse/issues/12602))
- Reduce log spam when running multiple event persisters. ([\#12610](https://github.com/matrix-org/synapse/issues/12610))
- Add extra debug logging to federation sender. ([\#12614](https://github.com/matrix-org/synapse/issues/12614))
- Prevent remote homeservers from requesting local user device names by default. ([\#12616](https://github.com/matrix-org/synapse/issues/12616))
- Add a consistency check on events which we read from the database. ([\#12620](https://github.com/matrix-org/synapse/issues/12620))
- Remove use of the `constantly` library and switch to enums for `EventRedactBehaviour`. Contributed by @andrewdoh. ([\#12624](https://github.com/matrix-org/synapse/issues/12624))
- Remove unused code related to receipts. ([\#12632](https://github.com/matrix-org/synapse/issues/12632))
- Minor improvements to the scripts for running Synapse in worker mode under Complement. ([\#12637](https://github.com/matrix-org/synapse/issues/12637))
- Move `pympler` back in to the `all` extras. ([\#12652](https://github.com/matrix-org/synapse/issues/12652))
- Fix spelling of `M_UNRECOGNIZED` in comments. ([\#12665](https://github.com/matrix-org/synapse/issues/12665))
- Release script: confirm the commit to be tagged before tagging. ([\#12556](https://github.com/matrix-org/synapse/issues/12556))
- Fix a typo in the announcement text generated by the Synapse release development script. ([\#12612](https://github.com/matrix-org/synapse/issues/12612))

### Typechecking

- Fix scripts-dev to pass typechecking. ([\#12356](https://github.com/matrix-org/synapse/issues/12356))
- Add some type hints to datastore. ([\#12485](https://github.com/matrix-org/synapse/issues/12485))
- Remove unused `# type: ignore`s. ([\#12531](https://github.com/matrix-org/synapse/issues/12531))
- Allow unused `# type: ignore` comments in bleeding edge CI jobs. ([\#12576](https://github.com/matrix-org/synapse/issues/12576))
- Remove redundant lines of config from `mypy.ini`. ([\#12608](https://github.com/matrix-org/synapse/issues/12608))
- Update to mypy 0.950. ([\#12650](https://github.com/matrix-org/synapse/issues/12650))
- Use `Concatenate` to better annotate `_do_execute`. ([\#12666](https://github.com/matrix-org/synapse/issues/12666))
- Use `ParamSpec` to refine type hints. ([\#12667](https://github.com/matrix-org/synapse/issues/12667))
- Fix mypy against latest pillow stubs. ([\#12671](https://github.com/matrix-org/synapse/issues/12671))

Synapse 1.58.1 (2022-05-05)
===========================

This patch release includes a fix to the Debian packages, installing the
`systemd` and `cache_memory` extra package groups, which were incorrectly
omitted in v1.58.0. This primarily prevented Synapse from starting
when the `systemd.journal.JournalHandler` log handler was configured.
See [#12631](https://github.com/matrix-org/synapse/issues/12631) for further information.

Otherwise, no significant changes since 1.58.0.


Synapse 1.58.0 (2022-05-03)
===========================

As of this release, the groups/communities feature in Synapse is now disabled by default. See [\#11584](https://github.com/matrix-org/synapse/issues/11584) for details. As mentioned in [the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1580), this feature will be removed in Synapse 1.61.

No significant changes since 1.58.0rc2.


Synapse 1.58.0rc2 (2022-04-26)
==============================

This release candidate fixes bugs related to Synapse 1.58.0rc1's logic for handling device list updates.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.58.0rc1 where the main process could consume excessive amounts of CPU and memory while handling sentry logging failures. ([\#12554](https://github.com/matrix-org/synapse/issues/12554))
- Fix a bug introduced in Synapse 1.58.0rc1 where opentracing contexts were not correctly sent to whitelisted remote servers with device lists updates. ([\#12555](https://github.com/matrix-org/synapse/issues/12555))


Internal Changes
----------------

- Reduce unnecessary work when handling remote device list updates. ([\#12557](https://github.com/matrix-org/synapse/issues/12557))


Synapse 1.58.0rc1 (2022-04-26)
==============================

Features
--------

- Implement [MSC3383](https://github.com/matrix-org/matrix-spec-proposals/pull/3383) for including the destination in server-to-server authentication headers. Contributed by @Bubu and @jcgruenhage for Famedly. ([\#11398](https://github.com/matrix-org/synapse/issues/11398))
- Docker images and Debian packages from matrix.org now contain a locked set of Python dependencies, greatly improving build reproducibility. ([Board](https://github.com/orgs/matrix-org/projects/54), [\#11537](https://github.com/matrix-org/synapse/issues/11537))
- Enable processing of device list updates asynchronously. ([\#12365](https://github.com/matrix-org/synapse/issues/12365), [\#12465](https://github.com/matrix-org/synapse/issues/12465))
- Implement [MSC2815](https://github.com/matrix-org/matrix-spec-proposals/pull/2815) to allow room moderators to view redacted event content. Contributed by @tulir @ Beeper. ([\#12427](https://github.com/matrix-org/synapse/issues/12427))
- Build Debian packages for Ubuntu 22.04 "Jammy Jellyfish". ([\#12543](https://github.com/matrix-org/synapse/issues/12543))


Bugfixes
--------

- Prevent a sync request from removing a user's busy presence status. ([\#12213](https://github.com/matrix-org/synapse/issues/12213))
- Fix bug with incremental sync missing events when rejoining/backfilling. Contributed by Nick @ Beeper. ([\#12319](https://github.com/matrix-org/synapse/issues/12319))
- Fix a long-standing bug which incorrectly caused `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}` to return edited events rather than the original. ([\#12476](https://github.com/matrix-org/synapse/issues/12476))
- Fix a bug introduced in Synapse 1.27.0 where the admin API for [deleting forward extremities](https://github.com/matrix-org/synapse/blob/erikj/fix_delete_event_response_count/docs/admin_api/rooms.md#deleting-forward-extremities) would always return a count of 1, no matter how many extremities were deleted. ([\#12496](https://github.com/matrix-org/synapse/issues/12496))
- Fix a long-standing bug where the image thumbnails embedded into email notifications were broken. ([\#12510](https://github.com/matrix-org/synapse/issues/12510))
- Fix a bug in the implementation of [MSC3202](https://github.com/matrix-org/matrix-spec-proposals/pull/3202) where Synapse would use the field name `device_unused_fallback_keys`, rather than `device_unused_fallback_key_types`. ([\#12520](https://github.com/matrix-org/synapse/issues/12520))
- Fix a bug introduced in Synapse 0.99.3 which could cause Synapse to consume large amounts of RAM when back-paginating in a large room. ([\#12522](https://github.com/matrix-org/synapse/issues/12522))


Improved Documentation
----------------------

- Fix rendering of the documentation site when using the 'print' feature. ([\#12340](https://github.com/matrix-org/synapse/issues/12340))
- Add a manual documenting config file options. ([\#12368](https://github.com/matrix-org/synapse/issues/12368), [\#12527](https://github.com/matrix-org/synapse/issues/12527))
- Update documentation to reflect that both the `run_background_tasks_on` option and the options for moving stream writers off of the main process are no longer experimental. ([\#12451](https://github.com/matrix-org/synapse/issues/12451))
- Update worker documentation and replace old `federation_reader` with `generic_worker`. ([\#12457](https://github.com/matrix-org/synapse/issues/12457))
- Strongly recommend [Poetry](https://python-poetry.org/) for development. ([\#12475](https://github.com/matrix-org/synapse/issues/12475))
- Add some example configurations for workers and update architectural diagram. ([\#12492](https://github.com/matrix-org/synapse/issues/12492))
- Fix a broken link in `README.rst`. ([\#12495](https://github.com/matrix-org/synapse/issues/12495))
- Add HAProxy delegation example with CORS headers to docs. ([\#12501](https://github.com/matrix-org/synapse/issues/12501))
- Remove extraneous comma in User Admin API's device deletion section so that the example JSON is actually valid and works. Contributed by @olmari. ([\#12533](https://github.com/matrix-org/synapse/issues/12533))


Deprecations and Removals
-------------------------

- The groups/communities feature in Synapse is now disabled by default. ([\#12344](https://github.com/matrix-org/synapse/issues/12344))
- Remove unstable identifiers from [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440). ([\#12382](https://github.com/matrix-org/synapse/issues/12382))


Internal Changes
----------------

- Preparation for faster-room-join work: start a background process to resynchronise the room state after a room join. ([\#12394](https://github.com/matrix-org/synapse/issues/12394))
- Preparation for faster-room-join work: Implement a tracking mechanism to allow functions to wait for full room state to arrive. ([\#12399](https://github.com/matrix-org/synapse/issues/12399))
- Remove an unstable identifier from [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083). ([\#12395](https://github.com/matrix-org/synapse/issues/12395))
- Run CI in the locked [Poetry](https://python-poetry.org/) environment, and remove corresponding `tox` jobs. ([\#12425](https://github.com/matrix-org/synapse/issues/12425), [\#12434](https://github.com/matrix-org/synapse/issues/12434), [\#12438](https://github.com/matrix-org/synapse/issues/12438), [\#12441](https://github.com/matrix-org/synapse/issues/12441), [\#12449](https://github.com/matrix-org/synapse/issues/12449), [\#12478](https://github.com/matrix-org/synapse/issues/12478), [\#12514](https://github.com/matrix-org/synapse/issues/12514), [\#12472](https://github.com/matrix-org/synapse/issues/12472))
- Change Mutual Rooms' `unstable_features` flag to `uk.half-shot.msc2666.mutual_rooms` which matches the current iteration of [MSC2666](https://github.com/matrix-org/matrix-spec-proposals/pull/2666). ([\#12445](https://github.com/matrix-org/synapse/issues/12445))
- Fix typo in the release script help string. ([\#12450](https://github.com/matrix-org/synapse/issues/12450))
- Fix a minor typo in the Debian changelogs generated by the release script. ([\#12497](https://github.com/matrix-org/synapse/issues/12497))
- Reintroduce the list of targets to the linter script, to avoid linting unwanted local-only directories during development. ([\#12455](https://github.com/matrix-org/synapse/issues/12455))
- Limit length of `device_id` to less than 512 characters. ([\#12454](https://github.com/matrix-org/synapse/issues/12454))
- Dockerfile-workers: reduce the amount we install in the image. ([\#12464](https://github.com/matrix-org/synapse/issues/12464))
- Dockerfile-workers: give the master its own log config. ([\#12466](https://github.com/matrix-org/synapse/issues/12466))
- complement-synapse-workers: factor out separate entry point script. ([\#12467](https://github.com/matrix-org/synapse/issues/12467))
- Back out experimental implementation of [MSC2314](https://github.com/matrix-org/matrix-spec-proposals/pull/2314). ([\#12474](https://github.com/matrix-org/synapse/issues/12474))
- Fix grammatical error in federation error response when the room version of a room is unknown. ([\#12483](https://github.com/matrix-org/synapse/issues/12483))
- Remove unnecessary configuration overrides in tests. ([\#12511](https://github.com/matrix-org/synapse/issues/12511))
- Refactor the relations code for clarity. ([\#12519](https://github.com/matrix-org/synapse/issues/12519))
- Add type hints so `docker` and `stubs` directories pass `mypy --disallow-untyped-defs`. ([\#12528](https://github.com/matrix-org/synapse/issues/12528))
- Update `delay_cancellation` to accept any awaitable, rather than just `Deferred`s. ([\#12468](https://github.com/matrix-org/synapse/issues/12468))
- Handle cancellation in `EventsWorkerStore._get_events_from_cache_or_db`. ([\#12529](https://github.com/matrix-org/synapse/issues/12529))


Synapse 1.57.1 (2022-04-20)
===========================

This is a patch release that only affects the Docker image. It is only of interest to administrators using [the LDAP module][LDAPModule] to authenticate their users.
If you have already upgraded to Synapse 1.57.0 without problem, then you have no need to upgrade to this patch release.

[LDAPModule]: https://github.com/matrix-org/matrix-synapse-ldap3


Updates to the Docker image
---------------------------

- Include version 0.2.0 of the Synapse LDAP Auth Provider module in the Docker image. This matches the version that was present in the Docker image for Synapse 1.56.0. ([\#12512](https://github.com/matrix-org/synapse/issues/12512))


Synapse 1.57.0 (2022-04-19)
===========================

This version includes a [change](https://github.com/matrix-org/synapse/pull/12209) to the way transaction IDs are managed for application services. If your deployment uses a dedicated worker for application service traffic, **it must be stopped** when the database is upgraded (which normally happens when the main process is upgraded), to ensure the change is made safely without any risk of reusing transaction IDs.

See the [upgrade notes](https://github.com/matrix-org/synapse/blob/v1.57.0rc1/docs/upgrade.md#upgrading-to-v1570) for more details.

No significant changes since 1.57.0rc1.


Synapse 1.57.0rc1 (2022-04-12)
==============================

Features
--------

- Send device list changes to application services as specified by [MSC3202](https://github.com/matrix-org/matrix-spec-proposals/pull/3202), using unstable prefixes. The `msc3202_transaction_extensions` experimental homeserver config option must be enabled and `org.matrix.msc3202: true` must be present in the application service registration file for device list changes to be sent. The "left" field is currently always empty. ([\#11881](https://github.com/matrix-org/synapse/issues/11881))
- Optimise fetching large quantities of missing room state over federation. ([\#12040](https://github.com/matrix-org/synapse/issues/12040))
- Offload the `update_client_ip` background job from the main process to the background worker, when using Redis-based replication. ([\#12251](https://github.com/matrix-org/synapse/issues/12251))
- Move `update_client_ip` background job from the main process to the background worker. ([\#12252](https://github.com/matrix-org/synapse/issues/12252))
- Add a module callback to react to new 3PID (email address, phone number) associations. ([\#12302](https://github.com/matrix-org/synapse/issues/12302))
- Add a configuration option to remove a specific set of rooms from sync responses. ([\#12310](https://github.com/matrix-org/synapse/issues/12310))
- Add a module callback to react to account data changes. ([\#12327](https://github.com/matrix-org/synapse/issues/12327))
- Allow setting user admin status using the module API. Contributed by Famedly. ([\#12341](https://github.com/matrix-org/synapse/issues/12341))
- Reduce overhead of restarting synchrotrons. ([\#12367](https://github.com/matrix-org/synapse/issues/12367), [\#12372](https://github.com/matrix-org/synapse/issues/12372))
- Update `/messages` to use historic pagination tokens if no `from` query parameter is given. ([\#12370](https://github.com/matrix-org/synapse/issues/12370))
- Add a module API for reading and writing global account data. ([\#12391](https://github.com/matrix-org/synapse/issues/12391))
- Support the stable `v1` endpoint for `/relations`, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#12403](https://github.com/matrix-org/synapse/issues/12403))
- Include bundled aggregations in search results
  ([MSC3666](https://github.com/matrix-org/matrix-spec-proposals/pull/3666)). ([\#12436](https://github.com/matrix-org/synapse/issues/12436))


Bugfixes
--------

- Fix a long-standing bug where updates to the server notices user profile (display name/avatar URL) in the configuration would not be applied to pre-existing rooms. Contributed by Jorge Florian. ([\#12115](https://github.com/matrix-org/synapse/issues/12115))
- Fix a long-standing bug where events from ignored users were still considered for bundled aggregations. ([\#12235](https://github.com/matrix-org/synapse/issues/12235), [\#12338](https://github.com/matrix-org/synapse/issues/12338))
- Fix non-member state events not resolving for historical events when used in [MSC2716](https://github.com/matrix-org/matrix-spec-proposals/pull/2716) `/batch_send` `state_events_at_start`. ([\#12329](https://github.com/matrix-org/synapse/issues/12329))
- Fix a long-standing bug affecting URL previews that would generate a 500 response instead of a 403 if the previewed URL includes a port that isn't allowed by the relevant blacklist. ([\#12333](https://github.com/matrix-org/synapse/issues/12333))
- Default to `private` room visibility rather than `public` when a client does not specify one, according to spec. ([\#12350](https://github.com/matrix-org/synapse/issues/12350))
- Fix a spec compliance issue where requests to the `/publicRooms` federation API would specify `limit` as a string. ([\#12364](https://github.com/matrix-org/synapse/issues/12364), [\#12410](https://github.com/matrix-org/synapse/issues/12410))
- Fix a bug introduced in Synapse 1.49.0 which caused the `synapse_event_persisted_position` metric to have invalid values. ([\#12390](https://github.com/matrix-org/synapse/issues/12390))


Updates to the Docker image
---------------------------

- Bundle locked versions of dependencies into the Docker image. ([\#12385](https://github.com/matrix-org/synapse/issues/12385), [\#12439](https://github.com/matrix-org/synapse/issues/12439))
- Fix up healthcheck generation for workers docker image. ([\#12405](https://github.com/matrix-org/synapse/issues/12405))


Improved Documentation
----------------------

- Clarify documentation for running SyTest against Synapse, including use of Postgres and worker mode. ([\#12271](https://github.com/matrix-org/synapse/issues/12271))
- Document the behaviour of `LoggingTransaction.call_after` and `LoggingTransaction.call_on_exception` methods when transactions are retried. ([\#12315](https://github.com/matrix-org/synapse/issues/12315))
- Update dead links in `check-newsfragment.sh` to point to the correct documentation URL. ([\#12331](https://github.com/matrix-org/synapse/issues/12331))
- Upgrade the version of `mdbook` in CI to 0.4.17. ([\#12339](https://github.com/matrix-org/synapse/issues/12339))
- Updates to the Room DAG concepts development document to clarify that we mark events as outliers because we don't have any state for them. ([\#12345](https://github.com/matrix-org/synapse/issues/12345))
- Update the link to Redis pub/sub documentation in the workers documentation. ([\#12369](https://github.com/matrix-org/synapse/issues/12369))
- Remove documentation for converting a legacy structured logging configuration to the new format. ([\#12392](https://github.com/matrix-org/synapse/issues/12392))


Deprecations and Removals
-------------------------

- Remove the unused and unstable `/aggregations` endpoint which was removed from [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#12293](https://github.com/matrix-org/synapse/issues/12293))


Internal Changes
----------------

- Remove lingering unstable references to MSC2403 (knocking). ([\#12165](https://github.com/matrix-org/synapse/issues/12165))
- Avoid trying to calculate the state at outlier events. ([\#12191](https://github.com/matrix-org/synapse/issues/12191), [\#12316](https://github.com/matrix-org/synapse/issues/12316), [\#12330](https://github.com/matrix-org/synapse/issues/12330), [\#12332](https://github.com/matrix-org/synapse/issues/12332), [\#12409](https://github.com/matrix-org/synapse/issues/12409))
- Omit sending "offline" presence updates to application services after they are initially configured. ([\#12193](https://github.com/matrix-org/synapse/issues/12193))
- Switch to using a sequence to generate AS transaction IDs. Contributed by Nick @ Beeper. If running synapse with a dedicated appservice worker, this MUST be stopped before upgrading the main process and database. ([\#12209](https://github.com/matrix-org/synapse/issues/12209))
- Add missing type hints for storage. ([\#12267](https://github.com/matrix-org/synapse/issues/12267))
- Add missing type definitions for scripts in docker folder. Contributed by Jorge Florian. ([\#12280](https://github.com/matrix-org/synapse/issues/12280))
- Move [MSC2654](https://github.com/matrix-org/matrix-doc/pull/2654) support behind an experimental configuration flag. ([\#12295](https://github.com/matrix-org/synapse/issues/12295))
- Update docstrings to explain how to decipher live and historic pagination tokens. ([\#12317](https://github.com/matrix-org/synapse/issues/12317))
- Add ground work for speeding up device list updates for users in large numbers of rooms. ([\#12321](https://github.com/matrix-org/synapse/issues/12321))
- Fix typechecker problems exposed by signedjson 1.1.2. ([\#12326](https://github.com/matrix-org/synapse/issues/12326))
- Remove the `tox` packaging job: it will be redundant once #11537 lands. ([\#12334](https://github.com/matrix-org/synapse/issues/12334))
- Ignore `.envrc` for `direnv` users. ([\#12335](https://github.com/matrix-org/synapse/issues/12335))
- Remove the (broadly unused, dev-only) dockerfile for pg tests. ([\#12336](https://github.com/matrix-org/synapse/issues/12336))
- Remove redundant `get_success` calls in test code. ([\#12346](https://github.com/matrix-org/synapse/issues/12346))
- Add type annotations for `tests/unittest.py`. ([\#12347](https://github.com/matrix-org/synapse/issues/12347))
- Move single-use methods out of `TestCase`. ([\#12348](https://github.com/matrix-org/synapse/issues/12348))
- Remove broken and unused development scripts. ([\#12349](https://github.com/matrix-org/synapse/issues/12349), [\#12351](https://github.com/matrix-org/synapse/issues/12351), [\#12355](https://github.com/matrix-org/synapse/issues/12355))
- Convert `Linearizer` tests from `inlineCallbacks` to async. ([\#12353](https://github.com/matrix-org/synapse/issues/12353))
- Update docstrings for `ReadWriteLock` tests. ([\#12354](https://github.com/matrix-org/synapse/issues/12354))
- Refactor `Linearizer`, convert methods to async and use an async context manager. ([\#12357](https://github.com/matrix-org/synapse/issues/12357))
- Fix a long-standing bug where `Linearizer`s could get stuck if a cancellation were to happen at the wrong time. ([\#12358](https://github.com/matrix-org/synapse/issues/12358))
- Make `StreamToken.from_string` and `RoomStreamToken.parse` propagate cancellations instead of replacing them with `SynapseError`s. ([\#12366](https://github.com/matrix-org/synapse/issues/12366))
- Add type hints to tests files. ([\#12371](https://github.com/matrix-org/synapse/issues/12371))
- Allow specifying the Postgres database's port when running unit tests with Postgres. ([\#12376](https://github.com/matrix-org/synapse/issues/12376))
- Remove temporary pin of signedjson<=1.1.1 that was added in Synapse 1.56.0. ([\#12379](https://github.com/matrix-org/synapse/issues/12379))
- Add opentracing spans to calls to external cache. ([\#12380](https://github.com/matrix-org/synapse/issues/12380))
- Lay groundwork for using `poetry` to manage Synapse's dependencies. ([\#12381](https://github.com/matrix-org/synapse/issues/12381), [\#12407](https://github.com/matrix-org/synapse/issues/12407), [\#12412](https://github.com/matrix-org/synapse/issues/12412), [\#12418](https://github.com/matrix-org/synapse/issues/12418))
- Make missing `importlib_metadata` dependency explicit. ([\#12384](https://github.com/matrix-org/synapse/issues/12384), [\#12400](https://github.com/matrix-org/synapse/issues/12400))
- Update type annotations for compatibility with prometheus_client 0.14. ([\#12389](https://github.com/matrix-org/synapse/issues/12389))
- Remove support for the unstable identifiers specified in [MSC3288](https://github.com/matrix-org/matrix-doc/pull/3288). ([\#12398](https://github.com/matrix-org/synapse/issues/12398))
- Add missing type hints to configuration classes. ([\#12402](https://github.com/matrix-org/synapse/issues/12402))
- Add files used to build the Docker image used for complement testing into the Synapse repository. ([\#12404](https://github.com/matrix-org/synapse/issues/12404))
- Do not include groups in the sync response when disabled. ([\#12408](https://github.com/matrix-org/synapse/issues/12408))
- Improve type hints related to HTTP query parameters. ([\#12415](https://github.com/matrix-org/synapse/issues/12415))
- Stop maintaining a list of lint targets. ([\#12420](https://github.com/matrix-org/synapse/issues/12420))
- Make `synapse._scripts` pass type checks. ([\#12421](https://github.com/matrix-org/synapse/issues/12421), [\#12422](https://github.com/matrix-org/synapse/issues/12422))
- Add some type hints to datastore. ([\#12423](https://github.com/matrix-org/synapse/issues/12423))
- Enable certificate checking during complement tests. ([\#12435](https://github.com/matrix-org/synapse/issues/12435))
- Explicitly specify the `tls` extra for Twisted dependency. ([\#12444](https://github.com/matrix-org/synapse/issues/12444))


Synapse 1.56.0 (2022-04-05)
===========================

Synapse will now refuse to start up if open registration is enabled, in order to help mitigate
abuse across the federation. If you would like
to provide registration to anyone, consider adding [email](https://github.com/matrix-org/synapse/blob/8a519f8abc6de772167c2cca101d22ee2052fafc/docs/sample_config.yaml#L1285),
[recaptcha](https://matrix-org.github.io/synapse/v1.56/CAPTCHA_SETUP.html)
or [token-based](https://matrix-org.github.io/synapse/v1.56/usage/administration/admin_api/registration_tokens.html) verification
in order to prevent automated registration from bad actors.
This check can be disabled by setting the `enable_registration_without_verification` option in your
homeserver configuration file to `true`. More details are available in the
[upgrade notes](https://matrix-org.github.io/synapse/v1.56/upgrade.html#open-registration-without-verification-is-now-disabled-by-default).

Synapse will additionally now refuse to start when using PostgreSQL with a non-`C` values for `COLLATE` and `CTYPE`, unless
the config flag `allow_unsafe_locale`, found in the database section of the configuration file, is set to `true`. See the
[upgrade notes](https://matrix-org.github.io/synapse/v1.56/upgrade#change-in-behaviour-for-postgresql-databases-with-unsafe-locale)
for details.

Internal Changes
----------------

- Bump the version of `black` for compatibility with the latest `click` release. ([\#12320](https://github.com/matrix-org/synapse/issues/12320))


Synapse 1.56.0rc1 (2022-03-29)
==============================

Features
--------

- Allow modules to store already existing 3PID associations. ([\#12195](https://github.com/matrix-org/synapse/issues/12195))
- Allow registering server administrators using the module API. Contributed by Famedly. ([\#12250](https://github.com/matrix-org/synapse/issues/12250))


Bugfixes
--------

- Fix a long-standing bug which caused the `/_matrix/federation/v1/state` and `/_matrix/federation/v1/state_ids` endpoints to return incorrect or invalid data when called for an event which we have stored as an "outlier". ([\#12087](https://github.com/matrix-org/synapse/issues/12087))
- Fix a long-standing bug where events from ignored users would still be considered for relations. ([\#12227](https://github.com/matrix-org/synapse/issues/12227), [\#12232](https://github.com/matrix-org/synapse/issues/12232), [\#12285](https://github.com/matrix-org/synapse/issues/12285))
- Fix a bug introduced in Synapse 1.53.0 where an unnecessary query could be performed when fetching bundled aggregations for threads. ([\#12228](https://github.com/matrix-org/synapse/issues/12228))
- Fix a bug introduced in Synapse 1.52.0 where admins could not deactivate and GDPR-erase a user if Synapse was configured with limits on avatars. ([\#12261](https://github.com/matrix-org/synapse/issues/12261))


Improved Documentation
----------------------

- Fix the link to the module documentation in the legacy spam checker warning message. ([\#12231](https://github.com/matrix-org/synapse/issues/12231))
- Remove incorrect prefixes in the worker documentation for some endpoints. ([\#12243](https://github.com/matrix-org/synapse/issues/12243))
- Correct `check_username_for_spam` annotations and docs. ([\#12246](https://github.com/matrix-org/synapse/issues/12246))
- Correct Authentik OpenID typo, and add notes on troubleshooting. Contributed by @IronTooch. ([\#12275](https://github.com/matrix-org/synapse/issues/12275))
- HAProxy reverse proxy guide update to stop sending IPv4-mapped address to homeserver. Contributed by @villepeh. ([\#12279](https://github.com/matrix-org/synapse/issues/12279))


Internal Changes
----------------

- Rename `shared_rooms` to `mutual_rooms` ([MSC2666](https://github.com/matrix-org/matrix-doc/pull/2666)), as per proposal changes. ([\#12036](https://github.com/matrix-org/synapse/issues/12036))
- Remove check on `update_user_directory` for shared rooms handler ([MSC2666](https://github.com/matrix-org/matrix-doc/pull/2666)), and update/expand documentation. ([\#12038](https://github.com/matrix-org/synapse/issues/12038))
- Refactor `create_new_client_event` to use a new parameter, `state_event_ids`, which accurately describes the usage with [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) instead of abusing `auth_event_ids`. ([\#12083](https://github.com/matrix-org/synapse/issues/12083), [\#12304](https://github.com/matrix-org/synapse/issues/12304))
- Refuse to start if registration is enabled without email, captcha, or token-based verification unless the new config flag `enable_registration_without_verification` is set to `true`. ([\#12091](https://github.com/matrix-org/synapse/issues/12091), [\#12322](https://github.com/matrix-org/synapse/issues/12322))
- Add tests for database transaction callbacks. ([\#12198](https://github.com/matrix-org/synapse/issues/12198))
- Handle cancellation in `DatabasePool.runInteraction`. ([\#12199](https://github.com/matrix-org/synapse/issues/12199))
- Add missing type hints for cache storage. ([\#12216](https://github.com/matrix-org/synapse/issues/12216))
- Add missing type hints for storage. ([\#12248](https://github.com/matrix-org/synapse/issues/12248), [\#12255](https://github.com/matrix-org/synapse/issues/12255))
- Add type hints to tests files. ([\#12224](https://github.com/matrix-org/synapse/issues/12224), [\#12240](https://github.com/matrix-org/synapse/issues/12240), [\#12256](https://github.com/matrix-org/synapse/issues/12256))
- Use type stubs for `psycopg2`. ([\#12269](https://github.com/matrix-org/synapse/issues/12269))
- Improve type annotations for `execute_values`. ([\#12311](https://github.com/matrix-org/synapse/issues/12311))
- Clean-up logic around rebasing URLs for URL image previews. ([\#12219](https://github.com/matrix-org/synapse/issues/12219))
- Use the `ignored_users` table in additional places instead of re-parsing the account data. ([\#12225](https://github.com/matrix-org/synapse/issues/12225))
- Refactor the relations endpoints to add a `RelationsHandler`. ([\#12237](https://github.com/matrix-org/synapse/issues/12237))
- Generate announcement links in the release script. ([\#12242](https://github.com/matrix-org/synapse/issues/12242))
- Improve error message when dependencies check finds a broken installation. ([\#12244](https://github.com/matrix-org/synapse/issues/12244))
- Compress metrics HTTP resource when enabled. Contributed by Nick @ Beeper. ([\#12258](https://github.com/matrix-org/synapse/issues/12258))
- Refuse to start if the PostgreSQL database has a non-`C` locale, unless the config flag `allow_unsafe_db_locale` is set to true. ([\#12262](https://github.com/matrix-org/synapse/issues/12262), [\#12288](https://github.com/matrix-org/synapse/issues/12288))
- Optionally include account validity expiration information to experimental [MSC3720](https://github.com/matrix-org/matrix-doc/pull/3720) account status responses. ([\#12266](https://github.com/matrix-org/synapse/issues/12266))
- Add a new cache `_get_membership_from_event_id` to speed up push rule calculations in large rooms. ([\#12272](https://github.com/matrix-org/synapse/issues/12272))
- Re-enable Complement concurrency in CI. ([\#12283](https://github.com/matrix-org/synapse/issues/12283))
- Remove unused test utilities. ([\#12291](https://github.com/matrix-org/synapse/issues/12291))
- Enhance logging for inbound federation events. ([\#12301](https://github.com/matrix-org/synapse/issues/12301))
- Fix compatibility with the recently-released Jinja 3.1. ([\#12313](https://github.com/matrix-org/synapse/issues/12313))
- Avoid trying to calculate the state at outlier events. ([\#12314](https://github.com/matrix-org/synapse/issues/12314))


Synapse 1.55.2 (2022-03-24)
===========================

This patch version reverts the earlier fixes from Synapse 1.55.1, which could cause problems in certain deployments, and instead adds a cap to the version of Jinja to be installed. Again, this is to fix an incompatibility with version 3.1.0 of the [Jinja](https://pypi.org/project/Jinja2/) library, and again, deployments of Synapse using the `matrixdotorg/synapse` Docker image or Debian packages from packages.matrix.org are not affected.

Internal Changes
----------------

- Pin Jinja to <3.1.0, as Synapse fails to start with Jinja 3.1.0. ([\#12297](https://github.com/matrix-org/synapse/issues/12297))
- Revert changes from 1.55.1 as they caused problems with older versions of Jinja ([\#12296](https://github.com/matrix-org/synapse/issues/12296))


Synapse 1.55.1 (2022-03-24)
===========================

This is a patch release that fixes an incompatibility with version 3.1.0 of the [Jinja](https://pypi.org/project/Jinja2/) library, released on March 24th, 2022. Deployments of Synapse using the `matrixdotorg/synapse` Docker image or Debian packages from packages.matrix.org are not affected.

Internal Changes
----------------

- Remove uses of the long-deprecated `jinja2.Markup` which would prevent Synapse from starting with Jinja 3.1.0 or above installed. ([\#12289](https://github.com/matrix-org/synapse/issues/12289))


Synapse 1.55.0 (2022-03-22)
===========================

This release removes a workaround introduced in Synapse 1.50.0 for Mjolnir compatibility. **This breaks compatibility with Mjolnir 1.3.1 and earlier. ([\#11700](https://github.com/matrix-org/synapse/issues/11700))**; Mjolnir users should upgrade Mjolnir before upgrading Synapse to this version.

This release also moves the location of the `synctl` script; see the [upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#synctl-script-has-been-moved) for more details.


Internal Changes
----------------

- Tweak copy for default Single Sign-On account details template to better adhere to mobile app store guidelines. ([\#12265](https://github.com/matrix-org/synapse/issues/12265), [\#12260](https://github.com/matrix-org/synapse/issues/12260))


Synapse 1.55.0rc1 (2022-03-15)
==============================

Features
--------

- Add third-party rules callbacks `check_can_shutdown_room` and `check_can_deactivate_user`. ([\#12028](https://github.com/matrix-org/synapse/issues/12028))
- Improve performance of logging in for large accounts. ([\#12132](https://github.com/matrix-org/synapse/issues/12132))
- Add experimental env var `SYNAPSE_ASYNC_IO_REACTOR` that causes Synapse to use the asyncio reactor for Twisted. ([\#12135](https://github.com/matrix-org/synapse/issues/12135))
- Support the stable identifiers from [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440): threads. ([\#12151](https://github.com/matrix-org/synapse/issues/12151))
- Add a new Jinja2 template filter to extract the local part of an email address. ([\#12212](https://github.com/matrix-org/synapse/issues/12212))


Bugfixes
--------

- Use the proper serialization format for bundled thread aggregations. The bug has existed since Synapse 1.48.0. ([\#12090](https://github.com/matrix-org/synapse/issues/12090))
- Fix a long-standing bug when redacting events with relations. ([\#12113](https://github.com/matrix-org/synapse/issues/12113), [\#12121](https://github.com/matrix-org/synapse/issues/12121), [\#12130](https://github.com/matrix-org/synapse/issues/12130), [\#12189](https://github.com/matrix-org/synapse/issues/12189))
- Fix a bug introduced in Synapse 1.7.2 whereby background updates are never run with the default background batch size. ([\#12157](https://github.com/matrix-org/synapse/issues/12157))
- Fix a bug where non-standard information was returned from the `/hierarchy` API. Introduced in Synapse 1.41.0. ([\#12175](https://github.com/matrix-org/synapse/issues/12175))
- Fix a bug introduced in Synapse 1.54.0 that broke background updates on sqlite homeservers while search was disabled. ([\#12215](https://github.com/matrix-org/synapse/issues/12215))
- Fix a long-standing bug when a `filter` argument with `event_fields` which did not include the `unsigned` field could result in a 500 error on `/sync`. ([\#12234](https://github.com/matrix-org/synapse/issues/12234))


Improved Documentation
----------------------

- Fix complexity checking config example in [Resource Constrained Devices](https://matrix-org.github.io/synapse/v1.54/other/running_synapse_on_single_board_computers.html) docs page. ([\#11998](https://github.com/matrix-org/synapse/issues/11998))
- Improve documentation for demo scripts. ([\#12143](https://github.com/matrix-org/synapse/issues/12143))
- Updates to the Room DAG concepts development document. ([\#12179](https://github.com/matrix-org/synapse/issues/12179))
- Document that the `typing`, `to_device`, `account_data`, `receipts`, and `presence` stream writer can only be used on a single worker. ([\#12196](https://github.com/matrix-org/synapse/issues/12196))
- Document that contributors can sign off privately by email. ([\#12204](https://github.com/matrix-org/synapse/issues/12204))


Deprecations and Removals
-------------------------

- **Remove workaround introduced in Synapse 1.50.0 for Mjolnir compatibility. Breaks compatibility with Mjolnir 1.3.1 and earlier. ([\#11700](https://github.com/matrix-org/synapse/issues/11700))**
- **`synctl` has been moved into into `synapse._scripts` and is exposed as an entry point; see [upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#synctl-script-has-been-moved). ([\#12140](https://github.com/matrix-org/synapse/issues/12140))
- Remove backwards compatibility with pagination tokens from the `/relations` and `/aggregations` endpoints generated from Synapse < v1.52.0. ([\#12138](https://github.com/matrix-org/synapse/issues/12138))
- The groups/communities feature in Synapse has been deprecated. ([\#12200](https://github.com/matrix-org/synapse/issues/12200))


Internal Changes
----------------

- Simplify the `ApplicationService` class' set of public methods related to interest checking. ([\#11915](https://github.com/matrix-org/synapse/issues/11915))
- Add config settings for background update parameters. ([\#11980](https://github.com/matrix-org/synapse/issues/11980))
- Correct type hints for txredis. ([\#12042](https://github.com/matrix-org/synapse/issues/12042))
- Limit the size of `aggregation_key` on annotations. ([\#12101](https://github.com/matrix-org/synapse/issues/12101))
- Add type hints to tests files. ([\#12108](https://github.com/matrix-org/synapse/issues/12108), [\#12146](https://github.com/matrix-org/synapse/issues/12146), [\#12207](https://github.com/matrix-org/synapse/issues/12207), [\#12208](https://github.com/matrix-org/synapse/issues/12208))
- Move scripts to Synapse package and expose as setuptools entry points. ([\#12118](https://github.com/matrix-org/synapse/issues/12118))
- Add support for cancellation to `ReadWriteLock`. ([\#12120](https://github.com/matrix-org/synapse/issues/12120))
- Fix data validation to compare to lists, not sequences. ([\#12128](https://github.com/matrix-org/synapse/issues/12128))
- Fix CI not attaching source distributions and wheels to the GitHub releases. ([\#12131](https://github.com/matrix-org/synapse/issues/12131))
- Remove unused mocks from `test_typing`. ([\#12136](https://github.com/matrix-org/synapse/issues/12136))
- Give `scripts-dev` scripts suffixes for neater CI config. ([\#12137](https://github.com/matrix-org/synapse/issues/12137))
- Move the snapcraft configuration file to `contrib`. ([\#12142](https://github.com/matrix-org/synapse/issues/12142))
- Enable [MSC3030](https://github.com/matrix-org/matrix-doc/pull/3030) Complement tests in CI. ([\#12144](https://github.com/matrix-org/synapse/issues/12144))
- Enable [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) Complement tests in CI. ([\#12145](https://github.com/matrix-org/synapse/issues/12145))
- Add test for `ObservableDeferred`'s cancellation behaviour. ([\#12149](https://github.com/matrix-org/synapse/issues/12149))
- Use `ParamSpec` in type hints for `synapse.logging.context`. ([\#12150](https://github.com/matrix-org/synapse/issues/12150))
- Prune unused jobs from `tox` config. ([\#12152](https://github.com/matrix-org/synapse/issues/12152))
- Move CI checks out of tox, to facilitate a move to using poetry. ([\#12153](https://github.com/matrix-org/synapse/issues/12153))
- Avoid generating state groups for local out-of-band leaves. ([\#12154](https://github.com/matrix-org/synapse/issues/12154))
- Avoid trying to calculate the state at outlier events. ([\#12155](https://github.com/matrix-org/synapse/issues/12155), [\#12173](https://github.com/matrix-org/synapse/issues/12173), [\#12202](https://github.com/matrix-org/synapse/issues/12202))
- Fix some type annotations. ([\#12156](https://github.com/matrix-org/synapse/issues/12156))
- Add type hints for `ObservableDeferred` attributes. ([\#12159](https://github.com/matrix-org/synapse/issues/12159))
- Use a prebuilt Action for the `tests-done` CI job. ([\#12161](https://github.com/matrix-org/synapse/issues/12161))
- Reduce number of DB queries made during processing of `/sync`. ([\#12163](https://github.com/matrix-org/synapse/issues/12163))
- Add `delay_cancellation` utility function, which behaves like `stop_cancellation` but waits until the original `Deferred` resolves before raising a `CancelledError`. ([\#12180](https://github.com/matrix-org/synapse/issues/12180))
- Retry HTTP replication failures, this should prevent 502's when restarting stateful workers (main, event persisters, stream writers). Contributed by Nick @ Beeper. ([\#12182](https://github.com/matrix-org/synapse/issues/12182))
- Add cancellation support to `@cached` and `@cachedList` decorators. ([\#12183](https://github.com/matrix-org/synapse/issues/12183))
- Remove unused variables. ([\#12187](https://github.com/matrix-org/synapse/issues/12187))
- Add combined test for HTTP pusher and push rule. Contributed by Nick @ Beeper. ([\#12188](https://github.com/matrix-org/synapse/issues/12188))
- Rename `HomeServer.get_tcp_replication` to `get_replication_command_handler`. ([\#12192](https://github.com/matrix-org/synapse/issues/12192))
- Remove some dead code. ([\#12197](https://github.com/matrix-org/synapse/issues/12197))
- Fix a misleading comment in the function `check_event_for_spam`. ([\#12203](https://github.com/matrix-org/synapse/issues/12203))
- Remove unnecessary `pass` statements. ([\#12206](https://github.com/matrix-org/synapse/issues/12206))
- Update the SSO username picker template to comply with SIWA guidelines. ([\#12210](https://github.com/matrix-org/synapse/issues/12210))
- Improve code documentation for the typing stream over replication. ([\#12211](https://github.com/matrix-org/synapse/issues/12211))


Synapse 1.54.0 (2022-03-08)
===========================

Please note that this will be the last release of Synapse that is compatible with Mjolnir 1.3.1 and earlier.
Administrators of servers which have the Mjolnir module installed are advised to upgrade Mjolnir to version 1.3.2 or later.


Bugfixes
--------

- Fix a bug introduced in Synapse 1.54.0rc1 preventing the new module callbacks introduced in this release from being registered by modules. ([\#12141](https://github.com/matrix-org/synapse/issues/12141))
- Fix a bug introduced in Synapse 1.54.0rc1 where runtime dependency version checks would mistakenly check development dependencies if they were present and would not accept pre-release versions of dependencies. ([\#12129](https://github.com/matrix-org/synapse/issues/12129), [\#12177](https://github.com/matrix-org/synapse/issues/12177))


Internal Changes
----------------

- Update release script to insert the previous version when writing "No significant changes" line in the changelog. ([\#12127](https://github.com/matrix-org/synapse/issues/12127))
- Relax the version guard for "packaging" added in [\#12088](https://github.com/matrix-org/synapse/issues/12088). ([\#12166](https://github.com/matrix-org/synapse/issues/12166))


Synapse 1.54.0rc1 (2022-03-02)
==============================


Features
--------

- Add support for [MSC3202](https://github.com/matrix-org/matrix-doc/pull/3202): sending one-time key counts and fallback key usage states to Application Services. ([\#11617](https://github.com/matrix-org/synapse/issues/11617))
- Improve the generated URL previews for some web pages. Contributed by @AndrewRyanChama. ([\#11985](https://github.com/matrix-org/synapse/issues/11985))
- Track cache invalidations in Prometheus metrics, as already happens for cache eviction based on size or time. ([\#12000](https://github.com/matrix-org/synapse/issues/12000))
- Implement experimental support for [MSC3720](https://github.com/matrix-org/matrix-doc/pull/3720) (account status endpoints). ([\#12001](https://github.com/matrix-org/synapse/issues/12001), [\#12067](https://github.com/matrix-org/synapse/issues/12067))
- Enable modules to set a custom display name when registering a user. ([\#12009](https://github.com/matrix-org/synapse/issues/12009))
- Advertise Matrix 1.1 and 1.2 support on `/_matrix/client/versions`. ([\#12020](https://github.com/matrix-org/synapse/issues/12020), ([\#12022](https://github.com/matrix-org/synapse/issues/12022))
- Support only the stable identifier for [MSC3069](https://github.com/matrix-org/matrix-doc/pull/3069)'s `is_guest` on `/_matrix/client/v3/account/whoami`. ([\#12021](https://github.com/matrix-org/synapse/issues/12021))
- Use room version 9 as the default room version (per [MSC3589](https://github.com/matrix-org/matrix-doc/pull/3589)). ([\#12058](https://github.com/matrix-org/synapse/issues/12058))
- Add module callbacks to react to user deactivation status changes (i.e. deactivations and reactivations) and profile updates. ([\#12062](https://github.com/matrix-org/synapse/issues/12062))


Bugfixes
--------

- Fix a bug introduced in Synapse 1.48.0 where an edit of the latest event in a thread would not be properly applied to the thread summary. ([\#11992](https://github.com/matrix-org/synapse/issues/11992))
- Fix long-standing bug where the `get_rooms_for_user` cache was not correctly invalidated for remote users when the server left a room. ([\#11999](https://github.com/matrix-org/synapse/issues/11999))
- Fix a 500 error with Postgres when looking backwards with the [MSC3030](https://github.com/matrix-org/matrix-doc/pull/3030) `/timestamp_to_event?dir=b` endpoint. ([\#12024](https://github.com/matrix-org/synapse/issues/12024))
- Properly fix a long-standing bug where wrong data could be inserted into the `event_search` table when using SQLite. This could block running `synapse_port_db` with an `argument of type 'int' is not iterable` error. This bug was partially fixed by a change in Synapse 1.44.0. ([\#12037](https://github.com/matrix-org/synapse/issues/12037))
- Fix slow performance of `/logout` in some cases where refresh tokens are in use. The slowness existed since the initial implementation of refresh tokens in version 1.38.0. ([\#12056](https://github.com/matrix-org/synapse/issues/12056))
- Fix a long-standing bug where Synapse would make additional failing requests over federation for missing data. ([\#12077](https://github.com/matrix-org/synapse/issues/12077))
- Fix occasional `Unhandled error in Deferred` error message. ([\#12089](https://github.com/matrix-org/synapse/issues/12089))
- Fix a bug introduced in Synapse 1.51.0 where incoming federation transactions containing at least one EDU would be dropped if debug logging was enabled for `synapse.8631_debug`. ([\#12098](https://github.com/matrix-org/synapse/issues/12098))
- Fix a long-standing bug which could cause push notifications to malfunction if `use_frozen_dicts` was set in the configuration. ([\#12100](https://github.com/matrix-org/synapse/issues/12100))
- Fix an extremely rare, long-standing bug in `ReadWriteLock` that would cause an error when a newly unblocked writer completes instantly. ([\#12105](https://github.com/matrix-org/synapse/issues/12105))
- Make a `POST` to `/rooms/<room_id>/receipt/m.read/<event_id>` only trigger a push notification if the count of unread messages is different to the one in the last successfully sent push. This reduces server load and load on the receiving device. ([\#11835](https://github.com/matrix-org/synapse/issues/11835))


Updates to the Docker image
---------------------------

- The Docker image no longer automatically creates a temporary volume at `/data`. This is not expected to affect normal usage. ([\#11997](https://github.com/matrix-org/synapse/issues/11997))
- Use Python 3.9 in Docker images by default. ([\#12112](https://github.com/matrix-org/synapse/issues/12112))


Improved Documentation
----------------------

- Document support for the `to_device`, `account_data`, `receipts`, and `presence` stream writers for workers. ([\#11599](https://github.com/matrix-org/synapse/issues/11599))
- Explain the meaning of spam checker callbacks' return values. ([\#12003](https://github.com/matrix-org/synapse/issues/12003))
- Clarify information about external Identity Provider IDs. ([\#12004](https://github.com/matrix-org/synapse/issues/12004))


Deprecations and Removals
-------------------------

- Deprecate using `synctl` with the config option `synctl_cache_factor` and print a warning if a user still uses this option. ([\#11865](https://github.com/matrix-org/synapse/issues/11865))
- Remove support for the legacy structured logging configuration (please see the the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#legacy-structured-logging-configuration-removal) if you are using `structured: true` in the Synapse configuration). ([\#12008](https://github.com/matrix-org/synapse/issues/12008))
- Drop support for [MSC3283](https://github.com/matrix-org/matrix-doc/pull/3283) unstable flags now that the stable flags are supported. ([\#12018](https://github.com/matrix-org/synapse/issues/12018))
- Remove the unstable `/spaces` endpoint from [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#12073](https://github.com/matrix-org/synapse/issues/12073))


Internal Changes
----------------

- Make the `get_room_version` method use `get_room_version_id` to benefit from caching. ([\#11808](https://github.com/matrix-org/synapse/issues/11808))
- Remove unnecessary condition on knock -> leave auth rule check. ([\#11900](https://github.com/matrix-org/synapse/issues/11900))
- Add tests for device list changes between local users. ([\#11972](https://github.com/matrix-org/synapse/issues/11972))
- Optimise calculating `device_list` changes in `/sync`. ([\#11974](https://github.com/matrix-org/synapse/issues/11974))
- Add missing type hints to storage classes. ([\#11984](https://github.com/matrix-org/synapse/issues/11984))
- Refactor the search code for improved readability. ([\#11991](https://github.com/matrix-org/synapse/issues/11991))
- Move common deduplication code down into `_auth_and_persist_outliers`. ([\#11994](https://github.com/matrix-org/synapse/issues/11994))
- Limit concurrent joins from applications services. ([\#11996](https://github.com/matrix-org/synapse/issues/11996))
- Preparation for faster-room-join work: when parsing the `send_join` response, get the `m.room.create` event from `state`, not `auth_chain`. ([\#12005](https://github.com/matrix-org/synapse/issues/12005), [\#12039](https://github.com/matrix-org/synapse/issues/12039))
- Preparation for faster-room-join work: parse MSC3706 fields in send_join response. ([\#12011](https://github.com/matrix-org/synapse/issues/12011))
- Preparation for faster-room-join work: persist information on which events and rooms have partial state to the database. ([\#12012](https://github.com/matrix-org/synapse/issues/12012))
- Preparation for faster-room-join work: Support for calling `/federation/v1/state` on a remote server. ([\#12013](https://github.com/matrix-org/synapse/issues/12013))
- Configure `tox` to use `venv` rather than `virtualenv`. ([\#12015](https://github.com/matrix-org/synapse/issues/12015))
- Fix bug in `StateFilter.return_expanded()` and add some tests. ([\#12016](https://github.com/matrix-org/synapse/issues/12016))
- Use Matrix v1.1 endpoints (`/_matrix/client/v3/auth/...`) in fallback auth HTML forms. ([\#12019](https://github.com/matrix-org/synapse/issues/12019))
- Update the `olddeps` CI job to use an old version of `markupsafe`. ([\#12025](https://github.com/matrix-org/synapse/issues/12025))
- Upgrade Mypy to version 0.931. ([\#12030](https://github.com/matrix-org/synapse/issues/12030))
- Remove legacy `HomeServer.get_datastore()`. ([\#12031](https://github.com/matrix-org/synapse/issues/12031), [\#12070](https://github.com/matrix-org/synapse/issues/12070))
- Minor typing fixes. ([\#12034](https://github.com/matrix-org/synapse/issues/12034), [\#12069](https://github.com/matrix-org/synapse/issues/12069))
- After joining a room, create a dedicated logcontext to process the queued events. ([\#12041](https://github.com/matrix-org/synapse/issues/12041))
- Tidy up GitHub Actions config which builds distributions for PyPI. ([\#12051](https://github.com/matrix-org/synapse/issues/12051))
- Move configuration out of `setup.cfg`. ([\#12052](https://github.com/matrix-org/synapse/issues/12052), [\#12059](https://github.com/matrix-org/synapse/issues/12059))
- Fix error message when a worker process fails to talk to another worker process. ([\#12060](https://github.com/matrix-org/synapse/issues/12060))
- Fix using the `complement.sh` script without specifying a directory or a branch. Contributed by Nico on behalf of Famedly. ([\#12063](https://github.com/matrix-org/synapse/issues/12063))
- Add type hints to `tests/rest/client`. ([\#12066](https://github.com/matrix-org/synapse/issues/12066), [\#12072](https://github.com/matrix-org/synapse/issues/12072), [\#12084](https://github.com/matrix-org/synapse/issues/12084), [\#12094](https://github.com/matrix-org/synapse/issues/12094))
- Add some logging to `/sync` to try and track down #11916. ([\#12068](https://github.com/matrix-org/synapse/issues/12068))
- Inspect application dependencies using `importlib.metadata` or its backport. ([\#12088](https://github.com/matrix-org/synapse/issues/12088))
- Use `assertEqual` instead of the deprecated `assertEquals` in test code. ([\#12092](https://github.com/matrix-org/synapse/issues/12092))
- Move experimental support for [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440) to `/versions`. ([\#12099](https://github.com/matrix-org/synapse/issues/12099))
- Add `stop_cancellation` utility function to stop `Deferred`s from being cancelled. ([\#12106](https://github.com/matrix-org/synapse/issues/12106))
- Improve exception handling for concurrent execution. ([\#12109](https://github.com/matrix-org/synapse/issues/12109))
- Advertise support for Python 3.10 in packaging files. ([\#12111](https://github.com/matrix-org/synapse/issues/12111))
- Move CI checks out of tox, to facilitate a move to using poetry. ([\#12119](https://github.com/matrix-org/synapse/issues/12119))


Synapse 1.53.0 (2022-02-22)
===========================

No significant changes since 1.53.0rc1.


Synapse 1.53.0rc1 (2022-02-15)
==============================

Features
--------

- Add experimental support for sending to-device messages to application services, as specified by [MSC2409](https://github.com/matrix-org/matrix-doc/pull/2409). ([\#11215](https://github.com/matrix-org/synapse/issues/11215), [\#11966](https://github.com/matrix-org/synapse/issues/11966))
- Add a background database update to purge account data for deactivated users. ([\#11655](https://github.com/matrix-org/synapse/issues/11655))
- Experimental support for [MSC3666](https://github.com/matrix-org/matrix-doc/pull/3666): including bundled aggregations in server side search results. ([\#11837](https://github.com/matrix-org/synapse/issues/11837))
- Enable cache time-based expiry by default. The `expiry_time` config flag has been superseded by `expire_caches` and `cache_entry_ttl`. ([\#11849](https://github.com/matrix-org/synapse/issues/11849))
- Add a callback to allow modules to allow or forbid a 3PID (email address, phone number) from being associated to a local account. ([\#11854](https://github.com/matrix-org/synapse/issues/11854))
- Stabilize support and remove unstable endpoints for [MSC3231](https://github.com/matrix-org/matrix-doc/pull/3231). Clients must switch to the stable identifier and endpoint. See the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#stablisation-of-msc3231) for more information. ([\#11867](https://github.com/matrix-org/synapse/issues/11867))
- Allow modules to retrieve the current instance's server name and worker name. ([\#11868](https://github.com/matrix-org/synapse/issues/11868))
- Use a dedicated configurable rate limiter for 3PID invites. ([\#11892](https://github.com/matrix-org/synapse/issues/11892))
- Support the stable API endpoint for [MSC3283](https://github.com/matrix-org/matrix-doc/pull/3283): new settings in `/capabilities` endpoint. ([\#11933](https://github.com/matrix-org/synapse/issues/11933), [\#11989](https://github.com/matrix-org/synapse/issues/11989))
- Support the `dir` parameter on the `/relations` endpoint, per [MSC3715](https://github.com/matrix-org/matrix-doc/pull/3715). ([\#11941](https://github.com/matrix-org/synapse/issues/11941))
- Experimental implementation of [MSC3706](https://github.com/matrix-org/matrix-doc/pull/3706): extensions to `/send_join` to support reduced response size. ([\#11967](https://github.com/matrix-org/synapse/issues/11967))


Bugfixes
--------

- Fix [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) historical messages backfilling in random order on remote homeservers. ([\#11114](https://github.com/matrix-org/synapse/issues/11114))
- Fix a bug introduced in Synapse 1.51.0 where incoming federation transactions containing at least one EDU would be dropped if debug logging was enabled for `synapse.8631_debug`. ([\#11890](https://github.com/matrix-org/synapse/issues/11890))
- Fix a long-standing bug where some unknown endpoints would return HTML error pages instead of JSON `M_UNRECOGNIZED` errors. ([\#11930](https://github.com/matrix-org/synapse/issues/11930))
- Implement an allow list of content types for which we will attempt to preview a URL. This prevents Synapse from making useless longer-lived connections to streaming media servers. ([\#11936](https://github.com/matrix-org/synapse/issues/11936))
- Fix a long-standing bug where pagination tokens from `/sync` and `/messages` could not be provided to the `/relations` API. ([\#11952](https://github.com/matrix-org/synapse/issues/11952))
- Require that modules register their callbacks using keyword arguments. ([\#11975](https://github.com/matrix-org/synapse/issues/11975))
- Fix a long-standing bug where `M_WRONG_ROOM_KEYS_VERSION` errors would not include the specced `current_version` field. ([\#11988](https://github.com/matrix-org/synapse/issues/11988))


Improved Documentation
----------------------

- Fix typo in User Admin API: unpind -> unbind. ([\#11859](https://github.com/matrix-org/synapse/issues/11859))
- Document images returned by the User List Media Admin API can include those generated by URL previews. ([\#11862](https://github.com/matrix-org/synapse/issues/11862))
- Remove outdated MSC1711 FAQ document. ([\#11907](https://github.com/matrix-org/synapse/issues/11907))
- Correct the structured logging configuration example. Contributed by Brad Jones. ([\#11946](https://github.com/matrix-org/synapse/issues/11946))
- Add information on the Synapse release cycle. ([\#11954](https://github.com/matrix-org/synapse/issues/11954))
- Fix broken link in the README to the admin API for password reset. ([\#11955](https://github.com/matrix-org/synapse/issues/11955))


Deprecations and Removals
-------------------------

- Drop support for `webclient` listeners and configuring `web_client_location` to a non-HTTP(S) URL. Deprecated configurations are a configuration error. ([\#11895](https://github.com/matrix-org/synapse/issues/11895))
- Remove deprecated `user_may_create_room_with_invites` spam checker callback. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html#removal-of-user_may_create_room_with_invites) for more information. ([\#11950](https://github.com/matrix-org/synapse/issues/11950))
- No longer build `.deb` packages for Ubuntu 21.04 Hirsute Hippo, which has now EOLed. ([\#11961](https://github.com/matrix-org/synapse/issues/11961))


Internal Changes
----------------

- Enhance user registration test helpers to make them more useful for tests involving application services and devices. ([\#11615](https://github.com/matrix-org/synapse/issues/11615), [\#11616](https://github.com/matrix-org/synapse/issues/11616))
- Improve performance when fetching bundled aggregations for multiple events. ([\#11660](https://github.com/matrix-org/synapse/issues/11660), [\#11752](https://github.com/matrix-org/synapse/issues/11752))
- Fix type errors introduced by new annotations in the Prometheus Client library. ([\#11832](https://github.com/matrix-org/synapse/issues/11832))
- Add missing type hints to replication code. ([\#11856](https://github.com/matrix-org/synapse/issues/11856), [\#11938](https://github.com/matrix-org/synapse/issues/11938))
- Ensure that `opentracing` scopes are activated and closed at the right time. ([\#11869](https://github.com/matrix-org/synapse/issues/11869))
- Improve opentracing for incoming federation requests. ([\#11870](https://github.com/matrix-org/synapse/issues/11870))
- Improve internal docstrings in `synapse.util.caches`. ([\#11876](https://github.com/matrix-org/synapse/issues/11876))
- Do not needlessly clear the `get_users_in_room` and `get_users_in_room_with_profiles` caches when any room state changes. ([\#11878](https://github.com/matrix-org/synapse/issues/11878))
- Convert `ApplicationServiceTestCase` to use `simple_async_mock`. ([\#11880](https://github.com/matrix-org/synapse/issues/11880))
- Remove experimental changes to the default push rules which were introduced in Synapse 1.19.0 but never enabled. ([\#11884](https://github.com/matrix-org/synapse/issues/11884))
- Disable coverage calculation for olddeps build. ([\#11888](https://github.com/matrix-org/synapse/issues/11888))
- Preparation to support sending device list updates to application services. ([\#11905](https://github.com/matrix-org/synapse/issues/11905))
- Add a test that checks users receive their own device list updates down `/sync`. ([\#11909](https://github.com/matrix-org/synapse/issues/11909))
- Run Complement tests sequentially. ([\#11910](https://github.com/matrix-org/synapse/issues/11910))
- Various refactors to the application service notifier code. ([\#11911](https://github.com/matrix-org/synapse/issues/11911), [\#11912](https://github.com/matrix-org/synapse/issues/11912))
- Tests: replace mocked `Authenticator` with the real thing. ([\#11913](https://github.com/matrix-org/synapse/issues/11913))
- Various refactors to the typing notifications code. ([\#11914](https://github.com/matrix-org/synapse/issues/11914))
- Use the proper type for the `Content-Length` header in the `UploadResource`. ([\#11927](https://github.com/matrix-org/synapse/issues/11927))
- Remove an unnecessary ignoring of type hints due to fixes in upstream packages. ([\#11939](https://github.com/matrix-org/synapse/issues/11939))
- Add missing type hints. ([\#11953](https://github.com/matrix-org/synapse/issues/11953))
- Fix an import cycle in `synapse.event_auth`. ([\#11965](https://github.com/matrix-org/synapse/issues/11965))
- Unpin `frozendict` but exclude the known bad version 2.1.2. ([\#11969](https://github.com/matrix-org/synapse/issues/11969))
- Prepare for rename of default Complement branch. ([\#11971](https://github.com/matrix-org/synapse/issues/11971))
- Fetch Synapse's version using a helper from `matrix-common`. ([\#11979](https://github.com/matrix-org/synapse/issues/11979))


Synapse 1.52.0 (2022-02-08)
===========================

No significant changes since 1.52.0rc1.

Note that [Twisted 22.1.0](https://github.com/twisted/twisted/releases/tag/twisted-22.1.0)
has recently been released, which fixes a [security issue](https://github.com/twisted/twisted/security/advisories/GHSA-92x2-jw7w-xvvx)
within the Twisted library. We do not believe Synapse is affected by this vulnerability,
though we advise server administrators who installed Synapse via pip to upgrade Twisted
with `pip install --upgrade Twisted treq` as a matter of good practice. The Docker image
`matrixdotorg/synapse` and the Debian packages from `packages.matrix.org` are using the
updated library.


Synapse 1.52.0rc1 (2022-02-01)
==============================

Features
--------

- Remove account data (including client config, push rules and ignored users) upon user deactivation. ([\#11621](https://github.com/matrix-org/synapse/issues/11621), [\#11788](https://github.com/matrix-org/synapse/issues/11788), [\#11789](https://github.com/matrix-org/synapse/issues/11789))
- Add an admin API to reset connection timeouts for remote server. ([\#11639](https://github.com/matrix-org/synapse/issues/11639))
- Add an admin API to get a list of rooms that federate with a given remote homeserver. ([\#11658](https://github.com/matrix-org/synapse/issues/11658))
- Add a config flag to inhibit `M_USER_IN_USE` during registration. ([\#11743](https://github.com/matrix-org/synapse/issues/11743))
- Add a module callback to set username at registration. ([\#11790](https://github.com/matrix-org/synapse/issues/11790))
- Allow configuring a maximum file size as well as a list of allowed content types for avatars. ([\#11846](https://github.com/matrix-org/synapse/issues/11846))


Bugfixes
--------

- Include the bundled aggregations in the `/sync` response, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#11612](https://github.com/matrix-org/synapse/issues/11612))
- Fix a long-standing bug when previewing Reddit URLs which do not contain an image. ([\#11767](https://github.com/matrix-org/synapse/issues/11767))
- Fix a long-standing bug that media streams could cause long-lived connections when generating URL previews. ([\#11784](https://github.com/matrix-org/synapse/issues/11784))
- Include a `prev_content` field in state events sent to Application Services. Contributed by @totallynotvaishnav. ([\#11798](https://github.com/matrix-org/synapse/issues/11798))
- Fix a bug introduced in Synapse 0.33.3 causing requests to sometimes log strings such as `HTTPStatus.OK` instead of integer status codes. ([\#11827](https://github.com/matrix-org/synapse/issues/11827))


Improved Documentation
----------------------

- Update pypi installation docs to indicate that we now support Python 3.10. ([\#11820](https://github.com/matrix-org/synapse/issues/11820))
- Add missing steps to the contribution submission process in the documentation.  Contributed by @sequentialread. ([\#11821](https://github.com/matrix-org/synapse/issues/11821))
- Remove not needed old table of contents in documentation. ([\#11860](https://github.com/matrix-org/synapse/issues/11860))
- Consolidate the `access_token` information at the top of each relevant page in the Admin API documentation. ([\#11861](https://github.com/matrix-org/synapse/issues/11861))


Deprecations and Removals
-------------------------

- Drop support for Python 3.6, which is EOL. ([\#11683](https://github.com/matrix-org/synapse/issues/11683))
- Remove the `experimental_msc1849_support_enabled` flag as the features are now stable. ([\#11843](https://github.com/matrix-org/synapse/issues/11843))


Internal Changes
----------------

- Preparation for database schema simplifications: add `state_key` and `rejection_reason` columns to `events` table. ([\#11792](https://github.com/matrix-org/synapse/issues/11792))
- Add `FrozenEvent.get_state_key` and use it in a couple of places. ([\#11793](https://github.com/matrix-org/synapse/issues/11793))
- Preparation for database schema simplifications: stop reading from `event_reference_hashes`. ([\#11794](https://github.com/matrix-org/synapse/issues/11794))
- Drop unused table `public_room_list_stream`. ([\#11795](https://github.com/matrix-org/synapse/issues/11795))
- Preparation for reducing Postgres serialization errors: allow setting transaction isolation level. Contributed by Nick @ Beeper. ([\#11799](https://github.com/matrix-org/synapse/issues/11799), [\#11847](https://github.com/matrix-org/synapse/issues/11847))
- Docker: skip the initial amd64-only build and go straight to multiarch. ([\#11810](https://github.com/matrix-org/synapse/issues/11810))
- Run Complement on the Github Actions VM and not inside a Docker container. ([\#11811](https://github.com/matrix-org/synapse/issues/11811))
- Log module names at startup. ([\#11813](https://github.com/matrix-org/synapse/issues/11813))
- Improve type safety of bundled aggregations code. ([\#11815](https://github.com/matrix-org/synapse/issues/11815))
- Correct a type annotation in the event validation logic. ([\#11817](https://github.com/matrix-org/synapse/issues/11817), [\#11830](https://github.com/matrix-org/synapse/issues/11830))
- Minor updates and documentation for database schema delta files. ([\#11823](https://github.com/matrix-org/synapse/issues/11823))
- Workaround a type annotation problem in `prometheus_client` 0.13.0. ([\#11834](https://github.com/matrix-org/synapse/issues/11834))
- Minor performance improvement in room state lookup. ([\#11836](https://github.com/matrix-org/synapse/issues/11836))
- Fix some indentation inconsistencies in the sample config. ([\#11838](https://github.com/matrix-org/synapse/issues/11838))
- Add type hints to `tests/rest/admin`. ([\#11851](https://github.com/matrix-org/synapse/issues/11851))


Synapse 1.51.0 (2022-01-25)
===========================

No significant changes since 1.51.0rc2.

Synapse 1.51.0 deprecates `webclient` listeners and non-HTTP(S) `web_client_location`s. Support for these will be removed in Synapse 1.53.0, at which point Synapse will not be capable of directly serving a web client for Matrix. See the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#upgrading-to-v1510).

Synapse 1.51.0rc2 (2022-01-24)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.40.0 that caused Synapse to fail to process incoming federation traffic after handling a large amount of events in a v1 room. ([\#11806](https://github.com/matrix-org/synapse/issues/11806))


Synapse 1.50.2 (2022-01-24)
===========================

This release includes the same bugfix as Synapse 1.51.0rc2.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.40.0 that caused Synapse to fail to process incoming federation traffic after handling a large amount of events in a v1 room. ([\#11806](https://github.com/matrix-org/synapse/issues/11806))


Synapse 1.51.0rc1 (2022-01-21)
==============================

Features
--------

- Add `track_puppeted_user_ips` config flag to record client IP addresses against puppeted users, and include the puppeted users in monthly active user counts. ([\#11561](https://github.com/matrix-org/synapse/issues/11561), [\#11749](https://github.com/matrix-org/synapse/issues/11749), [\#11757](https://github.com/matrix-org/synapse/issues/11757))
- Include whether the requesting user has participated in a thread when generating a summary for [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440). ([\#11577](https://github.com/matrix-org/synapse/issues/11577))
- Return an `M_FORBIDDEN` error code instead of `M_UNKNOWN` when a spam checker module prevents a user from creating a room. ([\#11672](https://github.com/matrix-org/synapse/issues/11672))
- Add a flag to the `synapse_review_recent_signups` script to ignore and filter appservice users. ([\#11675](https://github.com/matrix-org/synapse/issues/11675), [\#11770](https://github.com/matrix-org/synapse/issues/11770))


Bugfixes
--------

- Fix a long-standing issue which could cause Synapse to incorrectly accept data in the unsigned field of events
  received over federation. ([\#11530](https://github.com/matrix-org/synapse/issues/11530))
- Fix a long-standing bug where Synapse wouldn't cache a response indicating that a remote user has no devices. ([\#11587](https://github.com/matrix-org/synapse/issues/11587))
- Fix an error that occurs whilst trying to get the federation status of a destination server that was working normally. This admin API was newly introduced in Synapse 1.49.0. ([\#11593](https://github.com/matrix-org/synapse/issues/11593))
- Fix bundled aggregations not being included in the `/sync` response, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#11612](https://github.com/matrix-org/synapse/issues/11612), [\#11659](https://github.com/matrix-org/synapse/issues/11659), [\#11791](https://github.com/matrix-org/synapse/issues/11791))
- Fix the `/_matrix/client/v1/room/{roomId}/hierarchy` endpoint returning incorrect fields which have been present since Synapse 1.49.0. ([\#11667](https://github.com/matrix-org/synapse/issues/11667))
- Fix preview of some GIF URLs (like tenor.com). Contributed by Philippe Daouadi. ([\#11669](https://github.com/matrix-org/synapse/issues/11669))
- Fix a bug where only the first 50 rooms from a space were returned from the `/hierarchy` API. This has existed since the introduction of the API in Synapse 1.41.0. ([\#11695](https://github.com/matrix-org/synapse/issues/11695))
- Fix a bug introduced in Synapse 1.18.0 where password reset and address validation emails would not be sent if their subject was configured to use the 'app' template variable. Contributed by @br4nnigan. ([\#11710](https://github.com/matrix-org/synapse/issues/11710), [\#11745](https://github.com/matrix-org/synapse/issues/11745))
- Make the 'List Rooms' Admin API sort stable. Contributed by Daniël Sonck. ([\#11737](https://github.com/matrix-org/synapse/issues/11737))
- Fix a long-standing bug where space hierarchy over federation would only work correctly some of the time. ([\#11775](https://github.com/matrix-org/synapse/issues/11775))
- Fix a bug introduced in Synapse 1.46.0 that prevented `on_logged_out` module callbacks from being correctly awaited by Synapse. ([\#11786](https://github.com/matrix-org/synapse/issues/11786))


Improved Documentation
----------------------

- Warn against using a Let's Encrypt certificate for TLS/DTLS TURN server client connections, and suggest using ZeroSSL certificate instead. This works around client-side connectivity errors caused by WebRTC libraries that reject Let's Encrypt certificates. Contributed by @AndrewFerr. ([\#11686](https://github.com/matrix-org/synapse/issues/11686))
- Document the new `SYNAPSE_TEST_PERSIST_SQLITE_DB` environment variable in the contributing guide. ([\#11715](https://github.com/matrix-org/synapse/issues/11715))
- Document that the minimum supported PostgreSQL version is now 10. ([\#11725](https://github.com/matrix-org/synapse/issues/11725))
- Fix typo in demo docs: different. ([\#11735](https://github.com/matrix-org/synapse/issues/11735))
- Update room spec URL in config files. ([\#11739](https://github.com/matrix-org/synapse/issues/11739))
- Mention `python3-venv` and `libpq-dev` dependencies in the contribution guide. ([\#11740](https://github.com/matrix-org/synapse/issues/11740))
- Update documentation for configuring login with Facebook. ([\#11755](https://github.com/matrix-org/synapse/issues/11755))
- Update installation instructions to note that Python 3.6 is no longer supported. ([\#11781](https://github.com/matrix-org/synapse/issues/11781))


Deprecations and Removals
-------------------------

- Remove the unstable `/send_relation` endpoint. ([\#11682](https://github.com/matrix-org/synapse/issues/11682))
- Remove `python_twisted_reactor_pending_calls` Prometheus metric. ([\#11724](https://github.com/matrix-org/synapse/issues/11724))
- Remove the `password_hash` field from the response dictionaries of the [Users Admin API](https://matrix-org.github.io/synapse/latest/admin_api/user_admin_api.html). ([\#11576](https://github.com/matrix-org/synapse/issues/11576))
- **Deprecate support for `webclient` listeners and non-HTTP(S) `web_client_location` configuration. ([\#11774](https://github.com/matrix-org/synapse/issues/11774), [\#11783](https://github.com/matrix-org/synapse/issues/11783))**


Internal Changes
----------------

- Run `pyupgrade --py37-plus --keep-percent-format` on Synapse. ([\#11685](https://github.com/matrix-org/synapse/issues/11685))
- Use buildkit's cache feature to speed up docker builds. ([\#11691](https://github.com/matrix-org/synapse/issues/11691))
- Use `auto_attribs` and native type hints for attrs classes. ([\#11692](https://github.com/matrix-org/synapse/issues/11692), [\#11768](https://github.com/matrix-org/synapse/issues/11768))
- Remove debug logging for #4422, which has been closed since Synapse 0.99. ([\#11693](https://github.com/matrix-org/synapse/issues/11693))
- Remove fallback code for Python 2. ([\#11699](https://github.com/matrix-org/synapse/issues/11699))
- Add a test for [an edge case](https://github.com/matrix-org/synapse/pull/11532#discussion_r769104461) in the `/sync` logic. ([\#11701](https://github.com/matrix-org/synapse/issues/11701))
- Add the option to write SQLite test dbs to disk when running tests. ([\#11702](https://github.com/matrix-org/synapse/issues/11702))
- Improve Complement test output for Gitub Actions. ([\#11707](https://github.com/matrix-org/synapse/issues/11707))
- Fix docstring on `add_account_data_for_user`. ([\#11716](https://github.com/matrix-org/synapse/issues/11716))
- Complement environment variable name change and update `.gitignore`. ([\#11718](https://github.com/matrix-org/synapse/issues/11718))
- Simplify calculation of Prometheus metrics for garbage collection. ([\#11723](https://github.com/matrix-org/synapse/issues/11723))
- Improve accuracy of `python_twisted_reactor_tick_time` Prometheus metric. ([\#11724](https://github.com/matrix-org/synapse/issues/11724), [\#11771](https://github.com/matrix-org/synapse/issues/11771))
- Minor efficiency improvements when inserting many values into the database. ([\#11742](https://github.com/matrix-org/synapse/issues/11742))
- Invite PR authors to give themselves credit in the changelog. ([\#11744](https://github.com/matrix-org/synapse/issues/11744))
- Add optional debugging to investigate [issue 8631](https://github.com/matrix-org/synapse/issues/8631). ([\#11760](https://github.com/matrix-org/synapse/issues/11760))
- Remove `log_function` utility function and its uses. ([\#11761](https://github.com/matrix-org/synapse/issues/11761))
- Add a unit test that checks both `client` and `webclient` resources will function when simultaneously enabled. ([\#11765](https://github.com/matrix-org/synapse/issues/11765))
- Allow overriding complement commit using `COMPLEMENT_REF`. ([\#11766](https://github.com/matrix-org/synapse/issues/11766))
- Add some comments and type annotations for `_update_outliers_txn`. ([\#11776](https://github.com/matrix-org/synapse/issues/11776))


Synapse 1.50.1 (2022-01-18)
===========================

This release fixes a bug in Synapse 1.50.0 that could prevent clients from being able to connect to Synapse if the `webclient` resource was enabled. Further details are available in [this issue](https://github.com/matrix-org/synapse/issues/11763).

Bugfixes
--------

- Fix a bug introduced in Synapse 1.50.0rc1 that could cause Matrix clients to be unable to connect to Synapse instances with the `webclient` resource enabled. ([\#11764](https://github.com/matrix-org/synapse/issues/11764))


Synapse 1.50.0 (2022-01-18)
===========================

**This release contains a critical bug that may prevent clients from being able to connect.
As such, it is not recommended to upgrade to 1.50.0. Instead, please upgrade straight to
to 1.50.1. Further details are available in [this issue](https://github.com/matrix-org/synapse/issues/11763).**

Please note that we now only support Python 3.7+ and PostgreSQL 10+ (if applicable), because Python 3.6 and PostgreSQL 9.6 have reached end-of-life.

No significant changes since 1.50.0rc2.


Synapse 1.50.0rc2 (2022-01-14)
==============================

This release candidate fixes a federation-breaking regression introduced in Synapse 1.50.0rc1.

Bugfixes
--------

- Fix a bug introduced in Synapse 1.0.0 whereby some device list updates would not be sent to remote homeservers if there were too many to send at once. ([\#11729](https://github.com/matrix-org/synapse/issues/11729))
- Fix a bug introduced in Synapse 1.50.0rc1 whereby outbound federation could fail because too many EDUs were produced for device updates. ([\#11730](https://github.com/matrix-org/synapse/issues/11730))


Improved Documentation
----------------------

- Document that now the minimum supported PostgreSQL version is 10. ([\#11725](https://github.com/matrix-org/synapse/issues/11725))


Internal Changes
----------------

- Fix a typechecker problem related to our (ab)use of `nacl.signing.SigningKey`s. ([\#11714](https://github.com/matrix-org/synapse/issues/11714))


Synapse 1.50.0rc1 (2022-01-05)
==============================


Features
--------

- Allow guests to send state events per [MSC3419](https://github.com/matrix-org/matrix-doc/pull/3419). ([\#11378](https://github.com/matrix-org/synapse/issues/11378))
- Add experimental support for part of [MSC3202](https://github.com/matrix-org/matrix-doc/pull/3202): allowing application services to masquerade as specific devices. ([\#11538](https://github.com/matrix-org/synapse/issues/11538))
- Add admin API to get users' account data. ([\#11664](https://github.com/matrix-org/synapse/issues/11664))
- Include the room topic in the stripped state included with invites and knocking. ([\#11666](https://github.com/matrix-org/synapse/issues/11666))
- Send and handle cross-signing messages using the stable prefix. ([\#10520](https://github.com/matrix-org/synapse/issues/10520))
- Support unprefixed versions of fallback key property names. ([\#11541](https://github.com/matrix-org/synapse/issues/11541))


Bugfixes
--------

- Fix a long-standing bug where relations from other rooms could be included in the bundled aggregations of an event. ([\#11516](https://github.com/matrix-org/synapse/issues/11516))
- Fix a long-standing bug which could cause `AssertionError`s to be written to the log when Synapse was restarted after purging events from the database. ([\#11536](https://github.com/matrix-org/synapse/issues/11536), [\#11642](https://github.com/matrix-org/synapse/issues/11642))
- Fix a bug introduced in Synapse 1.17.0 where a pusher created for an email with capital letters would fail to be created. ([\#11547](https://github.com/matrix-org/synapse/issues/11547))
- Fix a long-standing bug where responses included bundled aggregations when they should not, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#11592](https://github.com/matrix-org/synapse/issues/11592), [\#11623](https://github.com/matrix-org/synapse/issues/11623))
- Fix a long-standing bug that some unknown endpoints would return HTML error pages instead of JSON `M_UNRECOGNIZED` errors. ([\#11602](https://github.com/matrix-org/synapse/issues/11602))
- Fix a bug introduced in Synapse 1.19.3 which could sometimes cause `AssertionError`s when backfilling rooms over federation. ([\#11632](https://github.com/matrix-org/synapse/issues/11632))


Improved Documentation
----------------------

- Update Synapse install command for FreeBSD as the package is now prefixed with `py38`. Contributed by @itchychips. ([\#11267](https://github.com/matrix-org/synapse/issues/11267))
- Document the usage of refresh tokens. ([\#11427](https://github.com/matrix-org/synapse/issues/11427))
- Add details for how to configure a TURN server when behind a NAT. Contributed by @AndrewFerr. ([\#11553](https://github.com/matrix-org/synapse/issues/11553))
- Add references for using Postgres to the Docker documentation. ([\#11640](https://github.com/matrix-org/synapse/issues/11640))
- Fix the documentation link in newly-generated configuration files. ([\#11678](https://github.com/matrix-org/synapse/issues/11678))
- Correct the documentation for `nginx` to use a case-sensitive url pattern. Fixes an error introduced in v1.21.0. ([\#11680](https://github.com/matrix-org/synapse/issues/11680))
- Clarify SSO mapping provider documentation by writing `def` or `async def` before the names of methods, as appropriate. ([\#11681](https://github.com/matrix-org/synapse/issues/11681))


Deprecations and Removals
-------------------------

- Replace `mock` package by its standard library version. ([\#11588](https://github.com/matrix-org/synapse/issues/11588))
- Drop support for Python 3.6 and Ubuntu 18.04. ([\#11633](https://github.com/matrix-org/synapse/issues/11633))


Internal Changes
----------------

- Allow specific, experimental events to be created without `prev_events`. Used by [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716). ([\#11243](https://github.com/matrix-org/synapse/issues/11243))
- A test helper (`wait_for_background_updates`) no longer depends on classes defining a `store` property. ([\#11331](https://github.com/matrix-org/synapse/issues/11331))
- Add type hints to `synapse.appservice`. ([\#11360](https://github.com/matrix-org/synapse/issues/11360))
- Add missing type hints to `synapse.config` module. ([\#11480](https://github.com/matrix-org/synapse/issues/11480))
- Add test to ensure we share the same `state_group` across the whole historical batch when using the [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` endpoint. ([\#11487](https://github.com/matrix-org/synapse/issues/11487))
- Refactor `tests.util.setup_test_homeserver` and `tests.server.setup_test_homeserver`. ([\#11503](https://github.com/matrix-org/synapse/issues/11503))
- Move `glob_to_regex` and `re_word_boundary` to `matrix-python-common`. ([\#11505](https://github.com/matrix-org/synapse/issues/11505), [\#11687](https://github.com/matrix-org/synapse/issues/11687))
- Use `HTTPStatus` constants in place of literals in `tests.rest.client.test_auth`. ([\#11520](https://github.com/matrix-org/synapse/issues/11520))
- Add a receipt types constant for `m.read`. ([\#11531](https://github.com/matrix-org/synapse/issues/11531))
- Clean up `synapse.rest.admin`. ([\#11535](https://github.com/matrix-org/synapse/issues/11535))
- Add missing `errcode` to `parse_string` and `parse_boolean`. ([\#11542](https://github.com/matrix-org/synapse/issues/11542))
- Use `HTTPStatus` constants in place of literals in `synapse.http`. ([\#11543](https://github.com/matrix-org/synapse/issues/11543))
- Add missing type hints to storage classes. ([\#11546](https://github.com/matrix-org/synapse/issues/11546), [\#11549](https://github.com/matrix-org/synapse/issues/11549), [\#11551](https://github.com/matrix-org/synapse/issues/11551), [\#11555](https://github.com/matrix-org/synapse/issues/11555), [\#11575](https://github.com/matrix-org/synapse/issues/11575), [\#11589](https://github.com/matrix-org/synapse/issues/11589), [\#11594](https://github.com/matrix-org/synapse/issues/11594), [\#11652](https://github.com/matrix-org/synapse/issues/11652), [\#11653](https://github.com/matrix-org/synapse/issues/11653), [\#11654](https://github.com/matrix-org/synapse/issues/11654), [\#11657](https://github.com/matrix-org/synapse/issues/11657))
- Fix an inaccurate and misleading comment in the `/sync` code. ([\#11550](https://github.com/matrix-org/synapse/issues/11550))
- Add missing type hints to `synapse.logging.context`. ([\#11556](https://github.com/matrix-org/synapse/issues/11556))
- Stop populating unused database column `state_events.prev_state`. ([\#11558](https://github.com/matrix-org/synapse/issues/11558))
- Minor efficiency improvements in event persistence. ([\#11560](https://github.com/matrix-org/synapse/issues/11560))
- Add some safety checks that storage functions are used correctly. ([\#11564](https://github.com/matrix-org/synapse/issues/11564), [\#11580](https://github.com/matrix-org/synapse/issues/11580))
- Make `get_device` return `None` if the device doesn't exist rather than raising an exception. ([\#11565](https://github.com/matrix-org/synapse/issues/11565))
- Split the HTML parsing code from the URL preview resource code. ([\#11566](https://github.com/matrix-org/synapse/issues/11566))
- Remove redundant `COALESCE()`s around `COUNT()`s in database queries. ([\#11570](https://github.com/matrix-org/synapse/issues/11570))
- Add missing type hints to `synapse.http`. ([\#11571](https://github.com/matrix-org/synapse/issues/11571))
- Add [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) and [MSC3030](https://github.com/matrix-org/matrix-doc/pull/3030) to `/versions` -> `unstable_features` to detect server support. ([\#11582](https://github.com/matrix-org/synapse/issues/11582))
- Add type hints to `synapse/tests/rest/admin`. ([\#11590](https://github.com/matrix-org/synapse/issues/11590))
- Drop end-of-life Python 3.6 and Postgres 9.6 from CI. ([\#11595](https://github.com/matrix-org/synapse/issues/11595))
- Update black version and run it on all the files. ([\#11596](https://github.com/matrix-org/synapse/issues/11596))
- Add opentracing type stubs and fix associated mypy errors. ([\#11603](https://github.com/matrix-org/synapse/issues/11603), [\#11622](https://github.com/matrix-org/synapse/issues/11622))
- Improve OpenTracing support for requests which use a `ResponseCache`. ([\#11607](https://github.com/matrix-org/synapse/issues/11607))
- Improve OpenTracing support for incoming HTTP requests. ([\#11618](https://github.com/matrix-org/synapse/issues/11618))
- A number of improvements to opentracing support. ([\#11619](https://github.com/matrix-org/synapse/issues/11619))
- Refactor the way that the `outlier` flag is set on events received over federation. ([\#11634](https://github.com/matrix-org/synapse/issues/11634))
- Improve the error messages from  `get_create_event_for_room`. ([\#11638](https://github.com/matrix-org/synapse/issues/11638))
- Remove redundant `get_current_events_token` method. ([\#11643](https://github.com/matrix-org/synapse/issues/11643))
- Convert `namedtuples` to `attrs`. ([\#11665](https://github.com/matrix-org/synapse/issues/11665), [\#11574](https://github.com/matrix-org/synapse/issues/11574))
- Update the `/capabilities` response to include whether support for [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440) is available. ([\#11690](https://github.com/matrix-org/synapse/issues/11690))
- Send the `Accept` header in HTTP requests made using `SimpleHttpClient.get_json`. ([\#11677](https://github.com/matrix-org/synapse/issues/11677))
- Work around Mjolnir compatibility issue by adding an import for `glob_to_regex` in `synapse.util`, where it moved from. ([\#11696](https://github.com/matrix-org/synapse/issues/11696))


**Changelogs for older versions can be found [here](CHANGES-2021.md).**
