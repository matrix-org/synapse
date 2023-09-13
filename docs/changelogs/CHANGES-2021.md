
Synapse 1.49.2 (2021-12-21)
===========================

This release fixes a regression introduced in Synapse 1.49.0 which could cause `/sync` requests to take significantly longer. This would particularly affect "initial" syncs for users participating in a large number of rooms, and in extreme cases, could make it impossible for such users to log in on a new client.

**Note:** in line with our [deprecation policy](https://matrix-org.github.io/synapse/latest/deprecation_policy.html) for platform dependencies, this will be the last release to support Python 3.6 and PostgreSQL 9.6, both of which have now reached upstream end-of-life. Synapse will require Python 3.7+ and PostgreSQL 10+.

**Note:** We will also stop producing packages for Ubuntu 18.04 (Bionic Beaver) after this release, as it uses Python 3.6.

Bugfixes
--------

- Fix a performance regression in `/sync` handling, introduced in 1.49.0. ([\#11583](https://github.com/matrix-org/synapse/issues/11583))

Internal Changes
----------------

- Work around a build problem on Debian Buster. ([\#11625](https://github.com/matrix-org/synapse/issues/11625))


Synapse 1.49.1 (2021-12-21)
===========================

Not released due to problems building the debian packages.


Synapse 1.49.0 (2021-12-14)
===========================

No significant changes since version 1.49.0rc1.


Support for Ubuntu 21.04 ends next month on the 20th of January
---------------------------------------------------------------

For users of Ubuntu 21.04 (Hirsute Hippo), please be aware that [upstream support for this version of Ubuntu will end next month][Ubuntu2104EOL].
We will stop producing packages for Ubuntu 21.04 after upstream support ends.

[Ubuntu2104EOL]: https://lists.ubuntu.com/archives/ubuntu-announce/2021-December/000275.html


The wiki has been migrated to the documentation website
-------------------------------------------------------

We've decided to move the existing, somewhat stagnant pages from the GitHub wiki
to the [documentation website](https://matrix-org.github.io/synapse/latest/).

This was done for two reasons. The first was to ensure that changes are checked by
multiple authors before being committed (everyone makes mistakes!) and the second
was visibility of the documentation. Not everyone knows that Synapse has some very
useful information hidden away in its GitHub wiki pages. Bringing them to the
documentation website should help with visibility, as well as keep all Synapse documentation
in one, easily-searchable location.

Note that contributions to the documentation website happen through [GitHub pull
requests](https://github.com/matrix-org/synapse/pulls). Please visit [#synapse-dev:matrix.org](https://matrix.to/#/#synapse-dev:matrix.org)
if you need help with the process!


Synapse 1.49.0rc1 (2021-12-07)
==============================

Features
--------

- Add [MSC3030](https://github.com/matrix-org/matrix-doc/pull/3030) experimental client and federation API endpoints to get the closest event to a given timestamp. ([\#9445](https://github.com/matrix-org/synapse/issues/9445))
- Include bundled relation aggregations during a limited `/sync` request and `/relations` request, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#11284](https://github.com/matrix-org/synapse/issues/11284), [\#11478](https://github.com/matrix-org/synapse/issues/11478))
- Add plugin support for controlling database background updates. ([\#11306](https://github.com/matrix-org/synapse/issues/11306), [\#11475](https://github.com/matrix-org/synapse/issues/11475), [\#11479](https://github.com/matrix-org/synapse/issues/11479))
- Support the stable API endpoints for [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946): the room `/hierarchy` endpoint. ([\#11329](https://github.com/matrix-org/synapse/issues/11329))
- Add admin API to get some information about federation status with remote servers. ([\#11407](https://github.com/matrix-org/synapse/issues/11407))
- Support expiry of refresh tokens and expiry of the overall session when refresh tokens are in use. ([\#11425](https://github.com/matrix-org/synapse/issues/11425))
- Stabilise support for [MSC2918](https://github.com/matrix-org/matrix-doc/blob/main/proposals/2918-refreshtokens.md#msc2918-refresh-tokens) refresh tokens as they have now been merged into the Matrix specification. ([\#11435](https://github.com/matrix-org/synapse/issues/11435), [\#11522](https://github.com/matrix-org/synapse/issues/11522))
- Update [MSC2918 refresh token](https://github.com/matrix-org/matrix-doc/blob/main/proposals/2918-refreshtokens.md#msc2918-refresh-tokens) support to confirm with the latest revision: accept the `refresh_tokens` parameter in the request body rather than in the URL parameters. ([\#11430](https://github.com/matrix-org/synapse/issues/11430))
- Support configuring the lifetime of non-refreshable access tokens separately to refreshable access tokens. ([\#11445](https://github.com/matrix-org/synapse/issues/11445))
- Expose `synapse_homeserver` and `synapse_worker` commands as entry points to run Synapse's main process and worker processes, respectively. Contributed by @Ma27. ([\#11449](https://github.com/matrix-org/synapse/issues/11449))
- `synctl stop` will now wait for Synapse to exit before returning. ([\#11459](https://github.com/matrix-org/synapse/issues/11459), [\#11490](https://github.com/matrix-org/synapse/issues/11490))
- Extend the "delete room" admin api to work correctly on rooms which have previously been partially deleted. ([\#11523](https://github.com/matrix-org/synapse/issues/11523))
- Add support for the `/_matrix/client/v3/login/sso/redirect/{idpId}` API from Matrix v1.1. This endpoint was overlooked when support for v3 endpoints was added in Synapse 1.48.0rc1. ([\#11451](https://github.com/matrix-org/synapse/issues/11451))


Bugfixes
--------

- Fix using [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) batch sending in combination with event persistence workers. Contributed by @tulir at Beeper. ([\#11220](https://github.com/matrix-org/synapse/issues/11220))
- Fix a long-standing bug where all requests that read events from the database could get stuck as a result of losing the database connection, properly this time. Also fix a race condition introduced in the previous insufficient fix in Synapse 1.47.0. ([\#11376](https://github.com/matrix-org/synapse/issues/11376))
- The `/send_join` response now includes the stable `event` field instead of the unstable field from [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083). ([\#11413](https://github.com/matrix-org/synapse/issues/11413))
- Fix a bug introduced in Synapse 1.47.0 where `send_join` could fail due to an outdated `ijson` version. ([\#11439](https://github.com/matrix-org/synapse/issues/11439), [\#11441](https://github.com/matrix-org/synapse/issues/11441), [\#11460](https://github.com/matrix-org/synapse/issues/11460))
- Fix a bug introduced in Synapse 1.36.0 which could cause problems fetching event-signing keys from trusted key servers. ([\#11440](https://github.com/matrix-org/synapse/issues/11440))
- Fix a bug introduced in Synapse 1.47.1 where the media repository would fail to work if the media store path contained any symbolic links. ([\#11446](https://github.com/matrix-org/synapse/issues/11446))
- Fix an `LruCache` corruption bug, introduced in Synapse 1.38.0, that would cause certain requests to fail until the next Synapse restart. ([\#11454](https://github.com/matrix-org/synapse/issues/11454))
- Fix a long-standing bug where invites from ignored users were included in incremental syncs. ([\#11511](https://github.com/matrix-org/synapse/issues/11511))
- Fix a regression in Synapse 1.48.0 where presence workers would not clear their presence updates over replication on shutdown. ([\#11518](https://github.com/matrix-org/synapse/issues/11518))
- Fix a regression in Synapse 1.48.0 where the module API's `looping_background_call` method would spam errors to the logs when given a non-async function. ([\#11524](https://github.com/matrix-org/synapse/issues/11524))


Updates to the Docker image
---------------------------

- Update `Dockerfile-workers` to healthcheck all workers in the container. ([\#11429](https://github.com/matrix-org/synapse/issues/11429))


Improved Documentation
----------------------

- Update the media repository documentation. ([\#11415](https://github.com/matrix-org/synapse/issues/11415))
- Update section about backward extremities in the room DAG concepts doc to correct the misconception about backward extremities indicating whether we have fetched an events' `prev_events`. ([\#11469](https://github.com/matrix-org/synapse/issues/11469))


Internal Changes
----------------

- Add `Final` annotation to string constants in `synapse.api.constants` so that they get typed as `Literal`s. ([\#11356](https://github.com/matrix-org/synapse/issues/11356))
- Add a check to ensure that users cannot start the Synapse master process when `worker_app` is set. ([\#11416](https://github.com/matrix-org/synapse/issues/11416))
- Add a note about postgres memory management and hugepages to postgres doc. ([\#11467](https://github.com/matrix-org/synapse/issues/11467))
- Add missing type hints to `synapse.config` module. ([\#11465](https://github.com/matrix-org/synapse/issues/11465))
- Add missing type hints to `synapse.federation`. ([\#11483](https://github.com/matrix-org/synapse/issues/11483))
- Add type annotations to `tests.storage.test_appservice`. ([\#11488](https://github.com/matrix-org/synapse/issues/11488), [\#11492](https://github.com/matrix-org/synapse/issues/11492))
- Add type annotations to some of the configuration surrounding refresh tokens. ([\#11428](https://github.com/matrix-org/synapse/issues/11428))
- Add type hints to `synapse/tests/rest/admin`. ([\#11501](https://github.com/matrix-org/synapse/issues/11501))
- Add type hints to storage classes. ([\#11411](https://github.com/matrix-org/synapse/issues/11411))
- Add wiki pages to documentation website. ([\#11402](https://github.com/matrix-org/synapse/issues/11402))
- Clean up `tests.storage.test_main` to remove use of legacy code. ([\#11493](https://github.com/matrix-org/synapse/issues/11493))
- Clean up `tests.test_visibility` to remove legacy code. ([\#11495](https://github.com/matrix-org/synapse/issues/11495))
- Convert status codes to `HTTPStatus` in `synapse.rest.admin`. ([\#11452](https://github.com/matrix-org/synapse/issues/11452), [\#11455](https://github.com/matrix-org/synapse/issues/11455))
- Extend the `scripts-dev/sign_json` script to support signing events. ([\#11486](https://github.com/matrix-org/synapse/issues/11486))
- Improve internal types in push code. ([\#11409](https://github.com/matrix-org/synapse/issues/11409))
- Improve type annotations in `synapse.module_api`. ([\#11029](https://github.com/matrix-org/synapse/issues/11029))
- Improve type hints for `LruCache`. ([\#11453](https://github.com/matrix-org/synapse/issues/11453))
- Preparation for database schema simplifications: disambiguate queries on `state_key`. ([\#11497](https://github.com/matrix-org/synapse/issues/11497))
- Refactor `backfilled` into specific behavior function arguments (`_persist_events_and_state_updates` and downstream calls). ([\#11417](https://github.com/matrix-org/synapse/issues/11417))
- Refactor `get_version_string` to fix-up types and duplicated code. ([\#11468](https://github.com/matrix-org/synapse/issues/11468))
- Refactor various parts of the `/sync` handler. ([\#11494](https://github.com/matrix-org/synapse/issues/11494), [\#11515](https://github.com/matrix-org/synapse/issues/11515))
- Remove unnecessary `json.dumps` from `tests.rest.admin`. ([\#11461](https://github.com/matrix-org/synapse/issues/11461))
- Save the OpenID Connect session ID on login. ([\#11482](https://github.com/matrix-org/synapse/issues/11482))
- Update and clean up recently ported documentation pages. ([\#11466](https://github.com/matrix-org/synapse/issues/11466))


Synapse 1.48.0 (2021-11-30)
===========================

This release removes support for the long-deprecated `trust_identity_server_for_password_resets` configuration flag.

This release also fixes some performance issues with some background database updates introduced in Synapse 1.47.0.

No significant changes since 1.48.0rc1.

Synapse 1.48.0rc1 (2021-11-25)
==============================

Features
--------

- Experimental support for the thread relation defined in [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440). ([\#11161](https://github.com/matrix-org/synapse/issues/11161))
- Support filtering by relation senders & types per [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440). ([\#11236](https://github.com/matrix-org/synapse/issues/11236))
- Add support for the `/_matrix/client/v3` and `/_matrix/media/v3` APIs from Matrix v1.1. ([\#11318](https://github.com/matrix-org/synapse/issues/11318), [\#11371](https://github.com/matrix-org/synapse/issues/11371))
- Support the stable version of [MSC2778](https://github.com/matrix-org/matrix-doc/pull/2778): the `m.login.application_service` login type. Contributed by @tulir. ([\#11335](https://github.com/matrix-org/synapse/issues/11335))
- Add a new version of delete room admin API `DELETE /_synapse/admin/v2/rooms/<room_id>` to run it in the background. Contributed by @dklimpel. ([\#11223](https://github.com/matrix-org/synapse/issues/11223))
- Allow the admin [Delete Room API](https://matrix-org.github.io/synapse/latest/admin_api/rooms.html#delete-room-api) to block a room without the need to join it. ([\#11228](https://github.com/matrix-org/synapse/issues/11228))
- Add an admin API to un-shadow-ban a user. ([\#11347](https://github.com/matrix-org/synapse/issues/11347))
- Add an admin API to run background database schema updates. ([\#11352](https://github.com/matrix-org/synapse/issues/11352))
- Add an admin API for blocking a room. ([\#11324](https://github.com/matrix-org/synapse/issues/11324))
- Update the JWT login type to support custom a `sub` claim. ([\#11361](https://github.com/matrix-org/synapse/issues/11361))
- Store and allow querying of arbitrary event relations. ([\#11391](https://github.com/matrix-org/synapse/issues/11391))


Bugfixes
--------

- Fix a long-standing bug wherein display names or avatar URLs containing null bytes cause an internal server error when stored in the DB. ([\#11230](https://github.com/matrix-org/synapse/issues/11230))
- Prevent [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) historical state events from being pushed to an application service via `/transactions`. ([\#11265](https://github.com/matrix-org/synapse/issues/11265))
- Fix a long-standing bug where uploading extremely thin images (e.g. 1000x1) would fail. Contributed by @Neeeflix. ([\#11288](https://github.com/matrix-org/synapse/issues/11288))
- Fix a bug, introduced in Synapse 1.46.0, which caused the `check_3pid_auth` and `on_logged_out` callbacks in legacy password authentication provider modules to not be registered. Modules using the generic module interface were not affected. ([\#11340](https://github.com/matrix-org/synapse/issues/11340))
- Fix a bug introduced in 1.41.0 where space hierarchy responses would be incorrectly reused if multiple users were to make the same request at the same time. ([\#11355](https://github.com/matrix-org/synapse/issues/11355))
- Fix a bug introduced in 1.45.0 where the `read_templates` method of the module API would error. ([\#11377](https://github.com/matrix-org/synapse/issues/11377))
- Fix an issue introduced in 1.47.0 which prevented servers re-joining rooms they had previously left, if their signing keys were replaced. ([\#11379](https://github.com/matrix-org/synapse/issues/11379))
- Fix a bug introduced in 1.13.0 where creating and publishing a room could cause errors if `room_list_publication_rules` is configured. ([\#11392](https://github.com/matrix-org/synapse/issues/11392))
- Improve performance of various background database updates. ([\#11421](https://github.com/matrix-org/synapse/issues/11421), [\#11422](https://github.com/matrix-org/synapse/issues/11422))


Improved Documentation
----------------------

- Suggest users of the Debian packages add configuration to `/etc/matrix-synapse/conf.d/` to prevent, upon upgrade, being asked to choose between their configuration and the maintainer's. ([\#11281](https://github.com/matrix-org/synapse/issues/11281))
- Fix typos in the documentation for the `username_available` admin API. Contributed by Stanislav Motylkov. ([\#11286](https://github.com/matrix-org/synapse/issues/11286))
- Add Single Sign-On, SAML and CAS pages to the documentation. ([\#11298](https://github.com/matrix-org/synapse/issues/11298))
- Change the word 'Home server' as one word 'homeserver' in documentation. ([\#11320](https://github.com/matrix-org/synapse/issues/11320))
- Fix missing quotes for wildcard domains in `federation_certificate_verification_whitelist`. ([\#11381](https://github.com/matrix-org/synapse/issues/11381))


Deprecations and Removals
-------------------------

- Remove deprecated `trust_identity_server_for_password_resets` configuration flag. ([\#11333](https://github.com/matrix-org/synapse/issues/11333), [\#11395](https://github.com/matrix-org/synapse/issues/11395))


Internal Changes
----------------

- Add type annotations to `synapse.metrics`. ([\#10847](https://github.com/matrix-org/synapse/issues/10847))
- Split out federated PDU retrieval function into a non-cached version. ([\#11242](https://github.com/matrix-org/synapse/issues/11242))
- Clean up code relating to to-device messages and sending ephemeral events to application services. ([\#11247](https://github.com/matrix-org/synapse/issues/11247))
- Fix a small typo in the error response when a relation type other than 'm.annotation' is passed to `GET /rooms/{room_id}/aggregations/{event_id}`. ([\#11278](https://github.com/matrix-org/synapse/issues/11278))
- Drop unused database tables `room_stats_historical` and `user_stats_historical`. ([\#11280](https://github.com/matrix-org/synapse/issues/11280))
- Require all files in synapse/ and tests/ to pass mypy unless specifically excluded. ([\#11282](https://github.com/matrix-org/synapse/issues/11282), [\#11285](https://github.com/matrix-org/synapse/issues/11285), [\#11359](https://github.com/matrix-org/synapse/issues/11359))
- Add missing type hints to `synapse.app`. ([\#11287](https://github.com/matrix-org/synapse/issues/11287))
- Remove unused parameters on `FederationEventHandler._check_event_auth`. ([\#11292](https://github.com/matrix-org/synapse/issues/11292))
- Add type hints to `synapse._scripts`. ([\#11297](https://github.com/matrix-org/synapse/issues/11297))
- Fix an issue which prevented the `remove_deleted_devices_from_device_inbox` background database schema update from running when updating from a recent Synapse version. ([\#11303](https://github.com/matrix-org/synapse/issues/11303))
- Add type hints to storage classes. ([\#11307](https://github.com/matrix-org/synapse/issues/11307), [\#11310](https://github.com/matrix-org/synapse/issues/11310), [\#11311](https://github.com/matrix-org/synapse/issues/11311), [\#11312](https://github.com/matrix-org/synapse/issues/11312), [\#11313](https://github.com/matrix-org/synapse/issues/11313), [\#11314](https://github.com/matrix-org/synapse/issues/11314), [\#11316](https://github.com/matrix-org/synapse/issues/11316), [\#11322](https://github.com/matrix-org/synapse/issues/11322), [\#11332](https://github.com/matrix-org/synapse/issues/11332), [\#11339](https://github.com/matrix-org/synapse/issues/11339), [\#11342](https://github.com/matrix-org/synapse/issues/11342))
- Add type hints to `synapse.util`. ([\#11321](https://github.com/matrix-org/synapse/issues/11321), [\#11328](https://github.com/matrix-org/synapse/issues/11328))
- Improve type annotations in Synapse's test suite. ([\#11323](https://github.com/matrix-org/synapse/issues/11323), [\#11330](https://github.com/matrix-org/synapse/issues/11330))
- Test that room alias deletion works as intended. ([\#11327](https://github.com/matrix-org/synapse/issues/11327))
- Add type annotations for some methods and properties in the module API. ([\#11341](https://github.com/matrix-org/synapse/issues/11341))
- Fix running `scripts-dev/complement.sh`, which was broken in v1.47.0rc1. ([\#11368](https://github.com/matrix-org/synapse/issues/11368))
- Rename internal functions for token generation to better reflect what they do. ([\#11369](https://github.com/matrix-org/synapse/issues/11369), [\#11370](https://github.com/matrix-org/synapse/issues/11370))
- Add type hints to configuration classes. ([\#11377](https://github.com/matrix-org/synapse/issues/11377))
- Publish a `develop` image to Docker Hub. ([\#11380](https://github.com/matrix-org/synapse/issues/11380))
- Keep fallback key marked as used if it's re-uploaded. ([\#11382](https://github.com/matrix-org/synapse/issues/11382))
- Use `auto_attribs` on the `attrs` class `RefreshTokenLookupResult`. ([\#11386](https://github.com/matrix-org/synapse/issues/11386))
- Rename unstable `access_token_lifetime` configuration option to `refreshable_access_token_lifetime` to make it clear it only concerns refreshable access tokens. ([\#11388](https://github.com/matrix-org/synapse/issues/11388))
- Do not run the broken MSC2716 tests when running `scripts-dev/complement.sh`. ([\#11389](https://github.com/matrix-org/synapse/issues/11389))
- Remove dead code from supporting ACME. ([\#11393](https://github.com/matrix-org/synapse/issues/11393))
- Refactor including the bundled relations when serializing an event. ([\#11408](https://github.com/matrix-org/synapse/issues/11408))


Synapse 1.47.1 (2021-11-23)
===========================

This release fixes a security issue in the media store, affecting all prior releases of Synapse. Server administrators are encouraged to update Synapse as soon as possible. We are not aware of these vulnerabilities being exploited in the wild.

Server administrators who are unable to update Synapse may use the workarounds described in the linked GitHub Security Advisory below.

Security advisory
-----------------

The following issue is fixed in 1.47.1.

- **[GHSA-3hfw-x7gx-437c](https://github.com/matrix-org/synapse/security/advisories/GHSA-3hfw-x7gx-437c) / [CVE-2021-41281](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41281): Path traversal when downloading remote media.**

  Synapse instances with the media repository enabled can be tricked into downloading a file from a remote server into an arbitrary directory, potentially outside the media store directory.

  The last two directories and file name of the path are chosen randomly by Synapse and cannot be controlled by an attacker, which limits the impact.

  Homeservers with the media repository disabled are unaffected. Homeservers configured with a federation whitelist are also unaffected.

  Fixed by [91f2bd090](https://github.com/matrix-org/synapse/commit/91f2bd090).


Synapse 1.47.0 (2021-11-17)
===========================

No significant changes since 1.47.0rc3.


Synapse 1.47.0rc3 (2021-11-16)
==============================

Bugfixes
--------

- Fix a bug introduced in 1.47.0rc1 which caused worker processes to not halt startup in the presence of outstanding database migrations. ([\#11346](https://github.com/matrix-org/synapse/issues/11346))
- Fix a bug introduced in 1.47.0rc1 which prevented the 'remove deleted devices from `device_inbox` column' background process from running when updating from a recent Synapse version. ([\#11303](https://github.com/matrix-org/synapse/issues/11303), [\#11353](https://github.com/matrix-org/synapse/issues/11353))


Synapse 1.47.0rc2 (2021-11-10)
==============================

This fixes an issue with publishing the Debian packages for 1.47.0rc1.
It is otherwise identical to 1.47.0rc1.


Synapse 1.47.0rc1 (2021-11-09)
==============================

Deprecations and Removals
-------------------------

- The `user_may_create_room_with_invites` module callback is now deprecated. Please refer to the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#upgrading-to-v1470) for more information. ([\#11206](https://github.com/matrix-org/synapse/issues/11206))
- Remove deprecated admin API to delete rooms (`POST /_synapse/admin/v1/rooms/<room_id>/delete`). ([\#11213](https://github.com/matrix-org/synapse/issues/11213))


Features
--------

- Advertise support for Client-Server API r0.6.1. ([\#11097](https://github.com/matrix-org/synapse/issues/11097))
- Add search by room ID and room alias to the List Room admin API. ([\#11099](https://github.com/matrix-org/synapse/issues/11099))
- Add an `on_new_event` third-party rules callback to allow Synapse modules to act after an event has been sent into a room. ([\#11126](https://github.com/matrix-org/synapse/issues/11126))
- Add a module API method to update a user's membership in a room. ([\#11147](https://github.com/matrix-org/synapse/issues/11147))
- Add metrics for thread pool usage. ([\#11178](https://github.com/matrix-org/synapse/issues/11178))
- Support the stable room type field for [MSC3288](https://github.com/matrix-org/matrix-doc/pull/3288). ([\#11187](https://github.com/matrix-org/synapse/issues/11187))
- Add a module API method to retrieve the current state of a room. ([\#11204](https://github.com/matrix-org/synapse/issues/11204))
- Calculate a default value for `public_baseurl` based on `server_name`. ([\#11210](https://github.com/matrix-org/synapse/issues/11210))
- Add support for serving `/.well-known/matrix/server` files, to redirect federation traffic to port 443. ([\#11211](https://github.com/matrix-org/synapse/issues/11211))
- Add admin APIs to pause, start and check the status of background updates. ([\#11263](https://github.com/matrix-org/synapse/issues/11263))


Bugfixes
--------

- Fix a long-standing bug which allowed hidden devices to receive to-device messages, resulting in unnecessary database bloat. ([\#10097](https://github.com/matrix-org/synapse/issues/10097))
- Fix a long-standing bug where messages in the `device_inbox` table for deleted devices would persist indefinitely. Contributed by @dklimpel and @JohannesKleine. ([\#10969](https://github.com/matrix-org/synapse/issues/10969), [\#11212](https://github.com/matrix-org/synapse/issues/11212))
- Do not accept events if a third-party rule `check_event_allowed` callback raises an exception. ([\#11033](https://github.com/matrix-org/synapse/issues/11033))
- Fix long-standing bug where verification requests could fail in certain cases if a federation whitelist was in place but did not include your own homeserver. ([\#11129](https://github.com/matrix-org/synapse/issues/11129))
- Allow an empty list of `state_events_at_start` to be sent when using the [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` endpoint and the author of the historical messages is already part of the current room state at the given `?prev_event_id`. ([\#11188](https://github.com/matrix-org/synapse/issues/11188))
- Fix a bug introduced in Synapse 1.45.0 which prevented the `synapse_review_recent_signups` script from running. Contributed by @samuel-p. ([\#11191](https://github.com/matrix-org/synapse/issues/11191))
- Delete `to_device` messages for hidden devices that will never be read, reducing database size. ([\#11199](https://github.com/matrix-org/synapse/issues/11199))
- Fix a long-standing bug wherein a missing `Content-Type` header when downloading remote media would cause Synapse to throw an error. ([\#11200](https://github.com/matrix-org/synapse/issues/11200))
- Fix a long-standing bug which could result in serialization errors and potentially duplicate transaction data when sending ephemeral events to application services. Contributed by @Fizzadar at Beeper. ([\#11207](https://github.com/matrix-org/synapse/issues/11207))
- Fix a bug introduced in Synapse 1.35.0 which made it impossible to join rooms that return a `send_join` response containing floats. ([\#11217](https://github.com/matrix-org/synapse/issues/11217))
- Fix long-standing bug where cross signing keys were not included in the response to `/r0/keys/query` the first time a remote user was queried. ([\#11234](https://github.com/matrix-org/synapse/issues/11234))
- Fix a long-standing bug where all requests that read events from the database could get stuck as a result of losing the database connection. ([\#11240](https://github.com/matrix-org/synapse/issues/11240))
- Fix a bug preventing Synapse from being rolled back to an earlier version when using workers. ([\#11255](https://github.com/matrix-org/synapse/issues/11255), [\#11276](https://github.com/matrix-org/synapse/issues/11276))
- Fix a bug introduced in Synapse 1.37.1 which caused a remote event being processed by a worker to not get processed on restart if the worker was killed. ([\#11262](https://github.com/matrix-org/synapse/issues/11262))
- Only allow old Element/Riot Android clients to send read receipts without a request body. All other clients must include a request body as required by the specification. Contributed by @rogersheu. ([\#11157](https://github.com/matrix-org/synapse/issues/11157))


Updates to the Docker image
---------------------------

- Avoid changing user ID when started as a non-root user, and no explicit `UID` is set. ([\#11209](https://github.com/matrix-org/synapse/issues/11209))


Improved Documentation
----------------------

- Improve example HAProxy config in the docs to properly handle HTTP `Host` headers with port information. This is required for federation over port 443 to work correctly. ([\#11128](https://github.com/matrix-org/synapse/issues/11128))
- Add documentation for using Authentik as an OpenID Connect Identity Provider. Contributed by @samip5. ([\#11151](https://github.com/matrix-org/synapse/issues/11151))
- Clarify lack of support for Windows. ([\#11198](https://github.com/matrix-org/synapse/issues/11198))
- Improve code formatting and fix a few typos in docs. Contributed by @sumnerevans at Beeper. ([\#11221](https://github.com/matrix-org/synapse/issues/11221))
- Add documentation for using LemonLDAP as an OpenID Connect Identity Provider. Contributed by @l00ptr. ([\#11257](https://github.com/matrix-org/synapse/issues/11257))


Internal Changes
----------------

- Add type annotations for the `log_function` decorator. ([\#10943](https://github.com/matrix-org/synapse/issues/10943))
- Add type hints to `synapse.events`. ([\#11098](https://github.com/matrix-org/synapse/issues/11098))
- Remove and document unnecessary `RoomStreamToken` checks in application service ephemeral event code. ([\#11137](https://github.com/matrix-org/synapse/issues/11137))
- Add type hints so that `synapse.http` passes `mypy` checks. ([\#11164](https://github.com/matrix-org/synapse/issues/11164))
- Update scripts to pass Shellcheck lints. ([\#11166](https://github.com/matrix-org/synapse/issues/11166))
- Add knock information in admin export. Contributed by Rafael Gonçalves. ([\#11171](https://github.com/matrix-org/synapse/issues/11171))
- Add tests to check that `ClientIpStore.get_last_client_ip_by_device` and `get_user_ip_and_agents` combine database and in-memory data correctly. ([\#11179](https://github.com/matrix-org/synapse/issues/11179))
- Refactor `Filter` to check different fields depending on the data type. ([\#11194](https://github.com/matrix-org/synapse/issues/11194))
- Improve type hints for the relations datastore. ([\#11205](https://github.com/matrix-org/synapse/issues/11205))
- Replace outdated links in the pull request checklist with links to the rendered documentation. ([\#11225](https://github.com/matrix-org/synapse/issues/11225))
- Fix a bug in unit test `test_block_room_and_not_purge`. ([\#11226](https://github.com/matrix-org/synapse/issues/11226))
- In `ObservableDeferred`, run observers in the order they were registered. ([\#11229](https://github.com/matrix-org/synapse/issues/11229))
- Minor speed up to start up times and getting updates for groups by adding missing index to `local_group_updates.stream_id`. ([\#11231](https://github.com/matrix-org/synapse/issues/11231))
- Add `twine` and `towncrier` as dev dependencies, as they're used by the release script. ([\#11233](https://github.com/matrix-org/synapse/issues/11233))
- Allow `stream_writers.typing` config to be a list of one worker. ([\#11237](https://github.com/matrix-org/synapse/issues/11237))
- Remove debugging statement in tests. ([\#11239](https://github.com/matrix-org/synapse/issues/11239))
- Fix [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) historical messages backfilling in random order on remote homeservers. ([\#11244](https://github.com/matrix-org/synapse/issues/11244))
- Add an additional test for the `cachedList` method decorator. ([\#11246](https://github.com/matrix-org/synapse/issues/11246))
- Make minor correction to the type of `auth_checkers` callbacks. ([\#11253](https://github.com/matrix-org/synapse/issues/11253))
- Clean up trivial aspects of the Debian package build tooling. ([\#11269](https://github.com/matrix-org/synapse/issues/11269), [\#11273](https://github.com/matrix-org/synapse/issues/11273))
- Blacklist new SyTest that checks that key uploads are valid pending the validation being implemented in Synapse. ([\#11270](https://github.com/matrix-org/synapse/issues/11270))


Synapse 1.46.0 (2021-11-02)
===========================

The cause of the [performance regression affecting Synapse 1.44](https://github.com/matrix-org/synapse/issues/11049) has been identified and fixed. ([\#11177](https://github.com/matrix-org/synapse/issues/11177))

Bugfixes
--------

- Fix a bug introduced in v1.46.0rc1 where URL previews of some XML documents would fail. ([\#11196](https://github.com/matrix-org/synapse/issues/11196))


Synapse 1.46.0rc1 (2021-10-27)
==============================

Features
--------

- Add support for Ubuntu 21.10 "Impish Indri". ([\#11024](https://github.com/matrix-org/synapse/issues/11024))
- Port the Password Auth Providers module interface to the new generic interface. ([\#10548](https://github.com/matrix-org/synapse/issues/10548), [\#11180](https://github.com/matrix-org/synapse/issues/11180))
- Experimental support for the thread relation defined in [MSC3440](https://github.com/matrix-org/matrix-doc/pull/3440). ([\#11088](https://github.com/matrix-org/synapse/issues/11088), [\#11181](https://github.com/matrix-org/synapse/issues/11181), [\#11192](https://github.com/matrix-org/synapse/issues/11192))
- Users admin API can now also modify user type in addition to allowing it to be set on user creation. ([\#11174](https://github.com/matrix-org/synapse/issues/11174))


Bugfixes
--------

- Newly-created public rooms are now only assigned an alias if the room's creation has not been blocked by permission settings. Contributed by @AndrewFerr. ([\#10930](https://github.com/matrix-org/synapse/issues/10930))
- Fix a long-standing bug which meant that events received over federation were sometimes incorrectly accepted into the room state. ([\#11001](https://github.com/matrix-org/synapse/issues/11001), [\#11009](https://github.com/matrix-org/synapse/issues/11009), [\#11012](https://github.com/matrix-org/synapse/issues/11012))
- Fix 500 error on `/messages` when the server accumulates more than 5 backwards extremities at a given depth for a room. ([\#11027](https://github.com/matrix-org/synapse/issues/11027))
- Fix a bug where setting a user's `external_id` via the admin API returns 500 and deletes user's existing external mappings if that external ID is already mapped. ([\#11051](https://github.com/matrix-org/synapse/issues/11051))
- Fix a long-standing bug where users excluded from the user directory were added into the directory if they belonged to a room which became public or private. ([\#11075](https://github.com/matrix-org/synapse/issues/11075))
- Fix a long-standing bug when attempting to preview URLs which are in the `windows-1252` character encoding. ([\#11077](https://github.com/matrix-org/synapse/issues/11077), [\#11089](https://github.com/matrix-org/synapse/issues/11089))
- Fix broken export-data admin command and add test script checking the command to CI. ([\#11078](https://github.com/matrix-org/synapse/issues/11078))
- Show an error when timestamp in seconds is provided to the `/purge_media_cache` Admin API. ([\#11101](https://github.com/matrix-org/synapse/issues/11101))
- Fix local users who left all their rooms being removed from the user directory, even if the `search_all_users` config option was enabled. ([\#11103](https://github.com/matrix-org/synapse/issues/11103))
- Fix a bug which caused the module API's `get_user_ip_and_agents` function to always fail on workers. `get_user_ip_and_agents` was introduced in 1.44.0 and did not function correctly on worker processes at the time. ([\#11112](https://github.com/matrix-org/synapse/issues/11112))
- Identity server connection is no longer ignoring `ip_range_whitelist`. ([\#11120](https://github.com/matrix-org/synapse/issues/11120))
- Fix a bug introduced in Synapse 1.45.0 breaking the configuration file parsing script. ([\#11145](https://github.com/matrix-org/synapse/issues/11145))
- Fix a performance regression introduced in 1.44.0 which could cause client requests to time out when making large numbers of outbound requests. ([\#11177](https://github.com/matrix-org/synapse/issues/11177), [\#11190](https://github.com/matrix-org/synapse/issues/11190))
- Resolve and share `state_groups` for all [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) historical events in batch. ([\#10975](https://github.com/matrix-org/synapse/issues/10975))


Improved Documentation
----------------------

- Fix broken links relating to module API deprecation in the upgrade notes. ([\#11069](https://github.com/matrix-org/synapse/issues/11069))
- Add more information about what happens when a user is deactivated. ([\#11083](https://github.com/matrix-org/synapse/issues/11083))
- Clarify the the sample log config can be copied from the documentation without issue. ([\#11092](https://github.com/matrix-org/synapse/issues/11092))
- Update the admin API documentation with an updated list of the characters allowed in registration tokens. ([\#11093](https://github.com/matrix-org/synapse/issues/11093))
- Document Synapse's behaviour when dealing with multiple modules registering the same callbacks and/or handlers for the same HTTP endpoints. ([\#11096](https://github.com/matrix-org/synapse/issues/11096))
- Fix instances of `[example]{.title-ref}` in the upgrade documentation as a result of prior RST to Markdown conversion. ([\#11118](https://github.com/matrix-org/synapse/issues/11118))
- Document the version of Synapse each module callback was introduced in. ([\#11132](https://github.com/matrix-org/synapse/issues/11132))
- Document the version of Synapse that introduced each module API method. ([\#11183](https://github.com/matrix-org/synapse/issues/11183))


Internal Changes
----------------
- Fix spurious warnings about losing the logging context on the `ReplicationCommandHandler` when losing the replication connection. ([\#10984](https://github.com/matrix-org/synapse/issues/10984))
- Include rejected status when we log events. ([\#11008](https://github.com/matrix-org/synapse/issues/11008))
- Add some extra logging to the event persistence code. ([\#11014](https://github.com/matrix-org/synapse/issues/11014))
- Rearrange the internal workings of the incremental user directory updates. ([\#11035](https://github.com/matrix-org/synapse/issues/11035))
- Fix a long-standing bug where users excluded from the directory could still be added to the `users_who_share_private_rooms` table after a regular user joins a private room. ([\#11143](https://github.com/matrix-org/synapse/issues/11143))
- Add and improve type hints. ([\#10972](https://github.com/matrix-org/synapse/issues/10972), [\#11055](https://github.com/matrix-org/synapse/issues/11055), [\#11066](https://github.com/matrix-org/synapse/issues/11066), [\#11076](https://github.com/matrix-org/synapse/issues/11076), [\#11095](https://github.com/matrix-org/synapse/issues/11095), [\#11109](https://github.com/matrix-org/synapse/issues/11109), [\#11121](https://github.com/matrix-org/synapse/issues/11121), [\#11146](https://github.com/matrix-org/synapse/issues/11146))
- Mark the Synapse package as containing type annotations and fix export declarations so that Synapse pluggable modules may be type checked against Synapse. ([\#11054](https://github.com/matrix-org/synapse/issues/11054))
- Remove dead code from `MediaFilePaths`. ([\#11056](https://github.com/matrix-org/synapse/issues/11056))
- Be more lenient when parsing oEmbed response versions. ([\#11065](https://github.com/matrix-org/synapse/issues/11065))
- Create a separate module for the retention configuration. ([\#11070](https://github.com/matrix-org/synapse/issues/11070))
- Clean up some of the federation event authentication code for clarity. ([\#11115](https://github.com/matrix-org/synapse/issues/11115), [\#11116](https://github.com/matrix-org/synapse/issues/11116), [\#11122](https://github.com/matrix-org/synapse/issues/11122))
- Add docstrings and comments to the application service ephemeral event sending code. ([\#11138](https://github.com/matrix-org/synapse/issues/11138))
- Update the `sign_json` script to support inline configuration of the signing key. ([\#11139](https://github.com/matrix-org/synapse/issues/11139))
- Fix broken link in the docker image README. ([\#11144](https://github.com/matrix-org/synapse/issues/11144))
- Always dump logs from unit tests during CI runs. ([\#11068](https://github.com/matrix-org/synapse/issues/11068))
- Add tests for `MediaFilePaths` class. ([\#11057](https://github.com/matrix-org/synapse/issues/11057))
- Simplify the user admin API tests. ([\#11048](https://github.com/matrix-org/synapse/issues/11048))
- Add a test for the workaround introduced in [\#11042](https://github.com/matrix-org/synapse/pull/11042) concerning the behaviour of third-party rule modules and `SynapseError`s. ([\#11071](https://github.com/matrix-org/synapse/issues/11071))


Synapse 1.45.1 (2021-10-20)
===========================

Bugfixes
--------

- Revert change to counting of deactivated users towards the monthly active users limit, introduced in 1.45.0rc1. ([\#11127](https://github.com/matrix-org/synapse/issues/11127))


Synapse 1.45.0 (2021-10-19)
===========================

No functional changes since Synapse 1.45.0rc2.

Known Issues
------------

- A suspected [performance regression](https://github.com/matrix-org/synapse/issues/11049) which was first reported after the release of 1.44.0 remains unresolved.

  We have not been able to identify a probable cause. Affected users report that setting up a federation sender worker appears to alleviate symptoms of the regression.

Improved Documentation
----------------------

- Reword changelog to clarify concerns about a suspected performance regression in 1.44.0. ([\#11117](https://github.com/matrix-org/synapse/issues/11117))


Synapse 1.45.0rc2 (2021-10-14)
==============================

This release candidate [fixes](https://github.com/matrix-org/synapse/issues/11053) a user directory [bug](https://github.com/matrix-org/synapse/issues/11025) present in 1.45.0rc1.

Known Issues
------------

- A suspected [performance regression](https://github.com/matrix-org/synapse/issues/11049) which was first reported after the release of 1.44.0 remains unresolved.

  We have not been able to identify a probable cause. Affected users report that setting up a federation sender worker appears to alleviate symptoms of the regression.

Bugfixes
--------

- Fix a long-standing bug when using multiple event persister workers where events were not correctly sent down `/sync` due to a race. ([\#11045](https://github.com/matrix-org/synapse/issues/11045))
- Fix a bug introduced in Synapse 1.45.0rc1 where the user directory would stop updating if it processed an event from a
  user not in the `users` table. ([\#11053](https://github.com/matrix-org/synapse/issues/11053))
- Fix a bug introduced in Synapse 1.44.0 when logging errors during oEmbed processing. ([\#11061](https://github.com/matrix-org/synapse/issues/11061))


Internal Changes
----------------

- Add an 'approximate difference' method to `StateFilter`. ([\#10825](https://github.com/matrix-org/synapse/issues/10825))
- Fix inconsistent behavior of `get_last_client_by_ip` when reporting data that has not been stored in the database yet. ([\#10970](https://github.com/matrix-org/synapse/issues/10970))
- Fix a bug introduced in Synapse 1.21.0 that causes opentracing and Prometheus metrics for replication requests to be measured incorrectly. ([\#10996](https://github.com/matrix-org/synapse/issues/10996))
- Ensure that cache config tests do not share state. ([\#11036](https://github.com/matrix-org/synapse/issues/11036))


Synapse 1.45.0rc1 (2021-10-12)
==============================

**Note:** Media storage providers module that read from Synapse's configuration need changes as of this version, see the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#upgrading-to-v1450) for more information.

Known Issues
------------

- We are investigating [a performance issue](https://github.com/matrix-org/synapse/issues/11049) which was reported after the release of 1.44.0.
- We are aware of [a bug](https://github.com/matrix-org/synapse/issues/11025) with the user directory when using application services. A second release candidate is expected which will resolve this.

Features
--------

- Add [MSC3069](https://github.com/matrix-org/matrix-doc/pull/3069) support to `/account/whoami`. ([\#9655](https://github.com/matrix-org/synapse/issues/9655))
- Support autodiscovery of oEmbed previews. ([\#10822](https://github.com/matrix-org/synapse/issues/10822))
- Add a `user_may_send_3pid_invite` spam checker callback for modules to allow or deny 3PID invites. ([\#10894](https://github.com/matrix-org/synapse/issues/10894))
- Add a spam checker callback to allow or deny room joins. ([\#10910](https://github.com/matrix-org/synapse/issues/10910))
- Include an `update_synapse_database` script in the distribution. Contributed by @Fizzadar at Beeper. ([\#10954](https://github.com/matrix-org/synapse/issues/10954))
- Include exception information in JSON logging output. Contributed by @Fizzadar at Beeper. ([\#11028](https://github.com/matrix-org/synapse/issues/11028))


Bugfixes
--------

- Fix a minor bug in the response to `/_matrix/client/r0/voip/turnServer`. Contributed by @lukaslihotzki. ([\#10922](https://github.com/matrix-org/synapse/issues/10922))
- Fix a bug where empty `yyyy-mm-dd/` directories would be left behind in the media store's `url_cache_thumbnails/` directory. ([\#10924](https://github.com/matrix-org/synapse/issues/10924))
- Fix a bug introduced in Synapse v1.40.0 where the signature checks for room version 8 and 9 could be applied to earlier room versions in some situations. ([\#10927](https://github.com/matrix-org/synapse/issues/10927))
- Fix a long-standing bug wherein deactivated users still count towards the monthly active users limit. ([\#10947](https://github.com/matrix-org/synapse/issues/10947))
- Fix a long-standing bug which meant that events received over federation were sometimes incorrectly accepted into the room state. ([\#10956](https://github.com/matrix-org/synapse/issues/10956))
- Fix a long-standing bug where rebuilding the user directory wouldn't exclude support and deactivated users. ([\#10960](https://github.com/matrix-org/synapse/issues/10960))
- Fix [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` endpoint rejecting subsequent batches with unknown batch ID error in existing room versions from the room creator. ([\#10962](https://github.com/matrix-org/synapse/issues/10962))
- Fix a bug that could leak local users' per-room nicknames and avatars when the user directory is rebuilt. ([\#10981](https://github.com/matrix-org/synapse/issues/10981))
- Fix a long-standing bug where the remainder of a batch of user directory changes would be silently dropped if the server left a room early in the batch. ([\#10982](https://github.com/matrix-org/synapse/issues/10982))
- Correct a bugfix introduced in Synapse v1.44.0 that would catch the wrong error if a connection is lost before a response could be written to it. ([\#10995](https://github.com/matrix-org/synapse/issues/10995))
- Fix a long-standing bug where local users' per-room nicknames/avatars were visible to anyone who could see you in the user directory. ([\#11002](https://github.com/matrix-org/synapse/issues/11002))
- Fix a long-standing bug where a user's per-room nickname/avatar would overwrite their profile in the user directory when a room was made public. ([\#11003](https://github.com/matrix-org/synapse/issues/11003))
- Work around a regression, introduced in Synapse v1.39.0, that caused `SynapseError`s raised by the experimental third-party rules module callback `check_event_allowed` to be ignored. ([\#11042](https://github.com/matrix-org/synapse/issues/11042))
- Fix a bug in [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) insertion events in rooms that could cause cross-talk/conflicts between batches. ([\#10877](https://github.com/matrix-org/synapse/issues/10877))


Improved Documentation
----------------------

- Change wording ("reference homeserver") in Synapse repository documentation. Contributed by @maxkratz. ([\#10971](https://github.com/matrix-org/synapse/issues/10971))
- Fix a dead URL in development documentation (SAML) and change wording from "Riot" to "Element". Contributed by @maxkratz. ([\#10973](https://github.com/matrix-org/synapse/issues/10973))
- Add additional content to the Welcome and Overview page of the documentation. ([\#10990](https://github.com/matrix-org/synapse/issues/10990))
- Update links to MSCs in documentation. Contributed by @dklimpel. ([\#10991](https://github.com/matrix-org/synapse/issues/10991))


Internal Changes
----------------

- Improve type hinting in `synapse.util`. ([\#10888](https://github.com/matrix-org/synapse/issues/10888))
- Add further type hints to `synapse.storage.util`. ([\#10892](https://github.com/matrix-org/synapse/issues/10892))
- Fix type hints to be compatible with an upcoming change to Twisted. ([\#10895](https://github.com/matrix-org/synapse/issues/10895))
- Update utility code to handle C implementations of frozendict. ([\#10902](https://github.com/matrix-org/synapse/issues/10902))
- Drop old functionality which maintained database compatibility with Synapse versions before v1.31. ([\#10903](https://github.com/matrix-org/synapse/issues/10903))
- Clean-up configuration helper classes for the `ServerConfig` class. ([\#10915](https://github.com/matrix-org/synapse/issues/10915))
- Use direct references to config flags. ([\#10916](https://github.com/matrix-org/synapse/issues/10916), [\#10959](https://github.com/matrix-org/synapse/issues/10959), [\#10985](https://github.com/matrix-org/synapse/issues/10985))
- Clean up some of the federation event authentication code for clarity. ([\#10926](https://github.com/matrix-org/synapse/issues/10926), [\#10940](https://github.com/matrix-org/synapse/issues/10940), [\#10986](https://github.com/matrix-org/synapse/issues/10986), [\#10987](https://github.com/matrix-org/synapse/issues/10987), [\#10988](https://github.com/matrix-org/synapse/issues/10988), [\#11010](https://github.com/matrix-org/synapse/issues/11010), [\#11011](https://github.com/matrix-org/synapse/issues/11011))
- Refactor various parts of the codebase to use `RoomVersion` objects instead of room version identifier strings. ([\#10934](https://github.com/matrix-org/synapse/issues/10934))
- Refactor user directory tests in preparation for upcoming changes. ([\#10935](https://github.com/matrix-org/synapse/issues/10935))
- Include the event id in the logcontext when handling PDUs received over federation. ([\#10936](https://github.com/matrix-org/synapse/issues/10936))
- Fix logged errors in unit tests. ([\#10939](https://github.com/matrix-org/synapse/issues/10939))
- Fix a broken test to ensure that consent configuration works during registration. ([\#10945](https://github.com/matrix-org/synapse/issues/10945))
- Add type hints to filtering classes. ([\#10958](https://github.com/matrix-org/synapse/issues/10958))
- Add type-hint to `HomeserverTestcase.setup_test_homeserver`. ([\#10961](https://github.com/matrix-org/synapse/issues/10961))
- Fix the test utility function `create_room_as` so that `is_public=True` will explicitly set the `visibility` parameter of room creation requests to `public`. Contributed by @AndrewFerr. ([\#10963](https://github.com/matrix-org/synapse/issues/10963))
- Make the release script more robust and transparent. ([\#10966](https://github.com/matrix-org/synapse/issues/10966))
- Refactor [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` mega function into smaller handler functions. ([\#10974](https://github.com/matrix-org/synapse/issues/10974))
- Log stack traces when a missing opentracing span is detected. ([\#10983](https://github.com/matrix-org/synapse/issues/10983))
- Update GHA config to run tests against Python 3.10 and PostgreSQL 14. ([\#10992](https://github.com/matrix-org/synapse/issues/10992))
- Fix a long-standing bug where `ReadWriteLock`s could drop logging contexts on exit. ([\#10993](https://github.com/matrix-org/synapse/issues/10993))
- Add a `CODEOWNERS` file to automatically request reviews from the `@matrix-org/synapse-core` team on new pull requests. ([\#10994](https://github.com/matrix-org/synapse/issues/10994))
- Add further type hints to `synapse.state`. ([\#11004](https://github.com/matrix-org/synapse/issues/11004))
- Remove the deprecated `BaseHandler` object. ([\#11005](https://github.com/matrix-org/synapse/issues/11005))
- Bump mypy version for CI to 0.910, and pull in new type stubs for dependencies. ([\#11006](https://github.com/matrix-org/synapse/issues/11006))
- Fix CI to run the unit tests without optional deps. ([\#11017](https://github.com/matrix-org/synapse/issues/11017))
- Ensure that cache config tests do not share state. ([\#11019](https://github.com/matrix-org/synapse/issues/11019))
- Add additional type hints to `synapse.server_notices`. ([\#11021](https://github.com/matrix-org/synapse/issues/11021))
- Add additional type hints for `synapse.push`. ([\#11023](https://github.com/matrix-org/synapse/issues/11023))
- When installing the optional developer dependencies, also include the dependencies needed for type-checking and unit testing. ([\#11034](https://github.com/matrix-org/synapse/issues/11034))
- Remove unnecessary list comprehension from `synapse_port_db` to satisfy code style requirements. ([\#11043](https://github.com/matrix-org/synapse/issues/11043))


Synapse 1.44.0 (2021-10-05)
===========================

No significant changes since 1.44.0rc3.


Synapse 1.44.0rc3 (2021-10-04)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse v1.40.0 where changing a user's display name or avatar in a restricted room would cause an authentication error. ([\#10933](https://github.com/matrix-org/synapse/issues/10933))
- Fix `/admin/whois/{user_id}` endpoint, which was broken in v1.44.0rc1. ([\#10968](https://github.com/matrix-org/synapse/issues/10968))


Synapse 1.44.0rc2 (2021-09-30)
==============================

Bugfixes
--------

- Fix a bug introduced in v1.44.0rc1 which caused the experimental [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` endpoint to return a 500 error. ([\#10938](https://github.com/matrix-org/synapse/issues/10938))
- Fix a bug introduced in v1.44.0rc1 which prevented sending presence events to application services. ([\#10944](https://github.com/matrix-org/synapse/issues/10944))


Improved Documentation
----------------------

- Minor updates to the installation instructions. ([\#10919](https://github.com/matrix-org/synapse/issues/10919))


Synapse 1.44.0rc1 (2021-09-29)
==============================

Features
--------

- Only allow the [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send?chunk_id=xxx` endpoint to connect to an already existing insertion event. ([\#10776](https://github.com/matrix-org/synapse/issues/10776))
- Improve oEmbed URL previews by processing the author name, photo, and video information. ([\#10814](https://github.com/matrix-org/synapse/issues/10814), [\#10819](https://github.com/matrix-org/synapse/issues/10819))
- Speed up responding with large JSON objects to requests. ([\#10868](https://github.com/matrix-org/synapse/issues/10868), [\#10905](https://github.com/matrix-org/synapse/issues/10905))
- Add a `user_may_create_room_with_invites` spam checker callback to allow modules to allow or deny a room creation request based on the invites and/or 3PID invites it includes. ([\#10898](https://github.com/matrix-org/synapse/issues/10898))


Bugfixes
--------

- Fix a long-standing bug that caused an `AssertionError` when purging history in certain rooms. Contributed by @Kokokokoka. ([\#10690](https://github.com/matrix-org/synapse/issues/10690))
- Fix a long-standing bug which caused deactivated users that were later reactivated to be missing from the user directory. ([\#10782](https://github.com/matrix-org/synapse/issues/10782))
- Fix a long-standing bug that caused unbanning a user by sending a membership event to fail. Contributed by @aaronraimist. ([\#10807](https://github.com/matrix-org/synapse/issues/10807))
- Fix a long-standing bug where logging contexts would go missing when federation requests time out. ([\#10810](https://github.com/matrix-org/synapse/issues/10810))
- Fix a long-standing bug causing an error in the deprecated `/initialSync` endpoint when using the undocumented `from` and `to` parameters. ([\#10827](https://github.com/matrix-org/synapse/issues/10827))
- Fix a bug causing the `remove_stale_pushers` background job to repeatedly fail and log errors. This bug affected Synapse servers that had been upgraded from version 1.28 or older and are using SQLite. ([\#10843](https://github.com/matrix-org/synapse/issues/10843))
- Fix a long-standing bug in Unicode support of the room search admin API breaking search for rooms with non-ASCII characters. ([\#10859](https://github.com/matrix-org/synapse/issues/10859))
- Fix a bug introduced in Synapse 1.37.0 which caused `knock` membership events which we sent to remote servers to be incorrectly stored in the local database. ([\#10873](https://github.com/matrix-org/synapse/issues/10873))
- Fix invalidating one-time key count cache after claiming keys. The bug was introduced in Synapse v1.41.0. Contributed by Tulir at Beeper. ([\#10875](https://github.com/matrix-org/synapse/issues/10875))
- Fix a long-standing bug causing application service users to be subject to MAU blocking if the MAU limit had been reached, even if configured not to be blocked. ([\#10881](https://github.com/matrix-org/synapse/issues/10881))
- Fix a long-standing bug which could cause events pulled over federation to be incorrectly rejected. ([\#10907](https://github.com/matrix-org/synapse/issues/10907))
- Fix a long-standing bug causing URL cache files to be stored in storage providers. Server admins may safely delete the `url_cache/` and `url_cache_thumbnails/` directories from any configured storage providers to reclaim space. ([\#10911](https://github.com/matrix-org/synapse/issues/10911))
- Fix a long-standing bug leading to race conditions when creating media store and config directories. ([\#10913](https://github.com/matrix-org/synapse/issues/10913))


Improved Documentation
----------------------

- Fix some crashes in the Module API example code, by adding JSON encoding/decoding. ([\#10845](https://github.com/matrix-org/synapse/issues/10845))
- Add developer documentation about experimental configuration flags. ([\#10865](https://github.com/matrix-org/synapse/issues/10865))
- Properly remove deleted files from GitHub pages when generating the documentation. ([\#10869](https://github.com/matrix-org/synapse/issues/10869))


Internal Changes
----------------

- Fix GitHub Actions config so we can run sytest on synapse from parallel branches. ([\#10659](https://github.com/matrix-org/synapse/issues/10659))
- Split out [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) meta events to their own fields in the `/batch_send` response. ([\#10777](https://github.com/matrix-org/synapse/issues/10777))
- Add missing type hints to REST servlets. ([\#10785](https://github.com/matrix-org/synapse/issues/10785), [\#10817](https://github.com/matrix-org/synapse/issues/10817))
- Simplify the internal logic which maintains the user directory database tables. ([\#10796](https://github.com/matrix-org/synapse/issues/10796))
- Use direct references to config flags. ([\#10812](https://github.com/matrix-org/synapse/issues/10812), [\#10885](https://github.com/matrix-org/synapse/issues/10885), [\#10893](https://github.com/matrix-org/synapse/issues/10893), [\#10897](https://github.com/matrix-org/synapse/issues/10897))
- Specify the type of token in generic "Invalid token" error messages. ([\#10815](https://github.com/matrix-org/synapse/issues/10815))
- Make `StateFilter` frozen so it is hashable. ([\#10816](https://github.com/matrix-org/synapse/issues/10816))
- Fix a long-standing bug where an `m.room.message` event containing a null byte would cause an internal server error. ([\#10820](https://github.com/matrix-org/synapse/issues/10820))
- Add type hints to the state database. ([\#10823](https://github.com/matrix-org/synapse/issues/10823))
- Opt out of cache expiry for `get_users_who_share_room_with_user`, to hopefully improve `/sync` performance when you
  haven't synced recently. ([\#10826](https://github.com/matrix-org/synapse/issues/10826))
- Track cache eviction rates more finely in Prometheus's monitoring. ([\#10829](https://github.com/matrix-org/synapse/issues/10829))
- Add missing type hints to `synapse.handlers`. ([\#10831](https://github.com/matrix-org/synapse/issues/10831), [\#10856](https://github.com/matrix-org/synapse/issues/10856))
- Extend the Module API to let plug-ins check whether an ID is local and to access IP + User Agent data. ([\#10833](https://github.com/matrix-org/synapse/issues/10833))
- Factor out PNG image data to a constant to be used in several tests. ([\#10834](https://github.com/matrix-org/synapse/issues/10834))
- Add a test to ensure state events sent by modules get persisted correctly. ([\#10835](https://github.com/matrix-org/synapse/issues/10835))
- Rename [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) fields and event types from `chunk` to `batch` to match the `/batch_send` endpoint. ([\#10838](https://github.com/matrix-org/synapse/issues/10838))
- Rename [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` query parameter from `?prev_event` to more obvious usage with `?prev_event_id`. ([\#10839](https://github.com/matrix-org/synapse/issues/10839))
- Add type hints to `synapse.http.site`. ([\#10867](https://github.com/matrix-org/synapse/issues/10867))
- Include outlier status when we log V2 or V3 events. ([\#10879](https://github.com/matrix-org/synapse/issues/10879))
- Break down Grafana's cache expiry time series based on reason for eviction, c.f. [\#10829](https://github.com/matrix-org/synapse/issues/10829). ([\#10880](https://github.com/matrix-org/synapse/issues/10880))
- Clean up some of the federation event authentication code for clarity. ([\#10883](https://github.com/matrix-org/synapse/issues/10883), [\#10884](https://github.com/matrix-org/synapse/issues/10884), [\#10896](https://github.com/matrix-org/synapse/issues/10896), [\#10901](https://github.com/matrix-org/synapse/issues/10901))
- Allow the `.` and `~` characters when creating registration tokens as per the change to [MSC3231](https://github.com/matrix-org/matrix-doc/pull/3231). ([\#10887](https://github.com/matrix-org/synapse/issues/10887))
- Clean up some unnecessary parentheses in places around the codebase. ([\#10889](https://github.com/matrix-org/synapse/issues/10889))
- Improve type hinting in the user directory code. ([\#10891](https://github.com/matrix-org/synapse/issues/10891))
- Update development testing script `test_postgresql.sh` to use a supported Python version and make re-runs quicker. ([\#10906](https://github.com/matrix-org/synapse/issues/10906))
- Document and summarize changes in schema version `61` – `64`. ([\#10917](https://github.com/matrix-org/synapse/issues/10917))
- Update release script to sign the newly created git tags. ([\#10925](https://github.com/matrix-org/synapse/issues/10925))
- Fix Debian builds due to `dh-virtualenv` no longer being able to build their docs. ([\#10931](https://github.com/matrix-org/synapse/issues/10931))


Synapse 1.43.0 (2021-09-21)
===========================

This release drops support for the deprecated, unstable API for [MSC2858 (Multiple SSO Identity Providers)](https://github.com/matrix-org/matrix-doc/blob/master/proposals/2858-Multiple-SSO-Identity-Providers.md#unstable-prefix), as well as the undocumented `experimental.msc2858_enabled` config option. Client authors should update their clients to use the stable API, available since Synapse 1.30.

The documentation has been updated with configuration for routing `/spaces`, `/hierarchy` and `/summary` to workers. See [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.43/docs/upgrade.md#upgrading-to-v1430) for more details.

No significant changes since 1.43.0rc2.

Synapse 1.43.0rc2 (2021-09-17)
==============================

Bugfixes
--------

- Added opentracing logging to help debug [\#9424](https://github.com/matrix-org/synapse/issues/9424). ([\#10828](https://github.com/matrix-org/synapse/issues/10828))


Synapse 1.43.0rc1 (2021-09-14)
==============================

Features
--------

- Allow room creators to send historical events specified by [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) in existing room versions. ([\#10566](https://github.com/matrix-org/synapse/issues/10566))
- Add config option to use non-default manhole password and keys. ([\#10643](https://github.com/matrix-org/synapse/issues/10643))
- Skip final GC at shutdown to improve restart performance. ([\#10712](https://github.com/matrix-org/synapse/issues/10712))
- Allow configuration of the oEmbed URLs used for URL previews. ([\#10714](https://github.com/matrix-org/synapse/issues/10714), [\#10759](https://github.com/matrix-org/synapse/issues/10759))
- Prefer [room version 9](https://github.com/matrix-org/matrix-doc/pull/3375) for restricted rooms per the [room version capabilities](https://github.com/matrix-org/matrix-doc/pull/3244) API. ([\#10772](https://github.com/matrix-org/synapse/issues/10772))


Bugfixes
--------

- Fix a long-standing bug where room avatars were not included in email notifications. ([\#10658](https://github.com/matrix-org/synapse/issues/10658))
- Fix a bug where the ordering algorithm was skipping the `origin_server_ts` step in the spaces summary resulting in unstable room orderings. ([\#10730](https://github.com/matrix-org/synapse/issues/10730))
- Fix edge case when persisting events into a room where there are multiple events we previously hadn't calculated auth chains for (and hadn't marked as needing to be calculated). ([\#10743](https://github.com/matrix-org/synapse/issues/10743))
- Fix a bug which prevented calls to `/createRoom` that included the `room_alias_name` parameter from being handled by worker processes. ([\#10757](https://github.com/matrix-org/synapse/issues/10757))
- Fix a bug which prevented user registration via SSO to require consent tracking for SSO mapping providers that don't prompt for Matrix ID selection. Contributed by @AndrewFerr. ([\#10733](https://github.com/matrix-org/synapse/issues/10733))
- Only return the stripped state events for the `m.space.child` events in a room for the spaces summary from [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#10760](https://github.com/matrix-org/synapse/issues/10760))
- Properly handle room upgrades of spaces. ([\#10774](https://github.com/matrix-org/synapse/issues/10774))
- Fix a bug which generated invalid homeserver config when the `frontend_proxy` worker type was passed to the Synapse Worker-based Complement image. ([\#10783](https://github.com/matrix-org/synapse/issues/10783))


Improved Documentation
----------------------

- Minor fix to the `media_repository` developer documentation. Contributed by @cuttingedge1109. ([\#10556](https://github.com/matrix-org/synapse/issues/10556))
- Update the documentation to note that the `/spaces` and `/hierarchy` endpoints can be routed to workers. ([\#10648](https://github.com/matrix-org/synapse/issues/10648))
- Clarify admin API documentation on undoing room deletions. ([\#10735](https://github.com/matrix-org/synapse/issues/10735))
- Split up the modules documentation and add examples for module developers. ([\#10758](https://github.com/matrix-org/synapse/issues/10758))
- Correct 2 typographical errors in the [Log Contexts documentation](https://matrix-org.github.io/synapse/latest/log_contexts.html). ([\#10795](https://github.com/matrix-org/synapse/issues/10795))
- Fix a wording mistake in the sample configuration. Contributed by @bramvdnheuvel:nltrix.net. ([\#10804](https://github.com/matrix-org/synapse/issues/10804))


Deprecations and Removals
-------------------------

- Remove the [unstable MSC2858 API](https://github.com/matrix-org/matrix-doc/blob/master/proposals/2858-Multiple-SSO-Identity-Providers.md#unstable-prefix), including the undocumented `experimental.msc2858_enabled` config option. The unstable API has been deprecated since Synapse 1.35. Client authors should update their clients to use the stable API introduced in Synapse 1.30 if they have not already done so. ([\#10693](https://github.com/matrix-org/synapse/issues/10693))


Internal Changes
----------------

- Add OpenTracing logging to help debug stuck messages (as described by issue [#9424](https://github.com/matrix-org/synapse/issues/9424)). ([\#10704](https://github.com/matrix-org/synapse/issues/10704))
- Add type annotations to the `synapse.util` package. ([\#10601](https://github.com/matrix-org/synapse/issues/10601))
- Ensure `rooms.creator` field is always populated for easy lookup in [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) usage later. ([\#10697](https://github.com/matrix-org/synapse/issues/10697))
- Add missing type hints to REST servlets. ([\#10707](https://github.com/matrix-org/synapse/issues/10707), [\#10728](https://github.com/matrix-org/synapse/issues/10728), [\#10736](https://github.com/matrix-org/synapse/issues/10736))
- Do not include rooms with unknown room versions in the spaces summary results. ([\#10727](https://github.com/matrix-org/synapse/issues/10727))
- Additional error checking for the `preset` field when creating a room. ([\#10738](https://github.com/matrix-org/synapse/issues/10738))
- Clean up some of the federation event authentication code for clarity. ([\#10744](https://github.com/matrix-org/synapse/issues/10744), [\#10745](https://github.com/matrix-org/synapse/issues/10745), [\#10746](https://github.com/matrix-org/synapse/issues/10746), [\#10771](https://github.com/matrix-org/synapse/issues/10771), [\#10773](https://github.com/matrix-org/synapse/issues/10773), [\#10781](https://github.com/matrix-org/synapse/issues/10781))
- Add an index to `presence_stream` to hopefully speed up startups a little. ([\#10748](https://github.com/matrix-org/synapse/issues/10748))
- Refactor event size checking code to simplify searching the codebase for the origins of certain error strings that are occasionally emitted. ([\#10750](https://github.com/matrix-org/synapse/issues/10750))
- Move tests relating to rooms having encryption out of the user directory tests. ([\#10752](https://github.com/matrix-org/synapse/issues/10752))
- Use `attrs` internally for the URL preview code & update documentation. ([\#10753](https://github.com/matrix-org/synapse/issues/10753))
- Minor speed ups when joining large rooms over federation. ([\#10754](https://github.com/matrix-org/synapse/issues/10754), [\#10755](https://github.com/matrix-org/synapse/issues/10755), [\#10756](https://github.com/matrix-org/synapse/issues/10756), [\#10780](https://github.com/matrix-org/synapse/issues/10780), [\#10784](https://github.com/matrix-org/synapse/issues/10784))
- Add a constant for `m.federate`. ([\#10775](https://github.com/matrix-org/synapse/issues/10775))
- Add a script to update the Debian changelog in a Docker container for systems that are not Debian-based. ([\#10778](https://github.com/matrix-org/synapse/issues/10778))
- Change the format of authenticated users in logs when a user is being puppeted by and admin user. ([\#10779](https://github.com/matrix-org/synapse/issues/10779))
- Remove fixed and flakey tests from the Sytest blacklist. ([\#10788](https://github.com/matrix-org/synapse/issues/10788))
- Improve internal details of the user directory code. ([\#10789](https://github.com/matrix-org/synapse/issues/10789))
- Use direct references to config flags. ([\#10798](https://github.com/matrix-org/synapse/issues/10798))
- Ensure the Rust reporter passes type checking with jaeger-client 4.7's type annotations. ([\#10799](https://github.com/matrix-org/synapse/issues/10799))


Synapse 1.42.0 (2021-09-07)
===========================

This version of Synapse removes deprecated room-management admin APIs, removes out-of-date email pushers, and improves error handling for fallback templates for user-interactive authentication. For more information on these points, server administrators are encouraged to read [the upgrade notes](docs/upgrade.md#upgrading-to-v1420).

No significant changes since 1.42.0rc2.


Synapse 1.42.0rc2 (2021-09-06)
==============================

Features
--------

- Support room version 9 from [MSC3375](https://github.com/matrix-org/matrix-doc/pull/3375). ([\#10747](https://github.com/matrix-org/synapse/issues/10747))


Internal Changes
----------------

- Print a warning when using one of the deprecated `template_dir` settings. ([\#10768](https://github.com/matrix-org/synapse/issues/10768))


Synapse 1.42.0rc1 (2021-09-01)
==============================

Features
--------

- Add support for [MSC3231](https://github.com/matrix-org/matrix-doc/pull/3231): Token authenticated registration. Users can be required to submit a token during registration to authenticate themselves. Contributed by Callum Brown. ([\#10142](https://github.com/matrix-org/synapse/issues/10142))
- Add support for [MSC3283](https://github.com/matrix-org/matrix-doc/pull/3283): Expose `enable_set_displayname` in capabilities. ([\#10452](https://github.com/matrix-org/synapse/issues/10452))
- Port the `PresenceRouter` module interface to the new generic interface. ([\#10524](https://github.com/matrix-org/synapse/issues/10524))
- Add pagination to the spaces summary based on updates to [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#10613](https://github.com/matrix-org/synapse/issues/10613), [\#10725](https://github.com/matrix-org/synapse/issues/10725))


Bugfixes
--------

- Validate new `m.room.power_levels` events. Contributed by @aaronraimist. ([\#10232](https://github.com/matrix-org/synapse/issues/10232))
- Display an error on User-Interactive Authentication fallback pages when authentication fails. Contributed by Callum Brown. ([\#10561](https://github.com/matrix-org/synapse/issues/10561))
- Remove pushers when deleting an e-mail address from an account. Pushers for old unlinked emails will also be deleted. ([\#10581](https://github.com/matrix-org/synapse/issues/10581), [\#10734](https://github.com/matrix-org/synapse/issues/10734))
- Reject Client-Server `/keys/query` requests which provide `device_ids` incorrectly. ([\#10593](https://github.com/matrix-org/synapse/issues/10593))
- Rooms with unsupported room versions are no longer returned via `/sync`. ([\#10644](https://github.com/matrix-org/synapse/issues/10644))
- Enforce the maximum length for per-room display names and avatar URLs. ([\#10654](https://github.com/matrix-org/synapse/issues/10654))
- Fix a bug which caused the `synapse_user_logins_total` Prometheus metric not to be correctly initialised on restart. ([\#10677](https://github.com/matrix-org/synapse/issues/10677))
- Improve `ServerNoticeServlet` to avoid duplicate requests and add unit tests. ([\#10679](https://github.com/matrix-org/synapse/issues/10679))
- Fix long-standing issue which caused an error when a thumbnail is requested and there are multiple thumbnails with the same quality rating. ([\#10684](https://github.com/matrix-org/synapse/issues/10684))
- Fix a regression introduced in v1.41.0 which affected the performance of concurrent fetches of large sets of events, in extreme cases causing the process to hang. ([\#10703](https://github.com/matrix-org/synapse/issues/10703))
- Fix a regression introduced in Synapse 1.41 which broke email transmission on Systems using older versions of the Twisted library. ([\#10713](https://github.com/matrix-org/synapse/issues/10713))


Improved Documentation
----------------------

- Add documentation on how to connect Django with Synapse using OpenID Connect and django-oauth-toolkit. Contributed by @HugoDelval. ([\#10192](https://github.com/matrix-org/synapse/issues/10192))
- Advertise https://matrix-org.github.io/synapse documentation in the `README` and `CONTRIBUTING` files. ([\#10595](https://github.com/matrix-org/synapse/issues/10595))
- Fix some of the titles not rendering in the OpenID Connect documentation. ([\#10639](https://github.com/matrix-org/synapse/issues/10639))
- Minor clarifications to the documentation for reverse proxies. ([\#10708](https://github.com/matrix-org/synapse/issues/10708))
- Remove table of contents from the top of installation and contributing documentation pages. ([\#10711](https://github.com/matrix-org/synapse/issues/10711))


Deprecations and Removals
-------------------------

- Remove deprecated Shutdown Room and Purge Room Admin API. ([\#8830](https://github.com/matrix-org/synapse/issues/8830))


Internal Changes
----------------

- Improve type hints for the proxy agent and SRV resolver modules. Contributed by @dklimpel. ([\#10608](https://github.com/matrix-org/synapse/issues/10608))
- Clean up some of the federation event authentication code for clarity. ([\#10614](https://github.com/matrix-org/synapse/issues/10614), [\#10615](https://github.com/matrix-org/synapse/issues/10615), [\#10624](https://github.com/matrix-org/synapse/issues/10624), [\#10640](https://github.com/matrix-org/synapse/issues/10640))
- Add a comment asking developers to leave a reason when bumping the database schema version. ([\#10621](https://github.com/matrix-org/synapse/issues/10621))
- Remove not needed database updates in modify user admin API. ([\#10627](https://github.com/matrix-org/synapse/issues/10627))
- Convert room member storage tuples to `attrs` classes. ([\#10629](https://github.com/matrix-org/synapse/issues/10629), [\#10642](https://github.com/matrix-org/synapse/issues/10642))
- Use auto-attribs for the attrs classes used in sync. ([\#10630](https://github.com/matrix-org/synapse/issues/10630))
- Make `backfill` and `get_missing_events` use the same codepath. ([\#10645](https://github.com/matrix-org/synapse/issues/10645))
- Improve the performance of the `/hierarchy` API (from [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946)) by caching responses received over federation. ([\#10647](https://github.com/matrix-org/synapse/issues/10647))
- Run a nightly CI build against Twisted trunk. ([\#10651](https://github.com/matrix-org/synapse/issues/10651), [\#10672](https://github.com/matrix-org/synapse/issues/10672))
- Do not print out stack traces for network errors when fetching data over federation. ([\#10662](https://github.com/matrix-org/synapse/issues/10662))
- Simplify tests for device admin rest API. ([\#10664](https://github.com/matrix-org/synapse/issues/10664))
- Add missing type hints to REST servlets. ([\#10665](https://github.com/matrix-org/synapse/issues/10665), [\#10666](https://github.com/matrix-org/synapse/issues/10666), [\#10674](https://github.com/matrix-org/synapse/issues/10674))
- Flatten the `tests.synapse.rests` package by moving the contents of `v1` and `v2_alpha` into the parent. ([\#10667](https://github.com/matrix-org/synapse/issues/10667))
- Update `complement.sh` to rebuild the base Docker image when run with workers. ([\#10686](https://github.com/matrix-org/synapse/issues/10686))
- Split the event-processing methods in `FederationHandler` into a separate `FederationEventHandler`. ([\#10692](https://github.com/matrix-org/synapse/issues/10692))
- Remove unused `compare_digest` function. ([\#10706](https://github.com/matrix-org/synapse/issues/10706))


Synapse 1.41.1 (2021-08-31)
===========================

Due to the two security issues highlighted below, server administrators are encouraged to update Synapse. We are not aware of these vulnerabilities being exploited in the wild.

Security advisory
-----------------

The following issues are fixed in v1.41.1.

- **[GHSA-3x4c-pq33-4w3q](https://github.com/matrix-org/synapse/security/advisories/GHSA-3x4c-pq33-4w3q) / [CVE-2021-39164](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39164): Enumerating a private room's list of members and their display names.**

  If an unauthorized user both knows the Room ID of a private room *and* that room's history visibility is set to `shared`, then they may be able to enumerate the room's members, including their display names.

  The unauthorized user must be on the same homeserver as a user who is a member of the target room.

  Fixed by [52c7a51cf](https://github.com/matrix-org/synapse/commit/52c7a51cf).

- **[GHSA-jj53-8fmw-f2w2](https://github.com/matrix-org/synapse/security/advisories/GHSA-jj53-8fmw-f2w2) / [CVE-2021-39163](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39163): Disclosing a private room's name, avatar, topic, and number of members.**

  If an unauthorized user knows the Room ID of a private room, then its name, avatar, topic, and number of members may be disclosed through Group / Community features.

  The unauthorized user must be on the same homeserver as a user who is a member of the target room, and their homeserver must allow non-administrators to create groups (`enable_group_creation` in the Synapse configuration; off by default).

  Fixed by [cb35df940a](https://github.com/matrix-org/synapse/commit/cb35df940a), [\#10723](https://github.com/matrix-org/synapse/issues/10723).

Bugfixes
--------

- Fix a regression introduced in Synapse 1.41 which broke email transmission on systems using older versions of the Twisted library. ([\#10713](https://github.com/matrix-org/synapse/issues/10713))

Synapse 1.41.0 (2021-08-24)
===========================

This release adds support for Debian 12 (Bookworm), but **removes support for Ubuntu 20.10 (Groovy Gorilla)**, which reached End of Life last month.

Note that when using workers the `/_synapse/admin/v1/users/{userId}/media` must now be handled by media workers. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html) for more information.


Features
--------

- Enable room capabilities ([MSC3244](https://github.com/matrix-org/matrix-doc/pull/3244)) by default and set room version 8 as the preferred room version when creating restricted rooms. ([\#10571](https://github.com/matrix-org/synapse/issues/10571))


Synapse 1.41.0rc1 (2021-08-18)
==============================

Features
--------

- Add `get_userinfo_by_id` method to ModuleApi. ([\#9581](https://github.com/matrix-org/synapse/issues/9581))
- Initial local support for [MSC3266](https://github.com/matrix-org/synapse/pull/10394), Room Summary over the unstable `/rooms/{roomIdOrAlias}/summary` API. ([\#10394](https://github.com/matrix-org/synapse/issues/10394))
- Experimental support for [MSC3288](https://github.com/matrix-org/matrix-doc/pull/3288), sending `room_type` to the identity server for 3pid invites over the `/store-invite` API. ([\#10435](https://github.com/matrix-org/synapse/issues/10435))
- Add support for sending federation requests through a proxy. Contributed by @Bubu and @dklimpel. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html) for more information. ([\#10596](https://github.com/matrix-org/synapse/issues/10596)). ([\#10475](https://github.com/matrix-org/synapse/issues/10475))
- Add support for "marker" events which makes historical events discoverable for servers that already have all of the scrollback history (part of [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716)). ([\#10498](https://github.com/matrix-org/synapse/issues/10498))
- Add a configuration setting for the time a `/sync` response is cached for. ([\#10513](https://github.com/matrix-org/synapse/issues/10513))
- The default logging handler for new installations is now `PeriodicallyFlushingMemoryHandler`, a buffered logging handler which periodically flushes itself. ([\#10518](https://github.com/matrix-org/synapse/issues/10518))
- Add support for new redaction rules for historical events specified in [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716). ([\#10538](https://github.com/matrix-org/synapse/issues/10538))
- Add a setting to disable TLS when sending email. ([\#10546](https://github.com/matrix-org/synapse/issues/10546))
- Add pagination to the spaces summary based on updates to [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#10549](https://github.com/matrix-org/synapse/issues/10549), [\#10560](https://github.com/matrix-org/synapse/issues/10560), [\#10569](https://github.com/matrix-org/synapse/issues/10569), [\#10574](https://github.com/matrix-org/synapse/issues/10574), [\#10575](https://github.com/matrix-org/synapse/issues/10575), [\#10579](https://github.com/matrix-org/synapse/issues/10579), [\#10583](https://github.com/matrix-org/synapse/issues/10583))
- Admin API to delete several media for a specific user. Contributed by @dklimpel. ([\#10558](https://github.com/matrix-org/synapse/issues/10558), [\#10628](https://github.com/matrix-org/synapse/issues/10628))
- Add support for routing `/createRoom` to workers. ([\#10564](https://github.com/matrix-org/synapse/issues/10564))
- Update the Synapse Grafana dashboard. ([\#10570](https://github.com/matrix-org/synapse/issues/10570))
- Add an admin API (`GET /_synapse/admin/username_available`) to check if a username is available (regardless of registration settings). ([\#10578](https://github.com/matrix-org/synapse/issues/10578))
- Allow editing a user's `external_ids` via the "Edit User" admin API. Contributed by @dklimpel. ([\#10598](https://github.com/matrix-org/synapse/issues/10598))
- The Synapse manhole no longer needs coroutines to be wrapped in `defer.ensureDeferred`. ([\#10602](https://github.com/matrix-org/synapse/issues/10602))
- Add option to allow modules to run periodic tasks on all instances, rather than just the one configured to run background tasks. ([\#10638](https://github.com/matrix-org/synapse/issues/10638))


Bugfixes
--------

- Add some clarification to the sample config file. Contributed by @Kentokamoto. ([\#10129](https://github.com/matrix-org/synapse/issues/10129))
- Fix a long-standing bug where protocols which are not implemented by any appservices were incorrectly returned via `GET /_matrix/client/r0/thirdparty/protocols`. ([\#10532](https://github.com/matrix-org/synapse/issues/10532))
- Fix exceptions in logs when failing to get remote room list. ([\#10541](https://github.com/matrix-org/synapse/issues/10541))
- Fix longstanding bug which caused the user's presence "status message" to be reset when the user went offline. Contributed by @dklimpel. ([\#10550](https://github.com/matrix-org/synapse/issues/10550))
- Allow public rooms to be previewed in the spaces summary APIs from [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#10580](https://github.com/matrix-org/synapse/issues/10580))
- Fix a bug introduced in v1.37.1 where an error could occur in the asynchronous processing of PDUs when the queue was empty. ([\#10592](https://github.com/matrix-org/synapse/issues/10592))
- Fix errors on /sync when read receipt data is a string. Only affects homeservers with the experimental flag for [MSC2285](https://github.com/matrix-org/matrix-doc/pull/2285) enabled. Contributed by @SimonBrandner. ([\#10606](https://github.com/matrix-org/synapse/issues/10606))
- Additional validation for the spaces summary API to avoid errors like `ValueError: Stop argument for islice() must be None or an integer`. The missing validation has existed since v1.31.0. ([\#10611](https://github.com/matrix-org/synapse/issues/10611))
- Revert behaviour introduced in v1.38.0 that strips `org.matrix.msc2732.device_unused_fallback_key_types` from `/sync` when its value is empty. This field should instead always be present according to [MSC2732](https://github.com/matrix-org/matrix-doc/blob/master/proposals/2732-olm-fallback-keys.md). ([\#10623](https://github.com/matrix-org/synapse/issues/10623))


Improved Documentation
----------------------

- Add documentation for configuring a forward proxy. ([\#10443](https://github.com/matrix-org/synapse/issues/10443))
- Updated the reverse proxy documentation to highlight the homserver configuration that is needed to make Synapse aware that is is intentionally reverse proxied. ([\#10551](https://github.com/matrix-org/synapse/issues/10551))
- Update CONTRIBUTING.md to fix index links and the instructions for SyTest in docker. ([\#10599](https://github.com/matrix-org/synapse/issues/10599))


Deprecations and Removals
-------------------------

- No longer build `.deb` packages for Ubuntu 20.10 Groovy Gorilla, which has now EOLed. ([\#10588](https://github.com/matrix-org/synapse/issues/10588))
- The `template_dir` configuration settings in the `sso`, `account_validity` and `email` sections of the configuration file are now deprecated in favour of the global `templates.custom_template_directory` setting. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html) for more information. ([\#10596](https://github.com/matrix-org/synapse/issues/10596))


Internal Changes
----------------

- Improve event caching mechanism to avoid having multiple copies of an event in memory at a time. ([\#10119](https://github.com/matrix-org/synapse/issues/10119))
- Reduce errors in PostgreSQL logs due to concurrent serialization errors. ([\#10504](https://github.com/matrix-org/synapse/issues/10504))
- Include room ID in ignored EDU log messages. Contributed by @ilmari. ([\#10507](https://github.com/matrix-org/synapse/issues/10507))
- Add pagination to the spaces summary based on updates to [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946). ([\#10527](https://github.com/matrix-org/synapse/issues/10527), [\#10530](https://github.com/matrix-org/synapse/issues/10530))
- Fix CI to not break when run against branches rather than pull requests. ([\#10529](https://github.com/matrix-org/synapse/issues/10529))
- Mark all events stemming from the [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) `/batch_send` endpoint as historical. ([\#10537](https://github.com/matrix-org/synapse/issues/10537))
- Clean up some of the federation event authentication code for clarity. ([\#10539](https://github.com/matrix-org/synapse/issues/10539), [\#10591](https://github.com/matrix-org/synapse/issues/10591))
- Convert `Transaction` and `Edu` objects to attrs. ([\#10542](https://github.com/matrix-org/synapse/issues/10542))
- Update `/batch_send` endpoint to only return `state_events` created by the `state_events_from_before` passed in. ([\#10552](https://github.com/matrix-org/synapse/issues/10552))
- Update contributing.md to warn against rebasing an open PR. ([\#10563](https://github.com/matrix-org/synapse/issues/10563))
- Remove the unused public rooms replication stream. ([\#10565](https://github.com/matrix-org/synapse/issues/10565))
- Clarify error message when failing to join a restricted room. ([\#10572](https://github.com/matrix-org/synapse/issues/10572))
- Remove references to BuildKite in favour of GitHub Actions. ([\#10573](https://github.com/matrix-org/synapse/issues/10573))
- Move `/batch_send` endpoint defined by [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) to the `/v2_alpha` directory. ([\#10576](https://github.com/matrix-org/synapse/issues/10576))
- Allow multiple custom directories in `read_templates`. ([\#10587](https://github.com/matrix-org/synapse/issues/10587))
- Re-organize the `synapse.federation.transport.server` module to create smaller files. ([\#10590](https://github.com/matrix-org/synapse/issues/10590))
- Flatten the `synapse.rest.client` package by moving the contents of `v1` and `v2_alpha` into the parent. ([\#10600](https://github.com/matrix-org/synapse/issues/10600))
- Build Debian packages for Debian 12 (Bookworm). ([\#10612](https://github.com/matrix-org/synapse/issues/10612))
- Fix up a couple of links to the database schema documentation. ([\#10620](https://github.com/matrix-org/synapse/issues/10620))
- Fix a broken link to the upgrade notes. ([\#10631](https://github.com/matrix-org/synapse/issues/10631))


Synapse 1.40.0 (2021-08-10)
===========================

No significant changes.


Synapse 1.40.0rc3 (2021-08-09)
==============================

Features
--------

- Support [MSC3289: room version 8](https://github.com/matrix-org/matrix-doc/pull/3289). ([\#10449](https://github.com/matrix-org/synapse/issues/10449))


Bugfixes
--------

- Mark the experimental room version from [MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716) as unstable. ([\#10449](https://github.com/matrix-org/synapse/issues/10449))


Improved Documentation
----------------------

- Fix broken links in `upgrade.md`. Contributed by @dklimpel. ([\#10543](https://github.com/matrix-org/synapse/issues/10543))


Synapse 1.40.0rc2 (2021-08-04)
==============================

Bugfixes
--------

- Fix the `PeriodicallyFlushingMemoryHandler` inhibiting application shutdown because of its background thread. ([\#10517](https://github.com/matrix-org/synapse/issues/10517))
- Fix a bug introduced in Synapse v1.40.0rc1 that could cause Synapse to respond with an error when clients would update read receipts. ([\#10531](https://github.com/matrix-org/synapse/issues/10531))


Internal Changes
----------------

- Fix release script to open the correct URL for the release. ([\#10516](https://github.com/matrix-org/synapse/issues/10516))


Synapse 1.40.0rc1 (2021-08-03)
==============================

Features
--------

- Add support for [MSC2033](https://github.com/matrix-org/matrix-doc/pull/2033): `device_id` on `/account/whoami`. ([\#9918](https://github.com/matrix-org/synapse/issues/9918))
- Update support for [MSC2716 - Incrementally importing history into existing rooms](https://github.com/matrix-org/matrix-doc/pull/2716). ([\#10245](https://github.com/matrix-org/synapse/issues/10245), [\#10432](https://github.com/matrix-org/synapse/issues/10432), [\#10463](https://github.com/matrix-org/synapse/issues/10463))
- Update support for [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083) to consider changes in the MSC around which servers can issue join events. ([\#10254](https://github.com/matrix-org/synapse/issues/10254), [\#10447](https://github.com/matrix-org/synapse/issues/10447), [\#10489](https://github.com/matrix-org/synapse/issues/10489))
- Initial support for [MSC3244](https://github.com/matrix-org/matrix-doc/pull/3244), Room version capabilities over the /capabilities API. ([\#10283](https://github.com/matrix-org/synapse/issues/10283))
- Add a buffered logging handler which periodically flushes itself. ([\#10407](https://github.com/matrix-org/synapse/issues/10407), [\#10515](https://github.com/matrix-org/synapse/issues/10515))
- Add support for https connections to a proxy server. Contributed by @Bubu and @dklimpel. ([\#10411](https://github.com/matrix-org/synapse/issues/10411))
- Support for [MSC2285 (hidden read receipts)](https://github.com/matrix-org/matrix-doc/pull/2285). Contributed by @SimonBrandner. ([\#10413](https://github.com/matrix-org/synapse/issues/10413))
- Email notifications now state whether an invitation is to a room or a space. ([\#10426](https://github.com/matrix-org/synapse/issues/10426))
- Allow setting transaction limit for database connections. ([\#10440](https://github.com/matrix-org/synapse/issues/10440), [\#10511](https://github.com/matrix-org/synapse/issues/10511))
- Add `creation_ts` to "list users" admin API. ([\#10448](https://github.com/matrix-org/synapse/issues/10448))


Bugfixes
--------

- Improve character set detection in URL previews by supporting underscores (in addition to hyphens). Contributed by @srividyut. ([\#10410](https://github.com/matrix-org/synapse/issues/10410))
- Fix events being incorrectly rejected over federation if they reference auth events that the server needed to fetch. ([\#10439](https://github.com/matrix-org/synapse/issues/10439))
- Fix `synapse_federation_server_oldest_inbound_pdu_in_staging` Prometheus metric to not report a max age of 51 years when the queue is empty. ([\#10455](https://github.com/matrix-org/synapse/issues/10455))
- Fix a bug which caused an explicit assignment of power-level 0 to a user to be misinterpreted in rare circumstances. ([\#10499](https://github.com/matrix-org/synapse/issues/10499))


Improved Documentation
----------------------

- Fix hierarchy of providers on the OpenID page. ([\#10445](https://github.com/matrix-org/synapse/issues/10445))
- Consolidate development documentation to `docs/development/`. ([\#10453](https://github.com/matrix-org/synapse/issues/10453))
- Add some developer docs to explain room DAG concepts like `outliers`, `state_groups`, `depth`, etc. ([\#10464](https://github.com/matrix-org/synapse/issues/10464))
- Document how to use Complement while developing a new Synapse feature. ([\#10483](https://github.com/matrix-org/synapse/issues/10483))


Internal Changes
----------------

- Prune inbound federation queues for a room if they get too large. ([\#10390](https://github.com/matrix-org/synapse/issues/10390))
- Add type hints to `synapse.federation.transport.client` module. ([\#10408](https://github.com/matrix-org/synapse/issues/10408))
- Remove shebang line from module files. ([\#10415](https://github.com/matrix-org/synapse/issues/10415))
- Drop backwards-compatibility code that was required to support Ubuntu Xenial. ([\#10429](https://github.com/matrix-org/synapse/issues/10429))
- Use a docker image cache for the prerequisites for the debian package build. ([\#10431](https://github.com/matrix-org/synapse/issues/10431))
- Improve servlet type hints. ([\#10437](https://github.com/matrix-org/synapse/issues/10437), [\#10438](https://github.com/matrix-org/synapse/issues/10438))
- Replace usage of `or_ignore` in `simple_insert` with `simple_upsert` usage, to stop spamming postgres logs with spurious ERROR messages. ([\#10442](https://github.com/matrix-org/synapse/issues/10442))
- Update the `tests-done` Github Actions status. ([\#10444](https://github.com/matrix-org/synapse/issues/10444), [\#10512](https://github.com/matrix-org/synapse/issues/10512))
- Update type annotations to work with forthcoming Twisted 21.7.0 release. ([\#10446](https://github.com/matrix-org/synapse/issues/10446), [\#10450](https://github.com/matrix-org/synapse/issues/10450))
- Cancel redundant GHA workflows when a new commit is pushed. ([\#10451](https://github.com/matrix-org/synapse/issues/10451))
- Mitigate media repo XSS attacks on IE11 via the non-standard X-Content-Security-Policy header. ([\#10468](https://github.com/matrix-org/synapse/issues/10468))
- Additional type hints in the state handler. ([\#10482](https://github.com/matrix-org/synapse/issues/10482))
- Update syntax used to run complement tests. ([\#10488](https://github.com/matrix-org/synapse/issues/10488))
- Fix up type annotations to work with Twisted 21.7. ([\#10490](https://github.com/matrix-org/synapse/issues/10490))
- Improve type annotations for `ObservableDeferred`. ([\#10491](https://github.com/matrix-org/synapse/issues/10491))
- Extend release script to also tag and create GitHub releases. ([\#10496](https://github.com/matrix-org/synapse/issues/10496))
- Fix a bug which caused production debian packages to be incorrectly marked as 'prerelease'. ([\#10500](https://github.com/matrix-org/synapse/issues/10500))


Synapse 1.39.0 (2021-07-29)
===========================

No significant changes.


Synapse 1.39.0rc3 (2021-07-28)
==============================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.38 which caused an exception at startup when SAML authentication was enabled. ([\#10477](https://github.com/matrix-org/synapse/issues/10477))
- Fix a long-standing bug where Synapse would not inform clients that a device had exhausted its one-time-key pool, potentially causing problems decrypting events. ([\#10485](https://github.com/matrix-org/synapse/issues/10485))
- Fix reporting old R30 stats as R30v2 stats. Introduced in v1.39.0rc1. ([\#10486](https://github.com/matrix-org/synapse/issues/10486))


Internal Changes
----------------

- Fix an error which prevented the Github Actions workflow to build the docker images from running. ([\#10461](https://github.com/matrix-org/synapse/issues/10461))
- Fix release script to correctly version debian changelog when doing RCs. ([\#10465](https://github.com/matrix-org/synapse/issues/10465))


Synapse 1.39.0rc2 (2021-07-22)
==============================

This release also includes the changes in v1.38.1.


Internal Changes
----------------

- Move docker image build to Github Actions. ([\#10416](https://github.com/matrix-org/synapse/issues/10416))


Synapse 1.38.1 (2021-07-22)
===========================

Bugfixes
--------

- Always include `device_one_time_keys_count` key in `/sync` response to work around a bug in Element Android that broke encryption for new devices. ([\#10457](https://github.com/matrix-org/synapse/issues/10457))


Synapse 1.39.0rc1 (2021-07-20)
==============================

The Third-Party Event Rules module interface has been deprecated in favour of the generic module interface introduced in Synapse v1.37.0. Support for the old interface is planned to be removed in September 2021. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html#upgrading-to-v1390) for more information.

Features
--------

- Add the ability to override the account validity feature with a module. ([\#9884](https://github.com/matrix-org/synapse/issues/9884))
- The spaces summary API now returns any joinable rooms, not only rooms which are world-readable. ([\#10298](https://github.com/matrix-org/synapse/issues/10298), [\#10305](https://github.com/matrix-org/synapse/issues/10305))
- Add a new version of the R30 phone-home metric, which removes a false impression of retention given by the old R30 metric. ([\#10332](https://github.com/matrix-org/synapse/issues/10332), [\#10427](https://github.com/matrix-org/synapse/issues/10427))
- Allow providing credentials to `http_proxy`. ([\#10360](https://github.com/matrix-org/synapse/issues/10360))


Bugfixes
--------

- Fix error while dropping locks on shutdown. Introduced in v1.38.0. ([\#10433](https://github.com/matrix-org/synapse/issues/10433))
- Add base starting insertion event when no chunk ID is specified in the historical batch send API. ([\#10250](https://github.com/matrix-org/synapse/issues/10250))
- Fix historical batch send endpoint (MSC2716) rejecting batches with messages from multiple senders. ([\#10276](https://github.com/matrix-org/synapse/issues/10276))
- Fix purging rooms that other homeservers are still sending events for. Contributed by @ilmari. ([\#10317](https://github.com/matrix-org/synapse/issues/10317))
- Fix errors during backfill caused by previously purged redaction events. Contributed by Andreas Rammhold (@andir). ([\#10343](https://github.com/matrix-org/synapse/issues/10343))
- Fix the user directory becoming broken (and noisy errors being logged) when knocking and room statistics are in use. ([\#10344](https://github.com/matrix-org/synapse/issues/10344))
- Fix newly added `synapse_federation_server_oldest_inbound_pdu_in_staging` prometheus metric to measure age rather than timestamp. ([\#10355](https://github.com/matrix-org/synapse/issues/10355))
- Fix PostgreSQL sometimes using table scans for queries against `state_groups_state` table, taking a long time and a large amount of IO. ([\#10359](https://github.com/matrix-org/synapse/issues/10359))
- Fix `make_room_admin` failing for users that have left a private room. ([\#10367](https://github.com/matrix-org/synapse/issues/10367))
- Fix a number of logged errors caused by remote servers being down. ([\#10400](https://github.com/matrix-org/synapse/issues/10400), [\#10414](https://github.com/matrix-org/synapse/issues/10414))
- Responses from `/make_{join,leave,knock}` no longer include signatures, which will turn out to be invalid after events are returned to `/send_{join,leave,knock}`. ([\#10404](https://github.com/matrix-org/synapse/issues/10404))


Improved Documentation
----------------------

- Updated installation dependencies for newer macOS versions and ARM Macs. Contributed by Luke Walsh. ([\#9971](https://github.com/matrix-org/synapse/issues/9971))
- Simplify structure of room admin API. ([\#10313](https://github.com/matrix-org/synapse/issues/10313))
- Refresh the logcontext dev documentation. ([\#10353](https://github.com/matrix-org/synapse/issues/10353)), ([\#10337](https://github.com/matrix-org/synapse/issues/10337))
- Add delegation example for caddy in the reverse proxy documentation. Contributed by @moritzdietz. ([\#10368](https://github.com/matrix-org/synapse/issues/10368))
- Fix and clarify some links in `docs` and `contrib`. ([\#10370](https://github.com/matrix-org/synapse/issues/10370)), ([\#10322](https://github.com/matrix-org/synapse/issues/10322)), ([\#10399](https://github.com/matrix-org/synapse/issues/10399))
- Make deprecation notice of the spam checker doc more obvious. ([\#10395](https://github.com/matrix-org/synapse/issues/10395))
- Add instructions on installing Debian packages for release candidates. ([\#10396](https://github.com/matrix-org/synapse/issues/10396))


Deprecations and Removals
-------------------------

- Remove functionality associated with the unused `room_stats_historical` and `user_stats_historical` tables. Contributed by @xmunoz. ([\#9721](https://github.com/matrix-org/synapse/issues/9721))
- The third-party event rules module interface is deprecated in favour of the generic module interface introduced in Synapse v1.37.0. See the [upgrade notes](https://matrix-org.github.io/synapse/latest/upgrade.html#upgrading-to-v1390) for more information. ([\#10386](https://github.com/matrix-org/synapse/issues/10386))


Internal Changes
----------------

- Convert `room_depth.min_depth` column to a `BIGINT`. ([\#10289](https://github.com/matrix-org/synapse/issues/10289))
- Add tests to characterise the current behaviour of R30 phone-home metrics. ([\#10315](https://github.com/matrix-org/synapse/issues/10315))
- Rebuild event context and auth when processing specific results from `ThirdPartyEventRules` modules. ([\#10316](https://github.com/matrix-org/synapse/issues/10316))
- Minor change to the code that populates `user_daily_visits`. ([\#10324](https://github.com/matrix-org/synapse/issues/10324))
- Re-enable Sytests that were disabled for the 1.37.1 release. ([\#10345](https://github.com/matrix-org/synapse/issues/10345), [\#10357](https://github.com/matrix-org/synapse/issues/10357))
- Run `pyupgrade` on the codebase. ([\#10347](https://github.com/matrix-org/synapse/issues/10347), [\#10348](https://github.com/matrix-org/synapse/issues/10348))
- Switch `application_services_txns.txn_id` database column to `BIGINT`. ([\#10349](https://github.com/matrix-org/synapse/issues/10349))
- Convert internal type variable syntax to reflect wider ecosystem use. ([\#10350](https://github.com/matrix-org/synapse/issues/10350), [\#10380](https://github.com/matrix-org/synapse/issues/10380), [\#10381](https://github.com/matrix-org/synapse/issues/10381), [\#10382](https://github.com/matrix-org/synapse/issues/10382), [\#10418](https://github.com/matrix-org/synapse/issues/10418))
- Make the Github Actions workflow configuration more efficient. ([\#10383](https://github.com/matrix-org/synapse/issues/10383))
- Add type hints to `get_{domain,localpart}_from_id`. ([\#10385](https://github.com/matrix-org/synapse/issues/10385))
- When building Debian packages for prerelease versions, set the Section accordingly. ([\#10391](https://github.com/matrix-org/synapse/issues/10391))
- Add type hints and comments to event auth code. ([\#10393](https://github.com/matrix-org/synapse/issues/10393))
- Stagger sending of presence update to remote servers, reducing CPU spikes caused by starting many connections to remote servers at once. ([\#10398](https://github.com/matrix-org/synapse/issues/10398))
- Remove unused `events_by_room` code (tech debt). ([\#10421](https://github.com/matrix-org/synapse/issues/10421))
- Add a github actions job which records success of other jobs. ([\#10430](https://github.com/matrix-org/synapse/issues/10430))


Synapse 1.38.0 (2021-07-13)
===========================

This release includes a database schema update which could result in elevated disk usage. See the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#upgrading-to-v1380) for more information.

No significant changes since 1.38.0rc3.


Synapse 1.38.0rc3 (2021-07-13)
==============================

Internal Changes
----------------

- Build the Debian packages in CI. ([\#10247](https://github.com/matrix-org/synapse/issues/10247), [\#10379](https://github.com/matrix-org/synapse/issues/10379))


Synapse 1.38.0rc2 (2021-07-09)
==============================

Bugfixes
--------

- Fix bug where inbound federation in a room could be delayed due to not correctly dropping a lock. Introduced in v1.37.1. ([\#10336](https://github.com/matrix-org/synapse/issues/10336))


Improved Documentation
----------------------

- Update links to documentation in the sample config. Contributed by @dklimpel. ([\#10287](https://github.com/matrix-org/synapse/issues/10287))
- Fix broken links in [INSTALL.md](INSTALL.md). Contributed by @dklimpel. ([\#10331](https://github.com/matrix-org/synapse/issues/10331))


Synapse 1.38.0rc1 (2021-07-06)
==============================

Features
--------

- Implement refresh tokens as specified by [MSC2918](https://github.com/matrix-org/matrix-doc/pull/2918). ([\#9450](https://github.com/matrix-org/synapse/issues/9450))
- Add support for evicting cache entries based on last access time. ([\#10205](https://github.com/matrix-org/synapse/issues/10205))
- Omit empty fields from the `/sync` response. Contributed by @deepbluev7. ([\#10214](https://github.com/matrix-org/synapse/issues/10214))
- Improve validation on federation `send_{join,leave,knock}` endpoints. ([\#10225](https://github.com/matrix-org/synapse/issues/10225), [\#10243](https://github.com/matrix-org/synapse/issues/10243))
- Add SSO `external_ids` to the Query User Account admin API. ([\#10261](https://github.com/matrix-org/synapse/issues/10261))
- Mark events received over federation which fail a spam check as "soft-failed". ([\#10263](https://github.com/matrix-org/synapse/issues/10263))
- Add metrics for new inbound federation staging area. ([\#10284](https://github.com/matrix-org/synapse/issues/10284))
- Add script to print information about recently registered users. ([\#10290](https://github.com/matrix-org/synapse/issues/10290))


Bugfixes
--------

- Fix a long-standing bug which meant that invite rejections and knocks were not sent out over federation in a timely manner. ([\#10223](https://github.com/matrix-org/synapse/issues/10223))
- Fix a bug introduced in v1.26.0 where only users who have set profile information could be deactivated with erasure enabled. ([\#10252](https://github.com/matrix-org/synapse/issues/10252))
- Fix a long-standing bug where Synapse would return errors after 2<sup>31</sup> events were handled by the server. ([\#10264](https://github.com/matrix-org/synapse/issues/10264), [\#10267](https://github.com/matrix-org/synapse/issues/10267), [\#10282](https://github.com/matrix-org/synapse/issues/10282), [\#10286](https://github.com/matrix-org/synapse/issues/10286), [\#10291](https://github.com/matrix-org/synapse/issues/10291), [\#10314](https://github.com/matrix-org/synapse/issues/10314), [\#10326](https://github.com/matrix-org/synapse/issues/10326))
- Fix the prometheus `synapse_federation_server_pdu_process_time` metric. Broke in v1.37.1. ([\#10279](https://github.com/matrix-org/synapse/issues/10279))
- Ensure that inbound events from federation that were being processed when Synapse was restarted get promptly processed on start up. ([\#10303](https://github.com/matrix-org/synapse/issues/10303))


Improved Documentation
----------------------

- Move the upgrade notes to [docs/upgrade.md](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md) and convert them to markdown. ([\#10166](https://github.com/matrix-org/synapse/issues/10166))
- Choose Welcome & Overview as the default page for synapse documentation website. ([\#10242](https://github.com/matrix-org/synapse/issues/10242))
- Adjust the URL in the README.rst file to point to irc.libera.chat. ([\#10258](https://github.com/matrix-org/synapse/issues/10258))
- Fix homeserver config option name in presence router documentation. ([\#10288](https://github.com/matrix-org/synapse/issues/10288))
- Fix link pointing at the wrong section in the modules documentation page. ([\#10302](https://github.com/matrix-org/synapse/issues/10302))


Internal Changes
----------------

- Drop `Origin` and `Accept` from the value of the `Access-Control-Allow-Headers` response header. ([\#10114](https://github.com/matrix-org/synapse/issues/10114))
- Add type hints to the federation servlets. ([\#10213](https://github.com/matrix-org/synapse/issues/10213))
- Improve the reliability of auto-joining remote rooms. ([\#10237](https://github.com/matrix-org/synapse/issues/10237))
- Update the release script to use the semver terminology and determine the release branch based on the next version. ([\#10239](https://github.com/matrix-org/synapse/issues/10239))
- Fix type hints for computing auth events. ([\#10253](https://github.com/matrix-org/synapse/issues/10253))
- Improve the performance of the spaces summary endpoint by only recursing into spaces (and not rooms in general). ([\#10256](https://github.com/matrix-org/synapse/issues/10256))
- Move event authentication methods from `Auth` to `EventAuthHandler`. ([\#10268](https://github.com/matrix-org/synapse/issues/10268))
- Re-enable a SyTest after it has been fixed. ([\#10292](https://github.com/matrix-org/synapse/issues/10292))


Synapse 1.37.1 (2021-06-30)
===========================

This release resolves issues (such as [#9490](https://github.com/matrix-org/synapse/issues/9490)) where one busy room could cause head-of-line blocking, starving Synapse from processing events in other rooms, and causing all federated traffic to fall behind. Synapse 1.37.1 processes inbound federation traffic asynchronously, ensuring that one busy room won't impact others. Please upgrade to Synapse 1.37.1 as soon as possible, in order to increase resilience to other traffic spikes.

No significant changes since v1.37.1rc1.


Synapse 1.37.1rc1 (2021-06-29)
==============================

Features
--------

- Handle inbound events from federation asynchronously. ([\#10269](https://github.com/matrix-org/synapse/issues/10269), [\#10272](https://github.com/matrix-org/synapse/issues/10272))


Synapse 1.37.0 (2021-06-29)
===========================

This release deprecates the current spam checker interface. See the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#deprecation-of-the-current-spam-checker-interface) for more information on how to update to the new generic module interface.

This release also removes support for fetching and renewing TLS certificates using the ACME v1 protocol, which has been fully decommissioned by Let's Encrypt on June 1st 2021. Admins previously using this feature should use a [reverse proxy](https://matrix-org.github.io/synapse/develop/reverse_proxy.html) to handle TLS termination, or use an external ACME client (such as [certbot](https://certbot.eff.org/)) to retrieve a certificate and key and provide them to Synapse using the `tls_certificate_path` and `tls_private_key_path` configuration settings.

Synapse 1.37.0rc1 (2021-06-24)
==============================

Features
--------

- Implement "room knocking" as per [MSC2403](https://github.com/matrix-org/matrix-doc/pull/2403). Contributed by @Sorunome and anoa. ([\#6739](https://github.com/matrix-org/synapse/issues/6739), [\#9359](https://github.com/matrix-org/synapse/issues/9359), [\#10167](https://github.com/matrix-org/synapse/issues/10167), [\#10212](https://github.com/matrix-org/synapse/issues/10212), [\#10227](https://github.com/matrix-org/synapse/issues/10227))
- Add experimental support for backfilling history into rooms ([MSC2716](https://github.com/matrix-org/matrix-doc/pull/2716)). ([\#9247](https://github.com/matrix-org/synapse/issues/9247))
- Implement a generic interface for third-party plugin modules. ([\#10062](https://github.com/matrix-org/synapse/issues/10062), [\#10206](https://github.com/matrix-org/synapse/issues/10206))
- Implement config option `sso.update_profile_information` to sync SSO users' profile information with the identity provider each time they login. Currently only displayname is supported. ([\#10108](https://github.com/matrix-org/synapse/issues/10108))
- Ensure that errors during startup are written to the logs and the console. ([\#10191](https://github.com/matrix-org/synapse/issues/10191))


Bugfixes
--------

- Fix a bug introduced in Synapse v1.25.0 that prevented the `ip_range_whitelist` configuration option from working for federation and identity servers. Contributed by @mikure. ([\#10115](https://github.com/matrix-org/synapse/issues/10115))
- Remove a broken import line in Synapse's `admin_cmd` worker. Broke in Synapse v1.33.0. ([\#10154](https://github.com/matrix-org/synapse/issues/10154))
- Fix a bug introduced in Synapse v1.21.0 which could cause `/sync` to return immediately with an empty response. ([\#10157](https://github.com/matrix-org/synapse/issues/10157), [\#10158](https://github.com/matrix-org/synapse/issues/10158))
- Fix a minor bug in the response to `/_matrix/client/r0/user/{user}/openid/request_token` causing `expires_in` to be a float instead of an integer. Contributed by @lukaslihotzki. ([\#10175](https://github.com/matrix-org/synapse/issues/10175))
- Always require users to re-authenticate for dangerous operations: deactivating an account, modifying an account password, and adding 3PIDs. ([\#10184](https://github.com/matrix-org/synapse/issues/10184))
- Fix a bug introduced in Synpase v1.7.2 where remote server count metrics collection would be incorrectly delayed on startup. Found by @heftig. ([\#10195](https://github.com/matrix-org/synapse/issues/10195))
- Fix a bug introduced in Synapse v1.35.1 where an `allow` key of a `m.room.join_rules` event could be applied for incorrect room versions and configurations. ([\#10208](https://github.com/matrix-org/synapse/issues/10208))
- Fix performance regression in responding to user key requests over federation. Introduced in Synapse v1.34.0rc1. ([\#10221](https://github.com/matrix-org/synapse/issues/10221))


Improved Documentation
----------------------

- Add a new guide to decoding request logs. ([\#8436](https://github.com/matrix-org/synapse/issues/8436))
- Mention in the sample homeserver config that you may need to configure max upload size in your reverse proxy. Contributed by @aaronraimist. ([\#10122](https://github.com/matrix-org/synapse/issues/10122))
- Fix broken links in documentation. ([\#10180](https://github.com/matrix-org/synapse/issues/10180))
- Deploy a snapshot of the documentation website upon each new Synapse release. ([\#10198](https://github.com/matrix-org/synapse/issues/10198))


Deprecations and Removals
-------------------------

- The current spam checker interface is deprecated in favour of a new generic modules system. See the [upgrade notes](https://matrix-org.github.io/synapse/develop/upgrade#deprecation-of-the-current-spam-checker-interface) for more information on how to update to the new system. ([\#10062](https://github.com/matrix-org/synapse/issues/10062), [\#10210](https://github.com/matrix-org/synapse/issues/10210), [\#10238](https://github.com/matrix-org/synapse/issues/10238))
- Stop supporting the unstable spaces prefixes from MSC1772. ([\#10161](https://github.com/matrix-org/synapse/issues/10161))
- Remove Synapse's support for automatically fetching and renewing certificates using the ACME v1 protocol. This protocol has been fully turned off by Let's Encrypt for existing installations on June 1st 2021. Admins previously using this feature should use a [reverse proxy](https://matrix-org.github.io/synapse/develop/reverse_proxy.html) to handle TLS termination, or use an external ACME client (such as [certbot](https://certbot.eff.org/)) to retrieve a certificate and key and provide them to Synapse using the `tls_certificate_path` and `tls_private_key_path` configuration settings. ([\#10194](https://github.com/matrix-org/synapse/issues/10194))


Internal Changes
----------------

- Update the database schema versioning to support gradual migration away from legacy tables. ([\#9933](https://github.com/matrix-org/synapse/issues/9933))
- Add type hints to the federation servlets. ([\#10080](https://github.com/matrix-org/synapse/issues/10080))
- Improve OpenTracing for event persistence. ([\#10134](https://github.com/matrix-org/synapse/issues/10134), [\#10193](https://github.com/matrix-org/synapse/issues/10193))
- Clean up the interface for injecting OpenTracing over HTTP. ([\#10143](https://github.com/matrix-org/synapse/issues/10143))
- Limit the number of in-flight `/keys/query` requests from a single device. ([\#10144](https://github.com/matrix-org/synapse/issues/10144))
- Refactor EventPersistenceQueue. ([\#10145](https://github.com/matrix-org/synapse/issues/10145))
- Document `SYNAPSE_TEST_LOG_LEVEL` to see the logger output when running tests. ([\#10148](https://github.com/matrix-org/synapse/issues/10148))
- Update the Complement build tags in GitHub Actions to test currently experimental features. ([\#10155](https://github.com/matrix-org/synapse/issues/10155))
- Add a `synapse_federation_soft_failed_events_total` metric to track how often events are soft failed. ([\#10156](https://github.com/matrix-org/synapse/issues/10156))
- Fetch the corresponding complement branch when performing CI. ([\#10160](https://github.com/matrix-org/synapse/issues/10160))
- Add some developer documentation about boolean columns in database schemas. ([\#10164](https://github.com/matrix-org/synapse/issues/10164))
- Add extra logging fields to better debug where events are being soft failed. ([\#10168](https://github.com/matrix-org/synapse/issues/10168))
- Add debug logging for when we enter and exit `Measure` blocks. ([\#10183](https://github.com/matrix-org/synapse/issues/10183))
- Improve comments in structured logging code. ([\#10188](https://github.com/matrix-org/synapse/issues/10188))
- Update [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083) support with modifications from the MSC. ([\#10189](https://github.com/matrix-org/synapse/issues/10189))
- Remove redundant DNS lookup limiter. ([\#10190](https://github.com/matrix-org/synapse/issues/10190))
- Upgrade `black` linting tool to 21.6b0. ([\#10197](https://github.com/matrix-org/synapse/issues/10197))
- Expose OpenTracing trace id in response headers. ([\#10199](https://github.com/matrix-org/synapse/issues/10199))


Synapse 1.36.0 (2021-06-15)
===========================

No significant changes.


Synapse 1.36.0rc2 (2021-06-11)
==============================

Bugfixes
--------

- Fix a bug which caused  presence updates to stop working some time after a restart, when using a presence writer worker. Broke in v1.33.0. ([\#10149](https://github.com/matrix-org/synapse/issues/10149))
- Fix a bug when using federation sender worker where it would send out more presence updates than necessary, leading to high resource usage. Broke in v1.33.0. ([\#10163](https://github.com/matrix-org/synapse/issues/10163))
- Fix a bug where Synapse could send the same presence update to a remote twice. ([\#10165](https://github.com/matrix-org/synapse/issues/10165))


Synapse 1.36.0rc1 (2021-06-08)
==============================

Features
--------

- Add new endpoint `/_matrix/client/r0/rooms/{roomId}/aliases` from Client-Server API r0.6.1 (previously [MSC2432](https://github.com/matrix-org/matrix-doc/pull/2432)). ([\#9224](https://github.com/matrix-org/synapse/issues/9224))
- Improve performance of incoming federation transactions in large rooms. ([\#9953](https://github.com/matrix-org/synapse/issues/9953), [\#9973](https://github.com/matrix-org/synapse/issues/9973))
- Rewrite logic around verifying JSON object and fetching server keys to be more performant and use less memory. ([\#10035](https://github.com/matrix-org/synapse/issues/10035))
- Add new admin APIs for unprotecting local media from quarantine. Contributed by @dklimpel. ([\#10040](https://github.com/matrix-org/synapse/issues/10040))
- Add new admin APIs to remove media by media ID from quarantine. Contributed by @dklimpel. ([\#10044](https://github.com/matrix-org/synapse/issues/10044))
- Make reason and score parameters optional for reporting content. Implements [MSC2414](https://github.com/matrix-org/matrix-doc/pull/2414). Contributed by Callum Brown. ([\#10077](https://github.com/matrix-org/synapse/issues/10077))
- Add support for routing more requests to workers. ([\#10084](https://github.com/matrix-org/synapse/issues/10084))
- Report OpenTracing spans for database activity. ([\#10113](https://github.com/matrix-org/synapse/issues/10113), [\#10136](https://github.com/matrix-org/synapse/issues/10136), [\#10141](https://github.com/matrix-org/synapse/issues/10141))
- Significantly reduce memory usage of joining large remote rooms. ([\#10117](https://github.com/matrix-org/synapse/issues/10117))


Bugfixes
--------

- Fixed a bug causing replication requests to fail when receiving a lot of events via federation. ([\#10082](https://github.com/matrix-org/synapse/issues/10082))
- Fix a bug in the `force_tracing_for_users` option introduced in Synapse v1.35 which meant that the OpenTracing spans produced were missing most tags. ([\#10092](https://github.com/matrix-org/synapse/issues/10092))
- Fixed a bug that could cause Synapse to stop notifying application services. Contributed by Willem Mulder. ([\#10107](https://github.com/matrix-org/synapse/issues/10107))
- Fix bug where the server would attempt to fetch the same history in the room from a remote server multiple times in parallel. ([\#10116](https://github.com/matrix-org/synapse/issues/10116))
- Fix a bug introduced in Synapse 1.33.0 which caused replication requests to fail when receiving a lot of very large events via federation. ([\#10118](https://github.com/matrix-org/synapse/issues/10118))
- Fix bug when using workers where pagination requests failed if a remote server returned zero events from `/backfill`. Introduced in 1.35.0. ([\#10133](https://github.com/matrix-org/synapse/issues/10133))


Improved Documentation
----------------------

- Clarify security note regarding hosting Synapse on the same domain as other web applications. ([\#9221](https://github.com/matrix-org/synapse/issues/9221))
- Update CAPTCHA documentation to mention turning off the verify origin feature. Contributed by @aaronraimist. ([\#10046](https://github.com/matrix-org/synapse/issues/10046))
- Tweak wording of database recommendation in `INSTALL.md`. Contributed by @aaronraimist. ([\#10057](https://github.com/matrix-org/synapse/issues/10057))
- Add initial infrastructure for rendering Synapse documentation with mdbook. ([\#10086](https://github.com/matrix-org/synapse/issues/10086))
- Convert the remaining Admin API documentation files to markdown. ([\#10089](https://github.com/matrix-org/synapse/issues/10089))
- Make a link in docs use HTTPS. Contributed by @RhnSharma. ([\#10130](https://github.com/matrix-org/synapse/issues/10130))
- Fix broken link in Docker docs. ([\#10132](https://github.com/matrix-org/synapse/issues/10132))


Deprecations and Removals
-------------------------

- Remove the experimental `spaces_enabled` flag. The spaces features are always available now. ([\#10063](https://github.com/matrix-org/synapse/issues/10063))


Internal Changes
----------------

- Tell CircleCI to build Docker images from `main` branch. ([\#9906](https://github.com/matrix-org/synapse/issues/9906))
- Simplify naming convention for release branches to only include the major and minor version numbers. ([\#10013](https://github.com/matrix-org/synapse/issues/10013))
- Add `parse_strings_from_args` for parsing an array from query parameters. ([\#10048](https://github.com/matrix-org/synapse/issues/10048), [\#10137](https://github.com/matrix-org/synapse/issues/10137))
- Remove some dead code regarding TLS certificate handling. ([\#10054](https://github.com/matrix-org/synapse/issues/10054))
- Remove redundant, unmaintained `convert_server_keys` script. ([\#10055](https://github.com/matrix-org/synapse/issues/10055))
- Improve the error message printed by synctl when synapse fails to start. ([\#10059](https://github.com/matrix-org/synapse/issues/10059))
- Fix GitHub Actions lint for newsfragments. ([\#10069](https://github.com/matrix-org/synapse/issues/10069))
- Update opentracing to inject the right context into the carrier. ([\#10074](https://github.com/matrix-org/synapse/issues/10074))
- Fix up `BatchingQueue` implementation. ([\#10078](https://github.com/matrix-org/synapse/issues/10078))
- Log method and path when dropping request due to size limit. ([\#10091](https://github.com/matrix-org/synapse/issues/10091))
- In Github Actions workflows, summarize the Sytest results in an easy-to-read format. ([\#10094](https://github.com/matrix-org/synapse/issues/10094))
- Make `/sync` do fewer state resolutions. ([\#10102](https://github.com/matrix-org/synapse/issues/10102))
- Add missing type hints to the admin API servlets. ([\#10105](https://github.com/matrix-org/synapse/issues/10105))
- Improve opentracing annotations for `Notifier`. ([\#10111](https://github.com/matrix-org/synapse/issues/10111))
- Enable Prometheus metrics for the jaeger client library. ([\#10112](https://github.com/matrix-org/synapse/issues/10112))
- Work to improve the responsiveness of `/sync` requests. ([\#10124](https://github.com/matrix-org/synapse/issues/10124))
- OpenTracing: use a consistent name for background processes. ([\#10135](https://github.com/matrix-org/synapse/issues/10135))


Synapse 1.35.1 (2021-06-03)
===========================

Bugfixes
--------

- Fix a bug introduced in v1.35.0 where invite-only rooms would be shown to all users in a space, regardless of if the user had access to it. ([\#10109](https://github.com/matrix-org/synapse/issues/10109))


Synapse 1.35.0 (2021-06-01)
===========================

Note that [the tag](https://github.com/matrix-org/synapse/releases/tag/v1.35.0rc3) and [docker images](https://hub.docker.com/layers/matrixdotorg/synapse/v1.35.0rc3/images/sha256-34ccc87bd99a17e2cbc0902e678b5937d16bdc1991ead097eee6096481ecf2c4?context=explore) for `v1.35.0rc3` were incorrectly built. If you are experiencing issues with either, it is recommended to upgrade to the equivalent tag or docker image for the `v1.35.0` release.

Deprecations and Removals
-------------------------

- The core Synapse development team plan to drop support for the [unstable API of MSC2858](https://github.com/matrix-org/matrix-doc/blob/master/proposals/2858-Multiple-SSO-Identity-Providers.md#unstable-prefix), including the undocumented `experimental.msc2858_enabled` config option, in August 2021. Client authors should ensure that their clients are updated to use the stable API (which has been supported since Synapse 1.30) well before that time, to give their users time to upgrade. ([\#10101](https://github.com/matrix-org/synapse/issues/10101))

Bugfixes
--------

- Fixed a bug causing replication requests to fail when receiving a lot of events via federation. Introduced in v1.33.0. ([\#10082](https://github.com/matrix-org/synapse/issues/10082))
- Fix HTTP response size limit to allow joining very large rooms over federation. Introduced in v1.33.0. ([\#10093](https://github.com/matrix-org/synapse/issues/10093))


Internal Changes
----------------

- Log method and path when dropping request due to size limit. ([\#10091](https://github.com/matrix-org/synapse/issues/10091))


Synapse 1.35.0rc2 (2021-05-27)
==============================

Bugfixes
--------

- Fix a bug introduced in v1.35.0rc1 when calling the spaces summary API via a GET request. ([\#10079](https://github.com/matrix-org/synapse/issues/10079))


Synapse 1.35.0rc1 (2021-05-25)
==============================

Features
--------

- Add experimental support to allow a user who could join a restricted room to view it in the spaces summary. ([\#9922](https://github.com/matrix-org/synapse/issues/9922), [\#10007](https://github.com/matrix-org/synapse/issues/10007), [\#10038](https://github.com/matrix-org/synapse/issues/10038))
- Reduce memory usage when joining very large rooms over federation. ([\#9958](https://github.com/matrix-org/synapse/issues/9958))
- Add a configuration option which allows enabling opentracing by user id. ([\#9978](https://github.com/matrix-org/synapse/issues/9978))
- Enable experimental support for [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946) (spaces summary API) and [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083) (restricted join rules) by default. ([\#10011](https://github.com/matrix-org/synapse/issues/10011))


Bugfixes
--------

- Fix a bug introduced in v1.26.0 which meant that `synapse_port_db` would not correctly initialise some postgres sequences, requiring manual updates afterwards. ([\#9991](https://github.com/matrix-org/synapse/issues/9991))
- Fix `synctl`'s `--no-daemonize` parameter to work correctly with worker processes. ([\#9995](https://github.com/matrix-org/synapse/issues/9995))
- Fix a validation bug introduced in v1.34.0 in the ordering of spaces in the space summary API. ([\#10002](https://github.com/matrix-org/synapse/issues/10002))
- Fixed deletion of new presence stream states from database. ([\#10014](https://github.com/matrix-org/synapse/issues/10014), [\#10033](https://github.com/matrix-org/synapse/issues/10033))
- Fixed a bug with very high resolution image uploads throwing internal server errors. ([\#10029](https://github.com/matrix-org/synapse/issues/10029))


Updates to the Docker image
---------------------------

- Fix bug introduced in Synapse 1.33.0 which caused a `Permission denied: '/homeserver.log'` error when starting Synapse with the generated log configuration. Contributed by Sergio Miguéns Iglesias. ([\#10045](https://github.com/matrix-org/synapse/issues/10045))


Improved Documentation
----------------------

- Add hardened systemd files as proposed in [#9760](https://github.com/matrix-org/synapse/issues/9760) and added them to `contrib/`. Change the docs to reflect the presence of these files. ([\#9803](https://github.com/matrix-org/synapse/issues/9803))
- Clarify documentation around SSO mapping providers generating unique IDs and localparts. ([\#9980](https://github.com/matrix-org/synapse/issues/9980))
- Updates to the PostgreSQL documentation (`postgres.md`). ([\#9988](https://github.com/matrix-org/synapse/issues/9988), [\#9989](https://github.com/matrix-org/synapse/issues/9989))
- Fix broken link in user directory documentation. Contributed by @junquera. ([\#10016](https://github.com/matrix-org/synapse/issues/10016))
- Add missing room state entry to the table of contents of room admin API. ([\#10043](https://github.com/matrix-org/synapse/issues/10043))


Deprecations and Removals
-------------------------

- Removed support for the deprecated `tls_fingerprints` configuration setting. Contributed by Jerin J Titus. ([\#9280](https://github.com/matrix-org/synapse/issues/9280))


Internal Changes
----------------

- Allow sending full presence to users via workers other than the one that called `ModuleApi.send_local_online_presence_to`. ([\#9823](https://github.com/matrix-org/synapse/issues/9823))
- Update comments in the space summary handler. ([\#9974](https://github.com/matrix-org/synapse/issues/9974))
- Minor enhancements to the `@cachedList` descriptor. ([\#9975](https://github.com/matrix-org/synapse/issues/9975))
- Split multipart email sending into a dedicated handler. ([\#9977](https://github.com/matrix-org/synapse/issues/9977))
- Run `black` on files in the `scripts` directory. ([\#9981](https://github.com/matrix-org/synapse/issues/9981))
- Add missing type hints to `synapse.util` module. ([\#9982](https://github.com/matrix-org/synapse/issues/9982))
- Simplify a few helper functions. ([\#9984](https://github.com/matrix-org/synapse/issues/9984), [\#9985](https://github.com/matrix-org/synapse/issues/9985), [\#9986](https://github.com/matrix-org/synapse/issues/9986))
- Remove unnecessary property from SQLBaseStore. ([\#9987](https://github.com/matrix-org/synapse/issues/9987))
- Remove `keylen` param on `LruCache`. ([\#9993](https://github.com/matrix-org/synapse/issues/9993))
- Update the Grafana dashboard in `contrib/`. ([\#10001](https://github.com/matrix-org/synapse/issues/10001))
- Add a batching queue implementation. ([\#10017](https://github.com/matrix-org/synapse/issues/10017))
- Reduce memory usage when verifying signatures on large numbers of events at once. ([\#10018](https://github.com/matrix-org/synapse/issues/10018))
- Properly invalidate caches for destination retry timings every (instead of expiring entries every 5 minutes). ([\#10036](https://github.com/matrix-org/synapse/issues/10036))
- Fix running complement tests with Synapse workers. ([\#10039](https://github.com/matrix-org/synapse/issues/10039))
- Fix typo in `get_state_ids_for_event` docstring where the return type was incorrect. ([\#10050](https://github.com/matrix-org/synapse/issues/10050))


Synapse 1.34.0 (2021-05-17)
===========================

This release deprecates the `room_invite_state_types` configuration setting. See the [upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.34.0/UPGRADE.rst#upgrading-to-v1340) for instructions on updating your configuration file to use the new `room_prejoin_state` setting.

This release also deprecates the `POST /_synapse/admin/v1/rooms/<room_id>/delete` admin API route. Server administrators are encouraged to update their scripts to use the new `DELETE /_synapse/admin/v1/rooms/<room_id>` route instead.


No significant changes since v1.34.0rc1.


Synapse 1.34.0rc1 (2021-05-12)
==============================

Features
--------

- Add experimental option to track memory usage of the caches. ([\#9881](https://github.com/matrix-org/synapse/issues/9881))
- Add support for `DELETE /_synapse/admin/v1/rooms/<room_id>`. ([\#9889](https://github.com/matrix-org/synapse/issues/9889))
- Add limits to how often Synapse will GC, ensuring that large servers do not end up GC thrashing if `gc_thresholds` has not been correctly set. ([\#9902](https://github.com/matrix-org/synapse/issues/9902))
- Improve performance of sending events for worker-based deployments using Redis. ([\#9905](https://github.com/matrix-org/synapse/issues/9905), [\#9950](https://github.com/matrix-org/synapse/issues/9950), [\#9951](https://github.com/matrix-org/synapse/issues/9951))
- Improve performance after joining a large room when presence is enabled. ([\#9910](https://github.com/matrix-org/synapse/issues/9910), [\#9916](https://github.com/matrix-org/synapse/issues/9916))
- Support stable identifiers for [MSC1772](https://github.com/matrix-org/matrix-doc/pull/1772) Spaces. `m.space.child` events will now be taken into account when populating the experimental spaces summary response. Please see [the upgrade notes](https://github.com/matrix-org/synapse/blob/release-v1.34.0/UPGRADE.rst#upgrading-to-v1340) if you have customised `room_invite_state_types` in your configuration. ([\#9915](https://github.com/matrix-org/synapse/issues/9915), [\#9966](https://github.com/matrix-org/synapse/issues/9966))
- Improve performance of backfilling in large rooms. ([\#9935](https://github.com/matrix-org/synapse/issues/9935))
- Add a config option to allow you to prevent device display names from being shared over federation. Contributed by @aaronraimist. ([\#9945](https://github.com/matrix-org/synapse/issues/9945))
- Update support for [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946): Spaces Summary. ([\#9947](https://github.com/matrix-org/synapse/issues/9947), [\#9954](https://github.com/matrix-org/synapse/issues/9954))


Bugfixes
--------

- Fix a bug introduced in v1.32.0 where the associated connection was improperly logged for SQL logging statements. ([\#9895](https://github.com/matrix-org/synapse/issues/9895))
- Correct the type hint for the `user_may_create_room_alias` method of spam checkers. It is provided a `RoomAlias`, not a `str`. ([\#9896](https://github.com/matrix-org/synapse/issues/9896))
- Fix bug where user directory could get out of sync if room visibility and membership changed in quick succession. ([\#9910](https://github.com/matrix-org/synapse/issues/9910))
- Include the `origin_server_ts` property in the experimental [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946) support to allow clients to properly sort rooms. ([\#9928](https://github.com/matrix-org/synapse/issues/9928))
- Fix bugs introduced in v1.23.0 which made the PostgreSQL port script fail when run with a newly-created SQLite database. ([\#9930](https://github.com/matrix-org/synapse/issues/9930))
- Fix a bug introduced in Synapse 1.29.0 which caused `m.room_key_request` to-device messages sent from one user to another to be dropped. ([\#9961](https://github.com/matrix-org/synapse/issues/9961), [\#9965](https://github.com/matrix-org/synapse/issues/9965))
- Fix a bug introduced in v1.27.0 preventing users and appservices exempt from ratelimiting from creating rooms with many invitees. ([\#9968](https://github.com/matrix-org/synapse/issues/9968))


Updates to the Docker image
---------------------------

- Add `startup_delay` to docker healthcheck to reduce waiting time for coming online and update the documentation with extra options. Contributed by @Maquis196. ([\#9913](https://github.com/matrix-org/synapse/issues/9913))


Improved Documentation
----------------------

- Add `port` argument to the Postgres database sample config section. ([\#9911](https://github.com/matrix-org/synapse/issues/9911))


Deprecations and Removals
-------------------------

- Mark as deprecated `POST /_synapse/admin/v1/rooms/<room_id>/delete`. ([\#9889](https://github.com/matrix-org/synapse/issues/9889))


Internal Changes
----------------

- Reduce the length of Synapse's access tokens. ([\#5588](https://github.com/matrix-org/synapse/issues/5588))
- Export jemalloc stats to Prometheus if it is being used. ([\#9882](https://github.com/matrix-org/synapse/issues/9882))
- Add type hints to presence handler. ([\#9885](https://github.com/matrix-org/synapse/issues/9885))
- Reduce memory usage of the LRU caches. ([\#9886](https://github.com/matrix-org/synapse/issues/9886))
- Add type hints to the `synapse.handlers` module. ([\#9896](https://github.com/matrix-org/synapse/issues/9896))
- Time response time for external cache requests. ([\#9904](https://github.com/matrix-org/synapse/issues/9904))
- Minor fixes to the `make_full_schema.sh` script. ([\#9931](https://github.com/matrix-org/synapse/issues/9931))
- Move database schema files into a common directory. ([\#9932](https://github.com/matrix-org/synapse/issues/9932))
- Add debug logging for lost/delayed to-device messages. ([\#9959](https://github.com/matrix-org/synapse/issues/9959))


Synapse 1.33.2 (2021-05-11)
===========================

Due to the security issue highlighted below, server administrators are encouraged to update Synapse. We are not aware of these vulnerabilities being exploited in the wild.

Security advisory
-----------------

This release fixes a denial of service attack ([CVE-2021-29471](https://github.com/matrix-org/synapse/security/advisories/GHSA-x345-32rc-8h85)) against Synapse's push rules implementation. Server admins are encouraged to upgrade.

Internal Changes
----------------

- Unpin attrs dependency. ([\#9946](https://github.com/matrix-org/synapse/issues/9946))


Synapse 1.33.1 (2021-05-06)
===========================

Bugfixes
--------

- Fix bug where `/sync` would break if using the latest version of `attrs` dependency, by pinning to a previous version. ([\#9937](https://github.com/matrix-org/synapse/issues/9937))


Synapse 1.33.0 (2021-05-05)
===========================

Features
--------

- Build Debian packages for Ubuntu 21.04 (Hirsute Hippo). ([\#9909](https://github.com/matrix-org/synapse/issues/9909))


Synapse 1.33.0rc2 (2021-04-29)
==============================

Bugfixes
--------

- Fix tight loop when handling presence replication when using workers. Introduced in v1.33.0rc1. ([\#9900](https://github.com/matrix-org/synapse/issues/9900))


Synapse 1.33.0rc1 (2021-04-28)
==============================

Features
--------

- Update experimental support for [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083): restricting room access via group membership. ([\#9800](https://github.com/matrix-org/synapse/issues/9800), [\#9814](https://github.com/matrix-org/synapse/issues/9814))
- Add experimental support for handling presence on a worker. ([\#9819](https://github.com/matrix-org/synapse/issues/9819), [\#9820](https://github.com/matrix-org/synapse/issues/9820), [\#9828](https://github.com/matrix-org/synapse/issues/9828), [\#9850](https://github.com/matrix-org/synapse/issues/9850))
- Return a new template when an user attempts to renew their account multiple times with the same token, stating that their account is set to expire. This replaces the invalid token template that would previously be shown in this case. This change concerns the optional account validity feature. ([\#9832](https://github.com/matrix-org/synapse/issues/9832))


Bugfixes
--------

- Fixes the OIDC SSO flow when using a `public_baseurl` value including a non-root URL path. ([\#9726](https://github.com/matrix-org/synapse/issues/9726))
- Fix thumbnail generation for some sites with non-standard content types. Contributed by @rkfg. ([\#9788](https://github.com/matrix-org/synapse/issues/9788))
- Add some sanity checks to identity server passed to 3PID bind/unbind endpoints. ([\#9802](https://github.com/matrix-org/synapse/issues/9802))
- Limit the size of HTTP responses read over federation. ([\#9833](https://github.com/matrix-org/synapse/issues/9833))
- Fix a bug which could cause Synapse to get stuck in a loop of resyncing device lists. ([\#9867](https://github.com/matrix-org/synapse/issues/9867))
- Fix a long-standing bug where errors from federation did not propagate to the client. ([\#9868](https://github.com/matrix-org/synapse/issues/9868))


Improved Documentation
----------------------

- Add a note to the docker docs mentioning that we mirror upstream's supported Docker platforms. ([\#9801](https://github.com/matrix-org/synapse/issues/9801))


Internal Changes
----------------

- Add a dockerfile for running Synapse in worker-mode under Complement. ([\#9162](https://github.com/matrix-org/synapse/issues/9162))
- Apply `pyupgrade` across the codebase. ([\#9786](https://github.com/matrix-org/synapse/issues/9786))
- Move some replication processing out of `generic_worker`. ([\#9796](https://github.com/matrix-org/synapse/issues/9796))
- Replace `HomeServer.get_config()` with inline references. ([\#9815](https://github.com/matrix-org/synapse/issues/9815))
- Rename some handlers and config modules to not duplicate the top-level module. ([\#9816](https://github.com/matrix-org/synapse/issues/9816))
- Fix a long-standing bug which caused `max_upload_size` to not be correctly enforced. ([\#9817](https://github.com/matrix-org/synapse/issues/9817))
- Reduce CPU usage of the user directory by reusing existing calculated room membership. ([\#9821](https://github.com/matrix-org/synapse/issues/9821))
- Small speed up for joining large remote rooms. ([\#9825](https://github.com/matrix-org/synapse/issues/9825))
- Introduce flake8-bugbear to the test suite and fix some of its lint violations. ([\#9838](https://github.com/matrix-org/synapse/issues/9838))
- Only store the raw data in the in-memory caches, rather than objects that include references to e.g. the data stores. ([\#9845](https://github.com/matrix-org/synapse/issues/9845))
- Limit length of accepted email addresses. ([\#9855](https://github.com/matrix-org/synapse/issues/9855))
- Remove redundant `synapse.types.Collection` type definition. ([\#9856](https://github.com/matrix-org/synapse/issues/9856))
- Handle recently added rate limits correctly when using `--no-rate-limit` with the demo scripts. ([\#9858](https://github.com/matrix-org/synapse/issues/9858))
- Disable invite rate-limiting by default when running the unit tests. ([\#9871](https://github.com/matrix-org/synapse/issues/9871))
- Pass a reactor into `SynapseSite` to make testing easier. ([\#9874](https://github.com/matrix-org/synapse/issues/9874))
- Make `DomainSpecificString` an `attrs` class. ([\#9875](https://github.com/matrix-org/synapse/issues/9875))
- Add type hints to `synapse.api.auth` and `synapse.api.auth_blocking` modules. ([\#9876](https://github.com/matrix-org/synapse/issues/9876))
- Remove redundant `_PushHTTPChannel` test class. ([\#9878](https://github.com/matrix-org/synapse/issues/9878))
- Remove backwards-compatibility code for Python versions < 3.6. ([\#9879](https://github.com/matrix-org/synapse/issues/9879))
- Small performance improvement around handling new local presence updates. ([\#9887](https://github.com/matrix-org/synapse/issues/9887))


Synapse 1.32.2 (2021-04-22)
===========================

This release includes a fix for a regression introduced in 1.32.0.

Bugfixes
--------

- Fix a regression in Synapse 1.32.0 and 1.32.1 which caused `LoggingContext` errors in plugins. ([\#9857](https://github.com/matrix-org/synapse/issues/9857))


Synapse 1.32.1 (2021-04-21)
===========================

This release fixes [a regression](https://github.com/matrix-org/synapse/issues/9853)
in Synapse 1.32.0 that caused connected Prometheus instances to become unstable.

However, as this release is still subject to the `LoggingContext` change in 1.32.0,
it is recommended to remain on or downgrade to 1.31.0.

Bugfixes
--------

- Fix a regression in Synapse 1.32.0 which caused Synapse to report large numbers of Prometheus time series, potentially overwhelming Prometheus instances. ([\#9854](https://github.com/matrix-org/synapse/issues/9854))


Synapse 1.32.0 (2021-04-20)
===========================

**Note:** This release introduces [a regression](https://github.com/matrix-org/synapse/issues/9853)
that can overwhelm connected Prometheus instances. This issue was not present in
1.32.0rc1. If affected, it is recommended to downgrade to 1.31.0 in the meantime, and
follow [these instructions](https://github.com/matrix-org/synapse/pull/9854#issuecomment-823472183)
to clean up any excess writeahead logs.

**Note:** This release also mistakenly included a change that may affected Synapse
modules that import `synapse.logging.context.LoggingContext`, such as
[synapse-s3-storage-provider](https://github.com/matrix-org/synapse-s3-storage-provider).
This will be fixed in a later Synapse version.

**Note:** This release requires Python 3.6+ and Postgres 9.6+ or SQLite 3.22+.

This release removes the deprecated `GET /_synapse/admin/v1/users/<user_id>` admin API. Please use the [v2 API](https://github.com/matrix-org/synapse/blob/develop/docs/admin_api/user_admin_api.rst#query-user-account) instead, which has improved capabilities.

This release requires Application Services to use type `m.login.application_service` when registering users via the `/_matrix/client/r0/register` endpoint to comply with the spec. Please ensure your Application Services are up to date.

If you are using the `packages.matrix.org` Debian repository for Synapse packages,
note that we have recently updated the expiry date on the gpg signing key. If you see an
error similar to `The following signatures were invalid: EXPKEYSIG F473DD4473365DE1`, you
will need to get a fresh copy of the keys. You can do so with:

```sh
sudo wget -O /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
```

Bugfixes
--------

- Fix the log lines of nested logging contexts. Broke in 1.32.0rc1. ([\#9829](https://github.com/matrix-org/synapse/issues/9829))


Synapse 1.32.0rc1 (2021-04-13)
==============================

Features
--------

- Add a Synapse module for routing presence updates between users. ([\#9491](https://github.com/matrix-org/synapse/issues/9491))
- Add an admin API to manage ratelimit for a specific user. ([\#9648](https://github.com/matrix-org/synapse/issues/9648))
- Include request information in structured logging output. ([\#9654](https://github.com/matrix-org/synapse/issues/9654))
- Add `order_by` to the admin API `GET /_synapse/admin/v2/users`. Contributed by @dklimpel. ([\#9691](https://github.com/matrix-org/synapse/issues/9691))
- Replace the `room_invite_state_types` configuration setting with `room_prejoin_state`. ([\#9700](https://github.com/matrix-org/synapse/issues/9700))
- Add experimental support for [MSC3083](https://github.com/matrix-org/matrix-doc/pull/3083): restricting room access via group membership. ([\#9717](https://github.com/matrix-org/synapse/issues/9717), [\#9735](https://github.com/matrix-org/synapse/issues/9735))
- Update experimental support for Spaces: include `m.room.create` in the room state sent with room-invites. ([\#9710](https://github.com/matrix-org/synapse/issues/9710))
- Synapse now requires Python 3.6 or later. It also requires Postgres 9.6 or later or SQLite 3.22 or later. ([\#9766](https://github.com/matrix-org/synapse/issues/9766))


Bugfixes
--------

- Prevent `synapse_forward_extremities` and `synapse_excess_extremity_events` Prometheus metrics from initially reporting zero-values after startup. ([\#8926](https://github.com/matrix-org/synapse/issues/8926))
- Fix recently added ratelimits to correctly honour the application service `rate_limited` flag. ([\#9711](https://github.com/matrix-org/synapse/issues/9711))
- Fix longstanding bug which caused `duplicate key value violates unique constraint "remote_media_cache_thumbnails_media_origin_media_id_thumbna_key"` errors. ([\#9725](https://github.com/matrix-org/synapse/issues/9725))
- Fix bug where sharded federation senders could get stuck repeatedly querying the DB in a loop, using lots of CPU. ([\#9770](https://github.com/matrix-org/synapse/issues/9770))
- Fix duplicate logging of exceptions thrown during federation transaction processing. ([\#9780](https://github.com/matrix-org/synapse/issues/9780))


Updates to the Docker image
---------------------------

- Move opencontainers labels to the final Docker image such that users can inspect them. ([\#9765](https://github.com/matrix-org/synapse/issues/9765))


Improved Documentation
----------------------

- Make the `allowed_local_3pids` regex example in the sample config stricter. ([\#9719](https://github.com/matrix-org/synapse/issues/9719))


Deprecations and Removals
-------------------------

- Remove old admin API `GET /_synapse/admin/v1/users/<user_id>`. ([\#9401](https://github.com/matrix-org/synapse/issues/9401))
- Make `/_matrix/client/r0/register` expect a type of `m.login.application_service` when an Application Service registers a user, to align with [the relevant spec](https://spec.matrix.org/unstable/application-service-api/#server-admin-style-permissions). ([\#9548](https://github.com/matrix-org/synapse/issues/9548))


Internal Changes
----------------

- Replace deprecated `imp` module with successor `importlib`. Contributed by Cristina Muñoz. ([\#9718](https://github.com/matrix-org/synapse/issues/9718))
- Experiment with GitHub Actions for CI. ([\#9661](https://github.com/matrix-org/synapse/issues/9661))
- Introduce flake8-bugbear to the test suite and fix some of its lint violations. ([\#9682](https://github.com/matrix-org/synapse/issues/9682))
- Update `scripts-dev/complement.sh` to use a local checkout of Complement, allow running a subset of tests and have it use Synapse's Complement test blacklist. ([\#9685](https://github.com/matrix-org/synapse/issues/9685))
- Improve Jaeger tracing for `to_device` messages. ([\#9686](https://github.com/matrix-org/synapse/issues/9686))
- Add release helper script for automating part of the Synapse release process. ([\#9713](https://github.com/matrix-org/synapse/issues/9713))
- Add type hints to expiring cache. ([\#9730](https://github.com/matrix-org/synapse/issues/9730))
- Convert various testcases to `HomeserverTestCase`. ([\#9736](https://github.com/matrix-org/synapse/issues/9736))
- Start linting mypy with `no_implicit_optional`. ([\#9742](https://github.com/matrix-org/synapse/issues/9742))
- Add missing type hints to federation handler and server. ([\#9743](https://github.com/matrix-org/synapse/issues/9743))
- Check that a `ConfigError` is raised, rather than simply `Exception`, when appropriate in homeserver config file generation tests. ([\#9753](https://github.com/matrix-org/synapse/issues/9753))
- Fix incompatibility with `tox` 2.5. ([\#9769](https://github.com/matrix-org/synapse/issues/9769))
- Enable Complement tests for [MSC2946](https://github.com/matrix-org/matrix-doc/pull/2946): Spaces Summary API. ([\#9771](https://github.com/matrix-org/synapse/issues/9771))
- Use mock from the standard library instead of a separate package. ([\#9772](https://github.com/matrix-org/synapse/issues/9772))
- Update Black configuration to target Python 3.6. ([\#9781](https://github.com/matrix-org/synapse/issues/9781))
- Add option to skip unit tests when building Debian packages. ([\#9793](https://github.com/matrix-org/synapse/issues/9793))


Synapse 1.31.0 (2021-04-06)
===========================

**Note:** As announced in v1.25.0, and in line with the deprecation policy for platform dependencies, this is the last release to support Python 3.5 and PostgreSQL 9.5. Future versions of Synapse will require Python 3.6+ and PostgreSQL 9.6+, as per our [deprecation policy](docs/deprecation_policy.md).

This is also the last release that the Synapse team will be publishing packages for Debian Stretch and Ubuntu Xenial.


Improved Documentation
----------------------

- Add a document describing the deprecation policy for platform dependencies. ([\#9723](https://github.com/matrix-org/synapse/issues/9723))


Internal Changes
----------------

- Revert using `dmypy run` in lint script. ([\#9720](https://github.com/matrix-org/synapse/issues/9720))
- Pin flake8-bugbear's version. ([\#9734](https://github.com/matrix-org/synapse/issues/9734))


Synapse 1.31.0rc1 (2021-03-30)
==============================

Features
--------

- Add support to OpenID Connect login for requiring attributes on the `userinfo` response. Contributed by Hubbe King. ([\#9609](https://github.com/matrix-org/synapse/issues/9609))
- Add initial experimental support for a "space summary" API. ([\#9643](https://github.com/matrix-org/synapse/issues/9643), [\#9652](https://github.com/matrix-org/synapse/issues/9652), [\#9653](https://github.com/matrix-org/synapse/issues/9653))
- Add support for the busy presence state as described in [MSC3026](https://github.com/matrix-org/matrix-doc/pull/3026). ([\#9644](https://github.com/matrix-org/synapse/issues/9644))
- Add support for credentials for proxy authentication in the `HTTPS_PROXY` environment variable. ([\#9657](https://github.com/matrix-org/synapse/issues/9657))


Bugfixes
--------

- Fix a longstanding bug that could cause issues when editing a reply to a message. ([\#9585](https://github.com/matrix-org/synapse/issues/9585))
- Fix the `/capabilities` endpoint to return `m.change_password` as disabled if the local password database is not used for authentication. Contributed by @dklimpel. ([\#9588](https://github.com/matrix-org/synapse/issues/9588))
- Check if local passwords are enabled before setting them for the user. ([\#9636](https://github.com/matrix-org/synapse/issues/9636))
- Fix a bug where federation sending can stall due to `concurrent access` database exceptions when it falls behind. ([\#9639](https://github.com/matrix-org/synapse/issues/9639))
- Fix a bug introduced in Synapse 1.30.1 which meant the suggested `pip` incantation to install an updated `cryptography` was incorrect. ([\#9699](https://github.com/matrix-org/synapse/issues/9699))


Updates to the Docker image
---------------------------

- Speed up Docker builds and make it nicer to test against Complement while developing (install all dependencies before copying the project). ([\#9610](https://github.com/matrix-org/synapse/issues/9610))
- Include [opencontainers labels](https://github.com/opencontainers/image-spec/blob/master/annotations.md#pre-defined-annotation-keys) in the Docker image. ([\#9612](https://github.com/matrix-org/synapse/issues/9612))


Improved Documentation
----------------------

- Clarify that `register_new_matrix_user` is present also when installed via non-pip package. ([\#9074](https://github.com/matrix-org/synapse/issues/9074))
- Update source install documentation to mention platform prerequisites before the source install steps. ([\#9667](https://github.com/matrix-org/synapse/issues/9667))
- Improve worker documentation for fallback/web auth endpoints. ([\#9679](https://github.com/matrix-org/synapse/issues/9679))
- Update the sample configuration for OIDC authentication. ([\#9695](https://github.com/matrix-org/synapse/issues/9695))


Internal Changes
----------------

- Preparatory steps for removing redundant `outlier` data from `event_json.internal_metadata` column. ([\#9411](https://github.com/matrix-org/synapse/issues/9411))
- Add type hints to the caching module. ([\#9442](https://github.com/matrix-org/synapse/issues/9442))
- Introduce flake8-bugbear to the test suite and fix some of its lint violations. ([\#9499](https://github.com/matrix-org/synapse/issues/9499), [\#9659](https://github.com/matrix-org/synapse/issues/9659))
- Add additional type hints to the Homeserver object. ([\#9631](https://github.com/matrix-org/synapse/issues/9631), [\#9638](https://github.com/matrix-org/synapse/issues/9638), [\#9675](https://github.com/matrix-org/synapse/issues/9675), [\#9681](https://github.com/matrix-org/synapse/issues/9681))
- Only save remote cross-signing and device keys if they're different from the current ones. ([\#9634](https://github.com/matrix-org/synapse/issues/9634))
- Rename storage function to fix spelling and not conflict with another function's name. ([\#9637](https://github.com/matrix-org/synapse/issues/9637))
- Improve performance of federation catch up by sending the latest events in the room to the remote, rather than just the last event sent by the local server. ([\#9640](https://github.com/matrix-org/synapse/issues/9640), [\#9664](https://github.com/matrix-org/synapse/issues/9664))
- In the `federation_client` commandline client, stop automatically adding the URL prefix, so that servlets on other prefixes can be tested. ([\#9645](https://github.com/matrix-org/synapse/issues/9645))
- In the `federation_client` commandline client, handle inline `signing_key`s in `homeserver.yaml`. ([\#9647](https://github.com/matrix-org/synapse/issues/9647))
- Fixed some antipattern issues to improve code quality. ([\#9649](https://github.com/matrix-org/synapse/issues/9649))
- Add a storage method for pulling all current user presence state from the database. ([\#9650](https://github.com/matrix-org/synapse/issues/9650))
- Import `HomeServer` from the proper module. ([\#9665](https://github.com/matrix-org/synapse/issues/9665))
- Increase default join ratelimiting burst rate. ([\#9674](https://github.com/matrix-org/synapse/issues/9674))
- Add type hints to third party event rules and visibility modules. ([\#9676](https://github.com/matrix-org/synapse/issues/9676))
- Bump mypy-zope to 0.2.13 to fix "Cannot determine consistent method resolution order (MRO)" errors when running mypy a second time. ([\#9678](https://github.com/matrix-org/synapse/issues/9678))
- Use interpreter from `$PATH` via `/usr/bin/env` instead of absolute paths in various scripts. ([\#9689](https://github.com/matrix-org/synapse/issues/9689))
- Make it possible to use `dmypy`. ([\#9692](https://github.com/matrix-org/synapse/issues/9692))
- Suppress "CryptographyDeprecationWarning: int_from_bytes is deprecated". ([\#9698](https://github.com/matrix-org/synapse/issues/9698))
- Use `dmypy run` in lint script for improved performance in type-checking while developing. ([\#9701](https://github.com/matrix-org/synapse/issues/9701))
- Fix undetected mypy error when using Python 3.6. ([\#9703](https://github.com/matrix-org/synapse/issues/9703))
- Fix type-checking CI on develop. ([\#9709](https://github.com/matrix-org/synapse/issues/9709))


Synapse 1.30.1 (2021-03-26)
===========================

This release is identical to Synapse 1.30.0, with the exception of explicitly
setting a minimum version of Python's Cryptography library to ensure that users
of Synapse are protected from the recent [OpenSSL security advisories](https://mta.openssl.org/pipermail/openssl-announce/2021-March/000198.html),
especially CVE-2021-3449.

Note that Cryptography defaults to bundling its own statically linked copy of
OpenSSL, which means that you may not be protected by your operating system's
security updates.

It's also worth noting that Cryptography no longer supports Python 3.5, so
admins deploying to older environments may not be protected against this or
future vulnerabilities. Synapse will be dropping support for Python 3.5 at the
end of March.


Updates to the Docker image
---------------------------

- Ensure that the docker container has up to date versions of openssl. ([\#9697](https://github.com/matrix-org/synapse/issues/9697))


Internal Changes
----------------

- Enforce that `cryptography` dependency is up to date to ensure it has the most recent openssl patches. ([\#9697](https://github.com/matrix-org/synapse/issues/9697))


Synapse 1.30.0 (2021-03-22)
===========================

Note that this release deprecates the ability for appservices to
call `POST /_matrix/client/r0/register`  without the body parameter `type`. Appservice
developers should use a `type` value of `m.login.application_service` as
per [the spec](https://matrix.org/docs/spec/application_service/r0.1.2#server-admin-style-permissions).
In future releases, calling this endpoint with an access token - but without a `m.login.application_service`
type - will fail.


No significant changes.


Synapse 1.30.0rc1 (2021-03-16)
==============================

Features
--------

- Add prometheus metrics for number of users successfully registering and logging in. ([\#9510](https://github.com/matrix-org/synapse/issues/9510), [\#9511](https://github.com/matrix-org/synapse/issues/9511), [\#9573](https://github.com/matrix-org/synapse/issues/9573))
- Add `synapse_federation_last_sent_pdu_time` and `synapse_federation_last_received_pdu_time` prometheus metrics, which monitor federation delays by reporting the timestamps of messages sent and received to a set of remote servers. ([\#9540](https://github.com/matrix-org/synapse/issues/9540))
- Add support for generating JSON Web Tokens dynamically for use as OIDC client secrets. ([\#9549](https://github.com/matrix-org/synapse/issues/9549))
- Optimise handling of incomplete room history for incoming federation. ([\#9601](https://github.com/matrix-org/synapse/issues/9601))
- Finalise support for allowing clients to pick an SSO Identity Provider ([MSC2858](https://github.com/matrix-org/matrix-doc/pull/2858)). ([\#9617](https://github.com/matrix-org/synapse/issues/9617))
- Tell spam checker modules about the SSO IdP a user registered through if one was used. ([\#9626](https://github.com/matrix-org/synapse/issues/9626))


Bugfixes
--------

- Fix long-standing bug when generating thumbnails for some images with transparency: `TypeError: cannot unpack non-iterable int object`. ([\#9473](https://github.com/matrix-org/synapse/issues/9473))
- Purge chain cover indexes for events that were purged prior to Synapse v1.29.0. ([\#9542](https://github.com/matrix-org/synapse/issues/9542), [\#9583](https://github.com/matrix-org/synapse/issues/9583))
- Fix bug where federation requests were not correctly retried on 5xx responses. ([\#9567](https://github.com/matrix-org/synapse/issues/9567))
- Fix re-activating an account via the admin API when local passwords are disabled. ([\#9587](https://github.com/matrix-org/synapse/issues/9587))
- Fix a bug introduced in Synapse 1.20 which caused incoming federation transactions to stack up, causing slow recovery from outages. ([\#9597](https://github.com/matrix-org/synapse/issues/9597))
- Fix a bug introduced in v1.28.0 where the OpenID Connect callback endpoint could error with a `MacaroonInitException`. ([\#9620](https://github.com/matrix-org/synapse/issues/9620))
- Fix Internal Server Error on `GET /_synapse/client/saml2/authn_response` request. ([\#9623](https://github.com/matrix-org/synapse/issues/9623))


Updates to the Docker image
---------------------------

- Make use of an improved malloc implementation (`jemalloc`) in the docker image. ([\#8553](https://github.com/matrix-org/synapse/issues/8553))


Improved Documentation
----------------------

- Add relayd entry to reverse proxy example configurations. ([\#9508](https://github.com/matrix-org/synapse/issues/9508))
- Improve the SAML2 upgrade notes for 1.27.0. ([\#9550](https://github.com/matrix-org/synapse/issues/9550))
- Link to the "List user's media" admin API from the media admin API docs. ([\#9571](https://github.com/matrix-org/synapse/issues/9571))
- Clarify the spam checker modules documentation example to mention that `parse_config` is a required method. ([\#9580](https://github.com/matrix-org/synapse/issues/9580))
- Clarify the sample configuration for `stats` settings. ([\#9604](https://github.com/matrix-org/synapse/issues/9604))


Deprecations and Removals
-------------------------

- The `synapse_federation_last_sent_pdu_age` and `synapse_federation_last_received_pdu_age` prometheus metrics have been removed. They are replaced by `synapse_federation_last_sent_pdu_time` and `synapse_federation_last_received_pdu_time`. ([\#9540](https://github.com/matrix-org/synapse/issues/9540))
- Registering an Application Service user without using the `m.login.application_service` login type will be unsupported in an upcoming Synapse release. ([\#9559](https://github.com/matrix-org/synapse/issues/9559))


Internal Changes
----------------

- Add tests to ResponseCache. ([\#9458](https://github.com/matrix-org/synapse/issues/9458))
- Add type hints to purge room and server notice admin API. ([\#9520](https://github.com/matrix-org/synapse/issues/9520))
- Add extra logging to ObservableDeferred when callbacks throw exceptions. ([\#9523](https://github.com/matrix-org/synapse/issues/9523))
- Fix incorrect type hints. ([\#9528](https://github.com/matrix-org/synapse/issues/9528), [\#9543](https://github.com/matrix-org/synapse/issues/9543), [\#9591](https://github.com/matrix-org/synapse/issues/9591), [\#9608](https://github.com/matrix-org/synapse/issues/9608), [\#9618](https://github.com/matrix-org/synapse/issues/9618))
- Add an additional test for purging a room. ([\#9541](https://github.com/matrix-org/synapse/issues/9541))
- Add a `.git-blame-ignore-revs` file with the hashes of auto-formatting. ([\#9560](https://github.com/matrix-org/synapse/issues/9560))
- Increase the threshold before which outbound federation to a server goes into "catch up" mode, which is expensive for the remote server to handle. ([\#9561](https://github.com/matrix-org/synapse/issues/9561))
- Fix spurious errors reported by the `config-lint.sh` script. ([\#9562](https://github.com/matrix-org/synapse/issues/9562))
- Fix type hints and tests for BlacklistingAgentWrapper and BlacklistingReactorWrapper. ([\#9563](https://github.com/matrix-org/synapse/issues/9563))
- Do not have mypy ignore type hints from unpaddedbase64. ([\#9568](https://github.com/matrix-org/synapse/issues/9568))
- Improve efficiency of calculating the auth chain in large rooms. ([\#9576](https://github.com/matrix-org/synapse/issues/9576))
- Convert `synapse.types.Requester` to an `attrs` class. ([\#9586](https://github.com/matrix-org/synapse/issues/9586))
- Add logging for redis connection setup. ([\#9590](https://github.com/matrix-org/synapse/issues/9590))
- Improve logging when processing incoming transactions. ([\#9596](https://github.com/matrix-org/synapse/issues/9596))
- Remove unused `stats.retention` setting, and emit a warning if stats are disabled. ([\#9604](https://github.com/matrix-org/synapse/issues/9604))
- Prevent attempting to bundle aggregations for state events in /context APIs. ([\#9619](https://github.com/matrix-org/synapse/issues/9619))


Synapse 1.29.0 (2021-03-08)
===========================

Note that synapse now expects an `X-Forwarded-Proto` header when used with a reverse proxy. Please see the [upgrade notes](docs/upgrade.md#upgrading-to-v1290) for more details on this change.


No significant changes.


Synapse 1.29.0rc1 (2021-03-04)
==============================

Features
--------

- Add rate limiters to cross-user key sharing requests. ([\#8957](https://github.com/matrix-org/synapse/issues/8957))
- Add `order_by` to the admin API `GET /_synapse/admin/v1/users/<user_id>/media`. Contributed by @dklimpel. ([\#8978](https://github.com/matrix-org/synapse/issues/8978))
- Add some configuration settings to make users' profile data more private. ([\#9203](https://github.com/matrix-org/synapse/issues/9203))
- The `no_proxy` and `NO_PROXY` environment variables are now respected in proxied HTTP clients with the lowercase form taking precedence if both are present. Additionally, the lowercase `https_proxy` environment variable is now respected in proxied HTTP clients on top of existing support for the uppercase `HTTPS_PROXY` form and takes precedence if both are present. Contributed by Timothy Leung. ([\#9372](https://github.com/matrix-org/synapse/issues/9372))
- Add a configuration option, `user_directory.prefer_local_users`, which when enabled will make it more likely for users on the same server as you to appear above other users. ([\#9383](https://github.com/matrix-org/synapse/issues/9383), [\#9385](https://github.com/matrix-org/synapse/issues/9385))
- Add support for regenerating thumbnails if they have been deleted but the original image is still stored. ([\#9438](https://github.com/matrix-org/synapse/issues/9438))
- Add support for `X-Forwarded-Proto` header when using a reverse proxy. ([\#9472](https://github.com/matrix-org/synapse/issues/9472), [\#9501](https://github.com/matrix-org/synapse/issues/9501), [\#9512](https://github.com/matrix-org/synapse/issues/9512), [\#9539](https://github.com/matrix-org/synapse/issues/9539))


Bugfixes
--------

- Fix a bug where users' pushers were not all deleted when they deactivated their account. ([\#9285](https://github.com/matrix-org/synapse/issues/9285), [\#9516](https://github.com/matrix-org/synapse/issues/9516))
- Fix a bug where a lot of unnecessary presence updates were sent when joining a room. ([\#9402](https://github.com/matrix-org/synapse/issues/9402))
- Fix a bug that caused multiple calls to the experimental `shared_rooms` endpoint to return stale results. ([\#9416](https://github.com/matrix-org/synapse/issues/9416))
- Fix a bug in single sign-on which could cause a "No session cookie found" error. ([\#9436](https://github.com/matrix-org/synapse/issues/9436))
- Fix bug introduced in v1.27.0 where allowing a user to choose their own username when logging in via single sign-on did not work unless an `idp_icon` was defined. ([\#9440](https://github.com/matrix-org/synapse/issues/9440))
- Fix a bug introduced in v1.26.0 where some sequences were not properly configured when running `synapse_port_db`. ([\#9449](https://github.com/matrix-org/synapse/issues/9449))
- Fix deleting pushers when using sharded pushers. ([\#9465](https://github.com/matrix-org/synapse/issues/9465), [\#9466](https://github.com/matrix-org/synapse/issues/9466), [\#9479](https://github.com/matrix-org/synapse/issues/9479), [\#9536](https://github.com/matrix-org/synapse/issues/9536))
- Fix missing startup checks for the consistency of certain PostgreSQL sequences. ([\#9470](https://github.com/matrix-org/synapse/issues/9470))
- Fix a long-standing bug where the media repository could leak file descriptors while previewing media. ([\#9497](https://github.com/matrix-org/synapse/issues/9497))
- Properly purge the event chain cover index when purging history. ([\#9498](https://github.com/matrix-org/synapse/issues/9498))
- Fix missing chain cover index due to a schema delta not being applied correctly. Only affected servers that ran development versions. ([\#9503](https://github.com/matrix-org/synapse/issues/9503))
- Fix a bug introduced in v1.25.0 where `/_synapse/admin/join/` would fail when given a room alias. ([\#9506](https://github.com/matrix-org/synapse/issues/9506))
- Prevent presence background jobs from running when presence is disabled. ([\#9530](https://github.com/matrix-org/synapse/issues/9530))
- Fix rare edge case that caused a background update to fail if the server had rejected an event that had duplicate auth events. ([\#9537](https://github.com/matrix-org/synapse/issues/9537))


Improved Documentation
----------------------

- Update the example systemd config to propagate reloads to individual units. ([\#9463](https://github.com/matrix-org/synapse/issues/9463))


Internal Changes
----------------

- Add documentation and type hints to `parse_duration`. ([\#9432](https://github.com/matrix-org/synapse/issues/9432))
- Remove vestiges of `uploads_path` configuration setting. ([\#9462](https://github.com/matrix-org/synapse/issues/9462))
- Add a comment about systemd-python. ([\#9464](https://github.com/matrix-org/synapse/issues/9464))
- Test that we require validated email for email pushers. ([\#9496](https://github.com/matrix-org/synapse/issues/9496))
- Allow python to generate bytecode for synapse. ([\#9502](https://github.com/matrix-org/synapse/issues/9502))
- Fix incorrect type hints. ([\#9515](https://github.com/matrix-org/synapse/issues/9515), [\#9518](https://github.com/matrix-org/synapse/issues/9518))
- Add type hints to device and event report admin API. ([\#9519](https://github.com/matrix-org/synapse/issues/9519))
- Add type hints to user admin API. ([\#9521](https://github.com/matrix-org/synapse/issues/9521))
- Bump the versions of mypy and mypy-zope used for static type checking. ([\#9529](https://github.com/matrix-org/synapse/issues/9529))


Synapse 1.28.0 (2021-02-25)
===========================

Note that this release drops support for ARMv7 in the official Docker images, due to repeated problems building for ARMv7 (and the associated maintenance burden this entails).

This release also fixes the documentation included in v1.27.0 around the callback URI for SAML2 identity providers. If your server is configured to use single sign-on via a SAML2 IdP, you may need to make configuration changes. Please review the [upgrade notes](docs/upgrade.md) for more details on these changes.


Internal Changes
----------------

- Revert change in v1.28.0rc1 to remove the deprecated SAML endpoint. ([\#9474](https://github.com/matrix-org/synapse/issues/9474))


Synapse 1.28.0rc1 (2021-02-19)
==============================

Removal warning
---------------

The v1 list accounts API is deprecated and will be removed in a future release.
This API was undocumented and misleading. It can be replaced by the
[v2 list accounts API](https://github.com/matrix-org/synapse/blob/release-v1.28.0/docs/admin_api/user_admin_api.rst#list-accounts),
which has been available since Synapse 1.7.0 (2019-12-13).

Please check if you're using any scripts which use the admin API and replace
`GET /_synapse/admin/v1/users/<user_id>` with `GET /_synapse/admin/v2/users`.


Features
--------

- New admin API to get the context of an event: `/_synapse/admin/rooms/{roomId}/context/{eventId}`. ([\#9150](https://github.com/matrix-org/synapse/issues/9150))
- Further improvements to the user experience of registration via single sign-on. ([\#9300](https://github.com/matrix-org/synapse/issues/9300), [\#9301](https://github.com/matrix-org/synapse/issues/9301))
- Add hook to spam checker modules that allow checking file uploads and remote downloads. ([\#9311](https://github.com/matrix-org/synapse/issues/9311))
- Add support for receiving OpenID Connect authentication responses via form `POST`s rather than `GET`s. ([\#9376](https://github.com/matrix-org/synapse/issues/9376))
- Add the shadow-banning status to the admin API for user info. ([\#9400](https://github.com/matrix-org/synapse/issues/9400))


Bugfixes
--------

- Fix long-standing bug where sending email notifications would fail for rooms that the server had since left. ([\#9257](https://github.com/matrix-org/synapse/issues/9257))
- Fix bug introduced in Synapse 1.27.0rc1 which meant the "session expired" error page during SSO registration was badly formatted. ([\#9296](https://github.com/matrix-org/synapse/issues/9296))
- Assert a maximum length for some parameters for spec compliance. ([\#9321](https://github.com/matrix-org/synapse/issues/9321), [\#9393](https://github.com/matrix-org/synapse/issues/9393))
- Fix additional errors when previewing URLs: "AttributeError 'NoneType' object has no attribute 'xpath'" and "ValueError: Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration.". ([\#9333](https://github.com/matrix-org/synapse/issues/9333))
- Fix a bug causing Synapse to impose the wrong type constraints on fields when processing responses from appservices to `/_matrix/app/v1/thirdparty/user/{protocol}`. ([\#9361](https://github.com/matrix-org/synapse/issues/9361))
- Fix bug where Synapse would occasionally stop reconnecting to Redis after the connection was lost. ([\#9391](https://github.com/matrix-org/synapse/issues/9391))
- Fix a long-standing bug when upgrading a room: "TypeError: '>' not supported between instances of 'NoneType' and 'int'". ([\#9395](https://github.com/matrix-org/synapse/issues/9395))
- Reduce the amount of memory used when generating the URL preview of a file that is larger than the `max_spider_size`. ([\#9421](https://github.com/matrix-org/synapse/issues/9421))
- Fix a long-standing bug in the deduplication of old presence, resulting in no deduplication. ([\#9425](https://github.com/matrix-org/synapse/issues/9425))
- The `ui_auth.session_timeout` config option can now be specified in terms of number of seconds/minutes/etc/. Contributed by Rishabh Arya. ([\#9426](https://github.com/matrix-org/synapse/issues/9426))
- Fix a bug introduced in v1.27.0: "TypeError: int() argument must be a string, a bytes-like object or a number, not 'NoneType." related to the user directory. ([\#9428](https://github.com/matrix-org/synapse/issues/9428))


Updates to the Docker image
---------------------------

- Drop support for ARMv7 in Docker images. ([\#9433](https://github.com/matrix-org/synapse/issues/9433))


Improved Documentation
----------------------

- Reorganize CHANGELOG.md. ([\#9281](https://github.com/matrix-org/synapse/issues/9281))
- Add note to `auto_join_rooms` config option explaining existing rooms must be publicly joinable. ([\#9291](https://github.com/matrix-org/synapse/issues/9291))
- Correct name of Synapse's service file in TURN howto. ([\#9308](https://github.com/matrix-org/synapse/issues/9308))
- Fix the braces in the `oidc_providers` section of the sample config. ([\#9317](https://github.com/matrix-org/synapse/issues/9317))
- Update installation instructions on Fedora. ([\#9322](https://github.com/matrix-org/synapse/issues/9322))
- Add HTTP/2 support to the nginx example configuration. Contributed by David Vo. ([\#9390](https://github.com/matrix-org/synapse/issues/9390))
- Update docs for using Gitea as OpenID provider. ([\#9404](https://github.com/matrix-org/synapse/issues/9404))
- Document that pusher instances are shardable. ([\#9407](https://github.com/matrix-org/synapse/issues/9407))
- Fix erroneous documentation from v1.27.0 about updating the SAML2 callback URL. ([\#9434](https://github.com/matrix-org/synapse/issues/9434))


Deprecations and Removals
-------------------------

- Deprecate old admin API `GET /_synapse/admin/v1/users/<user_id>`. ([\#9429](https://github.com/matrix-org/synapse/issues/9429))


Internal Changes
----------------

- Fix 'object name reserved for internal use' errors with recent versions of SQLite. ([\#9003](https://github.com/matrix-org/synapse/issues/9003))
- Add experimental support for running Synapse with PyPy. ([\#9123](https://github.com/matrix-org/synapse/issues/9123))
- Deny access to additional IP addresses by default. ([\#9240](https://github.com/matrix-org/synapse/issues/9240))
- Update the `Cursor` type hints to better match PEP 249. ([\#9299](https://github.com/matrix-org/synapse/issues/9299))
- Add debug logging for SRV lookups. Contributed by @Bubu. ([\#9305](https://github.com/matrix-org/synapse/issues/9305))
- Improve logging for OIDC login flow. ([\#9307](https://github.com/matrix-org/synapse/issues/9307))
- Share the code for handling required attributes between the CAS and SAML handlers. ([\#9326](https://github.com/matrix-org/synapse/issues/9326))
- Clean up the code to load the metadata for OpenID Connect identity providers. ([\#9362](https://github.com/matrix-org/synapse/issues/9362))
- Convert tests to use `HomeserverTestCase`. ([\#9377](https://github.com/matrix-org/synapse/issues/9377), [\#9396](https://github.com/matrix-org/synapse/issues/9396))
- Update the version of black used to 20.8b1. ([\#9381](https://github.com/matrix-org/synapse/issues/9381))
- Allow OIDC config to override discovered values. ([\#9384](https://github.com/matrix-org/synapse/issues/9384))
- Remove some dead code from the acceptance of room invites path. ([\#9394](https://github.com/matrix-org/synapse/issues/9394))
- Clean up an unused method in the presence handler code. ([\#9408](https://github.com/matrix-org/synapse/issues/9408))


Synapse 1.27.0 (2021-02-16)
===========================

Note that this release includes a change in Synapse to use Redis as a cache ─ as well as a pub/sub mechanism ─ if Redis support is enabled for workers. No action is needed by server administrators, and we do not expect resource usage of the Redis instance to change dramatically.

This release also changes the callback URI for OpenID Connect (OIDC) and SAML2 identity providers. If your server is configured to use single sign-on via an OIDC/OAuth2 or SAML2 IdP, you may need to make configuration changes. Please review the [upgrade notes](docs/upgrade.md) for more details on these changes.

This release also changes escaping of variables in the HTML templates for SSO or email notifications. If you have customised these templates, please review the [upgrade notes](docs/upgrade.md) for more details on these changes.


Bugfixes
--------

- Fix building Docker images for armv7. ([\#9405](https://github.com/matrix-org/synapse/issues/9405))


Synapse 1.27.0rc2 (2021-02-11)
==============================

Features
--------

- Further improvements to the user experience of registration via single sign-on. ([\#9297](https://github.com/matrix-org/synapse/issues/9297))


Bugfixes
--------

- Fix ratelimiting introduced in v1.27.0rc1 for invites to respect the `ratelimit` flag on application services. ([\#9302](https://github.com/matrix-org/synapse/issues/9302))
- Do not automatically calculate `public_baseurl` since it can be wrong in some situations. Reverts behaviour introduced in v1.26.0. ([\#9313](https://github.com/matrix-org/synapse/issues/9313))


Improved Documentation
----------------------

- Clarify the sample configuration for changes made to the template loading code. ([\#9310](https://github.com/matrix-org/synapse/issues/9310))


Synapse 1.27.0rc1 (2021-02-02)
==============================

Features
--------

- Add an admin API for getting and deleting forward extremities for a room. ([\#9062](https://github.com/matrix-org/synapse/issues/9062))
- Add an admin API for retrieving the current room state of a room. ([\#9168](https://github.com/matrix-org/synapse/issues/9168))
- Add experimental support for allowing clients to pick an SSO Identity Provider ([MSC2858](https://github.com/matrix-org/matrix-doc/pull/2858)). ([\#9183](https://github.com/matrix-org/synapse/issues/9183), [\#9242](https://github.com/matrix-org/synapse/issues/9242))
- Add an admin API endpoint for shadow-banning users. ([\#9209](https://github.com/matrix-org/synapse/issues/9209))
- Add ratelimits to the 3PID `/requestToken` APIs. ([\#9238](https://github.com/matrix-org/synapse/issues/9238))
- Add support to the OpenID Connect integration for adding the user's email address. ([\#9245](https://github.com/matrix-org/synapse/issues/9245))
- Add ratelimits to invites in rooms and to specific users. ([\#9258](https://github.com/matrix-org/synapse/issues/9258))
- Improve the user experience of setting up an account via single-sign on. ([\#9262](https://github.com/matrix-org/synapse/issues/9262), [\#9272](https://github.com/matrix-org/synapse/issues/9272), [\#9275](https://github.com/matrix-org/synapse/issues/9275), [\#9276](https://github.com/matrix-org/synapse/issues/9276), [\#9277](https://github.com/matrix-org/synapse/issues/9277), [\#9286](https://github.com/matrix-org/synapse/issues/9286), [\#9287](https://github.com/matrix-org/synapse/issues/9287))
- Add phone home stats for encrypted messages. ([\#9283](https://github.com/matrix-org/synapse/issues/9283))
- Update the redirect URI for OIDC authentication. ([\#9288](https://github.com/matrix-org/synapse/issues/9288))


Bugfixes
--------

- Fix spurious errors in logs when deleting a non-existent pusher. ([\#9121](https://github.com/matrix-org/synapse/issues/9121))
- Fix a long-standing bug where Synapse would return a 500 error when a thumbnail did not exist (and auto-generation of thumbnails was not enabled). ([\#9163](https://github.com/matrix-org/synapse/issues/9163))
- Fix a long-standing bug where an internal server error was raised when attempting to preview an HTML document in an unknown character encoding. ([\#9164](https://github.com/matrix-org/synapse/issues/9164))
- Fix a long-standing bug where invalid data could cause errors when calculating the presentable room name for push. ([\#9165](https://github.com/matrix-org/synapse/issues/9165))
- Fix bug where we sometimes didn't detect that Redis connections had died, causing workers to not see new data. ([\#9218](https://github.com/matrix-org/synapse/issues/9218))
- Fix a bug where `None` was passed to Synapse modules instead of an empty dictionary if an empty module `config` block was provided in the homeserver config. ([\#9229](https://github.com/matrix-org/synapse/issues/9229))
- Fix a bug in the `make_room_admin` admin API where it failed if the admin with the greatest power level was not in the room. Contributed by Pankaj Yadav. ([\#9235](https://github.com/matrix-org/synapse/issues/9235))
- Prevent password hashes from getting dropped if a client failed threepid validation during a User Interactive Auth stage. Removes a workaround for an ancient bug in Riot Web <v0.7.4. ([\#9265](https://github.com/matrix-org/synapse/issues/9265))
- Fix single-sign-on when the endpoints are routed to synapse workers. ([\#9271](https://github.com/matrix-org/synapse/issues/9271))


Improved Documentation
----------------------

- Add docs for using Gitea as OpenID provider. ([\#9134](https://github.com/matrix-org/synapse/issues/9134))
- Add link to Matrix VoIP tester for turn-howto. ([\#9135](https://github.com/matrix-org/synapse/issues/9135))
- Add notes on integrating with Facebook for SSO login. ([\#9244](https://github.com/matrix-org/synapse/issues/9244))


Deprecations and Removals
-------------------------

- The `service_url` parameter in `cas_config` is deprecated in favor of `public_baseurl`. ([\#9199](https://github.com/matrix-org/synapse/issues/9199))
- Add new endpoint `/_synapse/client/saml2` for SAML2 authentication callbacks, and deprecate the old endpoint `/_matrix/saml2`. ([\#9289](https://github.com/matrix-org/synapse/issues/9289))


Internal Changes
----------------

- Add tests to `test_user.UsersListTestCase` for List Users Admin API. ([\#9045](https://github.com/matrix-org/synapse/issues/9045))
- Various improvements to the federation client. ([\#9129](https://github.com/matrix-org/synapse/issues/9129))
- Speed up chain cover calculation when persisting a batch of state events at once. ([\#9176](https://github.com/matrix-org/synapse/issues/9176))
- Add a `long_description_type` to the package metadata. ([\#9180](https://github.com/matrix-org/synapse/issues/9180))
- Speed up batch insertion when using PostgreSQL. ([\#9181](https://github.com/matrix-org/synapse/issues/9181), [\#9188](https://github.com/matrix-org/synapse/issues/9188))
- Emit an error at startup if different Identity Providers are configured with the same `idp_id`. ([\#9184](https://github.com/matrix-org/synapse/issues/9184))
- Improve performance of concurrent use of `StreamIDGenerators`. ([\#9190](https://github.com/matrix-org/synapse/issues/9190))
- Add some missing source directories to the automatic linting script. ([\#9191](https://github.com/matrix-org/synapse/issues/9191))
- Precompute joined hosts and store in Redis. ([\#9198](https://github.com/matrix-org/synapse/issues/9198), [\#9227](https://github.com/matrix-org/synapse/issues/9227))
- Clean-up template loading code. ([\#9200](https://github.com/matrix-org/synapse/issues/9200))
- Fix the Python 3.5 old dependencies build. ([\#9217](https://github.com/matrix-org/synapse/issues/9217))
- Update `isort` to v5.7.0 to bypass a bug where it would disagree with `black` about formatting. ([\#9222](https://github.com/matrix-org/synapse/issues/9222))
- Add type hints to handlers code. ([\#9223](https://github.com/matrix-org/synapse/issues/9223), [\#9232](https://github.com/matrix-org/synapse/issues/9232))
- Fix Debian package building on Ubuntu 16.04 LTS (Xenial). ([\#9254](https://github.com/matrix-org/synapse/issues/9254))
- Minor performance improvement during TLS handshake. ([\#9255](https://github.com/matrix-org/synapse/issues/9255))
- Refactor the generation of summary text for email notifications. ([\#9260](https://github.com/matrix-org/synapse/issues/9260))
- Restore PyPy compatibility by not calling CPython-specific GC methods when under PyPy. ([\#9270](https://github.com/matrix-org/synapse/issues/9270))


Synapse 1.26.0 (2021-01-27)
===========================

This release brings a new schema version for Synapse and rolling back to a previous
version is not trivial. Please review the [upgrade notes](docs/upgrade.md) for more details
on these changes and for general upgrade guidance.

No significant changes since 1.26.0rc2.


Synapse 1.26.0rc2 (2021-01-25)
==============================

Bugfixes
--------

- Fix receipts and account data not being sent down sync. Introduced in v1.26.0rc1. ([\#9193](https://github.com/matrix-org/synapse/issues/9193), [\#9195](https://github.com/matrix-org/synapse/issues/9195))
- Fix chain cover update to handle events with duplicate auth events. Introduced in v1.26.0rc1. ([\#9210](https://github.com/matrix-org/synapse/issues/9210))


Internal Changes
----------------

- Add an `oidc-` prefix to any `idp_id`s which are given in the `oidc_providers` configuration. ([\#9189](https://github.com/matrix-org/synapse/issues/9189))
- Bump minimum `psycopg2` version to v2.8. ([\#9204](https://github.com/matrix-org/synapse/issues/9204))


Synapse 1.26.0rc1 (2021-01-20)
==============================

This release brings a new schema version for Synapse and rolling back to a previous
version is not trivial. Please review the [upgrade notes](docs/upgrade.md) for more details
on these changes and for general upgrade guidance.

Features
--------

- Add support for multiple SSO Identity Providers. ([\#9015](https://github.com/matrix-org/synapse/issues/9015), [\#9017](https://github.com/matrix-org/synapse/issues/9017), [\#9036](https://github.com/matrix-org/synapse/issues/9036), [\#9067](https://github.com/matrix-org/synapse/issues/9067), [\#9081](https://github.com/matrix-org/synapse/issues/9081), [\#9082](https://github.com/matrix-org/synapse/issues/9082), [\#9105](https://github.com/matrix-org/synapse/issues/9105), [\#9107](https://github.com/matrix-org/synapse/issues/9107), [\#9109](https://github.com/matrix-org/synapse/issues/9109), [\#9110](https://github.com/matrix-org/synapse/issues/9110), [\#9127](https://github.com/matrix-org/synapse/issues/9127), [\#9153](https://github.com/matrix-org/synapse/issues/9153), [\#9154](https://github.com/matrix-org/synapse/issues/9154), [\#9177](https://github.com/matrix-org/synapse/issues/9177))
- During user-interactive authentication via single-sign-on, give a better error if the user uses the wrong account on the SSO IdP. ([\#9091](https://github.com/matrix-org/synapse/issues/9091))
- Give the `public_baseurl` a default value, if it is not explicitly set in the configuration file. ([\#9159](https://github.com/matrix-org/synapse/issues/9159))
- Improve performance when calculating ignored users in large rooms. ([\#9024](https://github.com/matrix-org/synapse/issues/9024))
- Implement [MSC2176](https://github.com/matrix-org/matrix-doc/pull/2176) in an experimental room version. ([\#8984](https://github.com/matrix-org/synapse/issues/8984))
- Add an admin API for protecting local media from quarantine. ([\#9086](https://github.com/matrix-org/synapse/issues/9086))
- Remove a user's avatar URL and display name when deactivated with the Admin API. ([\#8932](https://github.com/matrix-org/synapse/issues/8932))
- Update `/_synapse/admin/v1/users/<user_id>/joined_rooms` to work for both local and remote users. ([\#8948](https://github.com/matrix-org/synapse/issues/8948))
- Add experimental support for handling to-device messages on worker processes. ([\#9042](https://github.com/matrix-org/synapse/issues/9042), [\#9043](https://github.com/matrix-org/synapse/issues/9043), [\#9044](https://github.com/matrix-org/synapse/issues/9044), [\#9130](https://github.com/matrix-org/synapse/issues/9130))
- Add experimental support for handling `/keys/claim` and `/room_keys` APIs on worker processes. ([\#9068](https://github.com/matrix-org/synapse/issues/9068))
- Add experimental support for handling `/devices` API on worker processes. ([\#9092](https://github.com/matrix-org/synapse/issues/9092))
- Add experimental support for moving off receipts and account data persistence off master. ([\#9104](https://github.com/matrix-org/synapse/issues/9104), [\#9166](https://github.com/matrix-org/synapse/issues/9166))


Bugfixes
--------

- Fix a long-standing issue where an internal server error would occur when requesting a profile over federation that did not include a display name / avatar URL. ([\#9023](https://github.com/matrix-org/synapse/issues/9023))
- Fix a long-standing bug where some caches could grow larger than configured. ([\#9028](https://github.com/matrix-org/synapse/issues/9028))
- Fix error handling during insertion of client IPs into the database. ([\#9051](https://github.com/matrix-org/synapse/issues/9051))
- Fix bug where we didn't correctly record CPU time spent in `on_new_event` block. ([\#9053](https://github.com/matrix-org/synapse/issues/9053))
- Fix a minor bug which could cause confusing error messages from invalid configurations. ([\#9054](https://github.com/matrix-org/synapse/issues/9054))
- Fix incorrect exit code when there is an error at startup. ([\#9059](https://github.com/matrix-org/synapse/issues/9059))
- Fix `JSONDecodeError` spamming the logs when sending transactions to remote servers. ([\#9070](https://github.com/matrix-org/synapse/issues/9070))
- Fix "Failed to send request" errors when a client provides an invalid room alias. ([\#9071](https://github.com/matrix-org/synapse/issues/9071))
- Fix bugs in federation catchup logic that caused outbound federation to be delayed for large servers after start up. Introduced in v1.8.0 and v1.21.0. ([\#9114](https://github.com/matrix-org/synapse/issues/9114), [\#9116](https://github.com/matrix-org/synapse/issues/9116))
- Fix corruption of `pushers` data when a postgres bouncer is used. ([\#9117](https://github.com/matrix-org/synapse/issues/9117))
- Fix minor bugs in handling the `clientRedirectUrl` parameter for SSO login. ([\#9128](https://github.com/matrix-org/synapse/issues/9128))
- Fix "Unhandled error in Deferred: BodyExceededMaxSize" errors when .well-known files that are too large. ([\#9108](https://github.com/matrix-org/synapse/issues/9108))
- Fix "UnboundLocalError: local variable 'length' referenced before assignment" errors when the response body exceeds the expected size. This bug was introduced in v1.25.0. ([\#9145](https://github.com/matrix-org/synapse/issues/9145))
- Fix a long-standing bug "ValueError: invalid literal for int() with base 10" when `/publicRooms` is requested with an invalid `server` parameter. ([\#9161](https://github.com/matrix-org/synapse/issues/9161))


Improved Documentation
----------------------

- Add some extra docs for getting Synapse running on macOS. ([\#8997](https://github.com/matrix-org/synapse/issues/8997))
- Correct a typo in the `systemd-with-workers` documentation. ([\#9035](https://github.com/matrix-org/synapse/issues/9035))
- Correct a typo in `INSTALL.md`. ([\#9040](https://github.com/matrix-org/synapse/issues/9040))
- Add missing `user_mapping_provider` configuration to the Keycloak OIDC example. Contributed by @chris-ruecker. ([\#9057](https://github.com/matrix-org/synapse/issues/9057))
- Quote `pip install` packages when extras are used to avoid shells interpreting bracket characters. ([\#9151](https://github.com/matrix-org/synapse/issues/9151))


Deprecations and Removals
-------------------------

- Remove broken and unmaintained `demo/webserver.py` script. ([\#9039](https://github.com/matrix-org/synapse/issues/9039))


Internal Changes
----------------

- Improve efficiency of large state resolutions. ([\#8868](https://github.com/matrix-org/synapse/issues/8868), [\#9029](https://github.com/matrix-org/synapse/issues/9029), [\#9115](https://github.com/matrix-org/synapse/issues/9115), [\#9118](https://github.com/matrix-org/synapse/issues/9118), [\#9124](https://github.com/matrix-org/synapse/issues/9124))
- Various clean-ups to the structured logging and logging context code. ([\#8939](https://github.com/matrix-org/synapse/issues/8939))
- Ensure rejected events get added to some metadata tables. ([\#9016](https://github.com/matrix-org/synapse/issues/9016))
- Ignore date-rotated homeserver logs saved to disk. ([\#9018](https://github.com/matrix-org/synapse/issues/9018))
- Remove an unused column from `access_tokens` table. ([\#9025](https://github.com/matrix-org/synapse/issues/9025))
- Add a `-noextras` factor to `tox.ini`, to support running the tests with no optional dependencies. ([\#9030](https://github.com/matrix-org/synapse/issues/9030))
- Fix running unit tests when optional dependencies are not installed. ([\#9031](https://github.com/matrix-org/synapse/issues/9031))
- Allow bumping schema version when using split out state database. ([\#9033](https://github.com/matrix-org/synapse/issues/9033))
- Configure the linters to run on a consistent set of files. ([\#9038](https://github.com/matrix-org/synapse/issues/9038))
- Various cleanups to device inbox store. ([\#9041](https://github.com/matrix-org/synapse/issues/9041))
- Drop unused database tables. ([\#9055](https://github.com/matrix-org/synapse/issues/9055))
- Remove unused `SynapseService` class. ([\#9058](https://github.com/matrix-org/synapse/issues/9058))
- Remove unnecessary declarations in the tests for the admin API. ([\#9063](https://github.com/matrix-org/synapse/issues/9063))
- Remove `SynapseRequest.get_user_agent`. ([\#9069](https://github.com/matrix-org/synapse/issues/9069))
- Remove redundant `Homeserver.get_ip_from_request` method. ([\#9080](https://github.com/matrix-org/synapse/issues/9080))
- Add type hints to media repository. ([\#9093](https://github.com/matrix-org/synapse/issues/9093))
- Fix the wrong arguments being passed to `BlacklistingAgentWrapper` from `MatrixFederationAgent`. Contributed by Timothy Leung. ([\#9098](https://github.com/matrix-org/synapse/issues/9098))
- Reduce the scope of caught exceptions in `BlacklistingAgentWrapper`. ([\#9106](https://github.com/matrix-org/synapse/issues/9106))
- Improve `UsernamePickerTestCase`. ([\#9112](https://github.com/matrix-org/synapse/issues/9112))
- Remove dependency on `distutils`. ([\#9125](https://github.com/matrix-org/synapse/issues/9125))
- Enforce that replication HTTP clients are called with keyword arguments only. ([\#9144](https://github.com/matrix-org/synapse/issues/9144))
- Fix the Python 3.5 / old dependencies build in CI. ([\#9146](https://github.com/matrix-org/synapse/issues/9146))
- Replace the old `perspectives` option in the Synapse docker config file template with `trusted_key_servers`. ([\#9157](https://github.com/matrix-org/synapse/issues/9157))


Synapse 1.25.0 (2021-01-13)
===========================

Ending Support for Python 3.5 and Postgres 9.5
----------------------------------------------

With this release, the Synapse team is announcing a formal deprecation policy for our platform dependencies, like Python and PostgreSQL:

All future releases of Synapse will follow the upstream end-of-life schedules.

Which means:

* This is the last release which guarantees support for Python 3.5.
* We will end support for PostgreSQL 9.5 early next month.
* We will end support for Python 3.6 and PostgreSQL 9.6 near the end of the year.

Crucially, this means __we will not produce .deb packages for Debian 9 (Stretch) or Ubuntu 16.04 (Xenial)__ beyond the transition period described below.

The website https://endoflife.date/ has convenient summaries of the support schedules for projects like [Python](https://endoflife.date/python) and [PostgreSQL](https://endoflife.date/postgresql).

If you are unable to upgrade your environment to a supported version of Python or
Postgres, we encourage you to consider using the
[Synapse Docker images](https://matrix-org.github.io/synapse/latest/setup/installation.html#docker-images-and-ansible-playbooks)
instead.

### Transition Period

We will make a good faith attempt to avoid breaking compatibility in all releases through the end of March 2021. However, critical security vulnerabilities in dependencies or other unanticipated circumstances may arise which necessitate breaking compatibility earlier.

We intend to continue producing .deb packages for Debian 9 (Stretch) and Ubuntu 16.04 (Xenial) through the transition period.

Removal warning
---------------

The old [Purge Room API](https://github.com/matrix-org/synapse/tree/master/docs/admin_api/purge_room.md)
and [Shutdown Room API](https://github.com/matrix-org/synapse/tree/master/docs/admin_api/shutdown_room.md)
are deprecated and will be removed in a future release. They will be replaced by the
[Delete Room API](https://github.com/matrix-org/synapse/tree/master/docs/admin_api/rooms.md#delete-room-api).

`POST /_synapse/admin/v1/rooms/<room_id>/delete` replaces `POST /_synapse/admin/v1/purge_room` and
`POST /_synapse/admin/v1/shutdown_room/<room_id>`.

Bugfixes
--------

- Fix HTTP proxy support when using a proxy that is on a blacklisted IP. Introduced in v1.25.0rc1. Contributed by @Bubu. ([\#9084](https://github.com/matrix-org/synapse/issues/9084))


Synapse 1.25.0rc1 (2021-01-06)
==============================

Features
--------

- Add an admin API that lets server admins get power in rooms in which local users have power. ([\#8756](https://github.com/matrix-org/synapse/issues/8756))
- Add optional HTTP authentication to replication endpoints. ([\#8853](https://github.com/matrix-org/synapse/issues/8853))
- Improve the error messages printed as a result of configuration problems for extension modules. ([\#8874](https://github.com/matrix-org/synapse/issues/8874))
- Add the number of local devices to Room Details Admin API. Contributed by @dklimpel. ([\#8886](https://github.com/matrix-org/synapse/issues/8886))
- Add `X-Robots-Tag` header to stop web crawlers from indexing media. Contributed by Aaron Raimist. ([\#8887](https://github.com/matrix-org/synapse/issues/8887))
- Spam-checkers may now define their methods as `async`. ([\#8890](https://github.com/matrix-org/synapse/issues/8890))
- Add support for allowing users to pick their own user ID during a single-sign-on login. ([\#8897](https://github.com/matrix-org/synapse/issues/8897), [\#8900](https://github.com/matrix-org/synapse/issues/8900), [\#8911](https://github.com/matrix-org/synapse/issues/8911), [\#8938](https://github.com/matrix-org/synapse/issues/8938), [\#8941](https://github.com/matrix-org/synapse/issues/8941), [\#8942](https://github.com/matrix-org/synapse/issues/8942), [\#8951](https://github.com/matrix-org/synapse/issues/8951))
- Add an `email.invite_client_location` configuration option to send a web client location to the invite endpoint on the identity server which allows customisation of the email template. ([\#8930](https://github.com/matrix-org/synapse/issues/8930))
- The search term in the list room and list user Admin APIs is now treated as case-insensitive. ([\#8931](https://github.com/matrix-org/synapse/issues/8931))
- Apply an IP range blacklist to push and key revocation requests. ([\#8821](https://github.com/matrix-org/synapse/issues/8821), [\#8870](https://github.com/matrix-org/synapse/issues/8870), [\#8954](https://github.com/matrix-org/synapse/issues/8954))
- Add an option to allow re-use of user-interactive authentication sessions for a period of time. ([\#8970](https://github.com/matrix-org/synapse/issues/8970))
- Allow running the redact endpoint on workers. ([\#8994](https://github.com/matrix-org/synapse/issues/8994))


Bugfixes
--------

- Fix bug where we might not correctly calculate the current state for rooms with multiple extremities. ([\#8827](https://github.com/matrix-org/synapse/issues/8827))
- Fix a long-standing bug in the register admin endpoint (`/_synapse/admin/v1/register`) when the `mac` field was not provided. The endpoint now properly returns a 400 error. Contributed by @edwargix. ([\#8837](https://github.com/matrix-org/synapse/issues/8837))
- Fix a long-standing bug on Synapse instances supporting Single-Sign-On, where users would be prompted to enter their password to confirm certain actions, even though they have not set a password. ([\#8858](https://github.com/matrix-org/synapse/issues/8858))
- Fix a longstanding bug where a 500 error would be returned if the `Content-Length` header was not provided to the upload media resource. ([\#8862](https://github.com/matrix-org/synapse/issues/8862))
- Add additional validation to pusher URLs to be compliant with the specification. ([\#8865](https://github.com/matrix-org/synapse/issues/8865))
- Fix the error code that is returned when a user tries to register on a homeserver on which new-user registration has been disabled. ([\#8867](https://github.com/matrix-org/synapse/issues/8867))
- Fix a bug where `PUT /_synapse/admin/v2/users/<user_id>` failed to create a new user when `avatar_url` is specified. Bug introduced in Synapse v1.9.0. ([\#8872](https://github.com/matrix-org/synapse/issues/8872))
- Fix a 500 error when attempting to preview an empty HTML file. ([\#8883](https://github.com/matrix-org/synapse/issues/8883))
- Fix occasional deadlock when handling SIGHUP. ([\#8918](https://github.com/matrix-org/synapse/issues/8918))
- Fix login API to not ratelimit application services that have ratelimiting disabled. ([\#8920](https://github.com/matrix-org/synapse/issues/8920))
- Fix bug where we ratelimited auto joining of rooms on registration (using `auto_join_rooms` config). ([\#8921](https://github.com/matrix-org/synapse/issues/8921))
- Fix a bug where deactivated users appeared in the user directory when their profile information was updated. ([\#8933](https://github.com/matrix-org/synapse/issues/8933), [\#8964](https://github.com/matrix-org/synapse/issues/8964))
- Fix bug introduced in Synapse v1.24.0 which would cause an exception on startup if both `enabled` and `localdb_enabled` were set to `False` in the `password_config` setting of the configuration file. ([\#8937](https://github.com/matrix-org/synapse/issues/8937))
- Fix a bug where 500 errors would be returned if the `m.room_history_visibility` event had invalid content. ([\#8945](https://github.com/matrix-org/synapse/issues/8945))
- Fix a bug causing common English words to not be considered for a user directory search. ([\#8959](https://github.com/matrix-org/synapse/issues/8959))
- Fix bug where application services couldn't register new ghost users if the server had reached its MAU limit. ([\#8962](https://github.com/matrix-org/synapse/issues/8962))
- Fix a long-standing bug where a `m.image` event without a `url` would cause errors on push. ([\#8965](https://github.com/matrix-org/synapse/issues/8965))
- Fix a small bug in v2 state resolution algorithm, which could also cause performance issues for rooms with large numbers of power levels. ([\#8971](https://github.com/matrix-org/synapse/issues/8971))
- Add validation to the `sendToDevice` API to raise a missing parameters error instead of a 500 error. ([\#8975](https://github.com/matrix-org/synapse/issues/8975))
- Add validation of group IDs to raise a 400 error instead of a 500 error. ([\#8977](https://github.com/matrix-org/synapse/issues/8977))


Improved Documentation
----------------------

- Fix the "Event persist rate" section of the included grafana dashboard by adding missing prometheus rules. ([\#8802](https://github.com/matrix-org/synapse/issues/8802))
- Combine related media admin API docs. ([\#8839](https://github.com/matrix-org/synapse/issues/8839))
- Fix an error in the documentation for the SAML username mapping provider. ([\#8873](https://github.com/matrix-org/synapse/issues/8873))
- Clarify comments around template directories in `sample_config.yaml`. ([\#8891](https://github.com/matrix-org/synapse/issues/8891))
- Move instructions for database setup, adjusted heading levels and improved syntax highlighting in [INSTALL.md](../INSTALL.md). Contributed by @fossterer. ([\#8987](https://github.com/matrix-org/synapse/issues/8987))
- Update the example value of `group_creation_prefix` in the sample configuration. ([\#8992](https://github.com/matrix-org/synapse/issues/8992))
- Link the Synapse developer room to the development section in the docs. ([\#9002](https://github.com/matrix-org/synapse/issues/9002))


Deprecations and Removals
-------------------------

- Deprecate Shutdown Room and Purge Room Admin APIs. ([\#8829](https://github.com/matrix-org/synapse/issues/8829))


Internal Changes
----------------

- Properly store the mapping of external ID to Matrix ID for CAS users. ([\#8856](https://github.com/matrix-org/synapse/issues/8856), [\#8958](https://github.com/matrix-org/synapse/issues/8958))
- Remove some unnecessary stubbing from unit tests. ([\#8861](https://github.com/matrix-org/synapse/issues/8861))
- Remove unused `FakeResponse` class from unit tests. ([\#8864](https://github.com/matrix-org/synapse/issues/8864))
- Pass `room_id` to `get_auth_chain_difference`. ([\#8879](https://github.com/matrix-org/synapse/issues/8879))
- Add type hints to push module. ([\#8880](https://github.com/matrix-org/synapse/issues/8880), [\#8882](https://github.com/matrix-org/synapse/issues/8882), [\#8901](https://github.com/matrix-org/synapse/issues/8901), [\#8940](https://github.com/matrix-org/synapse/issues/8940), [\#8943](https://github.com/matrix-org/synapse/issues/8943), [\#9020](https://github.com/matrix-org/synapse/issues/9020))
- Simplify logic for handling user-interactive-auth via single-sign-on servers. ([\#8881](https://github.com/matrix-org/synapse/issues/8881))
- Skip the SAML tests if the requirements (`pysaml2` and `xmlsec1`) aren't available. ([\#8905](https://github.com/matrix-org/synapse/issues/8905))
- Fix multiarch docker image builds. ([\#8906](https://github.com/matrix-org/synapse/issues/8906))
- Don't publish `latest` docker image until all archs are built. ([\#8909](https://github.com/matrix-org/synapse/issues/8909))
- Various clean-ups to the structured logging and logging context code. ([\#8916](https://github.com/matrix-org/synapse/issues/8916), [\#8935](https://github.com/matrix-org/synapse/issues/8935))
- Automatically drop stale forward-extremities under some specific conditions. ([\#8929](https://github.com/matrix-org/synapse/issues/8929))
- Refactor test utilities for injecting HTTP requests. ([\#8946](https://github.com/matrix-org/synapse/issues/8946))
- Add a maximum size of 50 kilobytes to .well-known lookups. ([\#8950](https://github.com/matrix-org/synapse/issues/8950))
- Fix bug in `generate_log_config` script which made it write empty files. ([\#8952](https://github.com/matrix-org/synapse/issues/8952))
- Clean up tox.ini file; disable coverage checking for non-test runs. ([\#8963](https://github.com/matrix-org/synapse/issues/8963))
- Add type hints to the admin and room list handlers. ([\#8973](https://github.com/matrix-org/synapse/issues/8973))
- Add type hints to the receipts and user directory handlers. ([\#8976](https://github.com/matrix-org/synapse/issues/8976))
- Drop the unused `local_invites` table. ([\#8979](https://github.com/matrix-org/synapse/issues/8979))
- Add type hints to the base storage code. ([\#8980](https://github.com/matrix-org/synapse/issues/8980))
- Support using PyJWT v2.0.0 in the test suite. ([\#8986](https://github.com/matrix-org/synapse/issues/8986))
- Fix `tests.federation.transport.RoomDirectoryFederationTests` and ensure it runs in CI. ([\#8998](https://github.com/matrix-org/synapse/issues/8998))
- Add type hints to the crypto module. ([\#8999](https://github.com/matrix-org/synapse/issues/8999))


**Changelogs for older versions can be found [here](CHANGES-2020.md).**
