
Synapse 1.7.3 (2019-12-31)
==========================

This release fixes a long-standing bug in the state resolution algorithm.

Bugfixes
--------

- Fix exceptions caused by state resolution choking on malformed events. ([\#6608](https://github.com/matrix-org/synapse/issues/6608))


Synapse 1.7.2 (2019-12-20)
==========================

This release fixes some regressions introduced in Synapse 1.7.0 and 1.7.1.

Bugfixes
--------

- Fix a regression introduced in Synapse 1.7.1 which caused errors when attempting to backfill rooms over federation. ([\#6576](https://github.com/matrix-org/synapse/issues/6576))
- Fix a bug introduced in Synapse 1.7.0 which caused an error on startup when upgrading from versions before 1.3.0. ([\#6578](https://github.com/matrix-org/synapse/issues/6578))


Synapse 1.7.1 (2019-12-18)
==========================

This release includes several security fixes as well as a fix to a bug exposed by the security fixes. Administrators are encouraged to upgrade as soon as possible.

Security updates
----------------

- Fix a bug which could cause room events to be incorrectly authorized using events from a different room. ([\#6501](https://github.com/matrix-org/synapse/issues/6501), [\#6503](https://github.com/matrix-org/synapse/issues/6503), [\#6521](https://github.com/matrix-org/synapse/issues/6521), [\#6524](https://github.com/matrix-org/synapse/issues/6524), [\#6530](https://github.com/matrix-org/synapse/issues/6530), [\#6531](https://github.com/matrix-org/synapse/issues/6531))
- Fix a bug causing responses to the `/context` client endpoint to not use the pruned version of the event. ([\#6553](https://github.com/matrix-org/synapse/issues/6553))
- Fix a cause of state resets in room versions 2 onwards. ([\#6556](https://github.com/matrix-org/synapse/issues/6556), [\#6560](https://github.com/matrix-org/synapse/issues/6560))

Bugfixes
--------

- Fix a bug which could cause the federation server to incorrectly return errors when handling certain obscure event graphs. ([\#6526](https://github.com/matrix-org/synapse/issues/6526), [\#6527](https://github.com/matrix-org/synapse/issues/6527))

Synapse 1.7.0 (2019-12-13)
==========================

This release changes the default settings so that only local authenticated users can query the server's room directory. See the [upgrade notes](docs/upgrade.md#upgrading-to-v170) for details.

Support for SQLite versions before 3.11 is now deprecated. A future release will refuse to start if used with an SQLite version before 3.11.

Administrators are reminded that SQLite should not be used for production instances. Instructions for migrating to Postgres are available [here](docs/postgres.md). A future release of synapse will, by default, disable federation for servers using SQLite.

No significant changes since 1.7.0rc2.


Synapse 1.7.0rc2 (2019-12-11)
=============================

Bugfixes
--------

- Fix incorrect error message for invalid requests when setting user's avatar URL. ([\#6497](https://github.com/matrix-org/synapse/issues/6497))
- Fix support for SQLite 3.7. ([\#6499](https://github.com/matrix-org/synapse/issues/6499))
- Fix regression where sending email push would not work when using a pusher worker. ([\#6507](https://github.com/matrix-org/synapse/issues/6507), [\#6509](https://github.com/matrix-org/synapse/issues/6509))


Synapse 1.7.0rc1 (2019-12-09)
=============================

Features
--------

- Implement per-room message retention policies. ([\#5815](https://github.com/matrix-org/synapse/issues/5815), [\#6436](https://github.com/matrix-org/synapse/issues/6436))
- Add etag and count fields to key backup endpoints to help clients guess if there are new keys. ([\#5858](https://github.com/matrix-org/synapse/issues/5858))
- Add `/admin/v2/users` endpoint with pagination. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#5925](https://github.com/matrix-org/synapse/issues/5925))
- Require User-Interactive Authentication for `/account/3pid/add`, meaning the user's password will be required to add a third-party ID to their account. ([\#6119](https://github.com/matrix-org/synapse/issues/6119))
- Implement the `/_matrix/federation/unstable/net.atleastfornow/state/<context>` API as drafted in MSC2314. ([\#6176](https://github.com/matrix-org/synapse/issues/6176))
- Configure privacy-preserving settings by default for the room directory. ([\#6355](https://github.com/matrix-org/synapse/issues/6355))
- Add ephemeral messages support by partially implementing [MSC2228](https://github.com/matrix-org/matrix-doc/pull/2228). ([\#6409](https://github.com/matrix-org/synapse/issues/6409))
- Add support for [MSC 2367](https://github.com/matrix-org/matrix-doc/pull/2367), which allows specifying a reason on all membership events. ([\#6434](https://github.com/matrix-org/synapse/issues/6434))


Bugfixes
--------

- Transfer non-standard power levels on room upgrade. ([\#6237](https://github.com/matrix-org/synapse/issues/6237))
- Fix error from the Pillow library when uploading RGBA images. ([\#6241](https://github.com/matrix-org/synapse/issues/6241))
- Correctly apply the event filter to the `state`, `events_before` and `events_after` fields in the response to `/context` requests. ([\#6329](https://github.com/matrix-org/synapse/issues/6329))
- Fix caching devices for remote users when using workers, so that we don't attempt to refetch (and potentially fail) each time a user requests devices. ([\#6332](https://github.com/matrix-org/synapse/issues/6332))
- Prevent account data syncs getting lost across TCP replication. ([\#6333](https://github.com/matrix-org/synapse/issues/6333))
- Fix bug: TypeError in `register_user()` while using LDAP auth module. ([\#6406](https://github.com/matrix-org/synapse/issues/6406))
- Fix an intermittent exception when handling read-receipts. ([\#6408](https://github.com/matrix-org/synapse/issues/6408))
- Fix broken guest registration when there are existing blocks of numeric user IDs. ([\#6420](https://github.com/matrix-org/synapse/issues/6420))
- Fix startup error when http proxy is defined. ([\#6421](https://github.com/matrix-org/synapse/issues/6421))
- Fix error when using synapse_port_db on a vanilla synapse db. ([\#6449](https://github.com/matrix-org/synapse/issues/6449))
- Fix uploading multiple cross signing signatures for the same user. ([\#6451](https://github.com/matrix-org/synapse/issues/6451))
- Fix bug which lead to exceptions being thrown in a loop when a cross-signed device is deleted. ([\#6462](https://github.com/matrix-org/synapse/issues/6462))
- Fix `synapse_port_db` not exiting with a 0 code if something went wrong during the port process. ([\#6470](https://github.com/matrix-org/synapse/issues/6470))
- Improve sanity-checking when receiving events over federation. ([\#6472](https://github.com/matrix-org/synapse/issues/6472))
- Fix inaccurate per-block Prometheus metrics. ([\#6491](https://github.com/matrix-org/synapse/issues/6491))
- Fix small performance regression for sending invites. ([\#6493](https://github.com/matrix-org/synapse/issues/6493))
- Back out cross-signing code added in Synapse 1.5.0, which caused a performance regression. ([\#6494](https://github.com/matrix-org/synapse/issues/6494))


Improved Documentation
----------------------

- Update documentation and variables in user contributed systemd reference file. ([\#6369](https://github.com/matrix-org/synapse/issues/6369), [\#6490](https://github.com/matrix-org/synapse/issues/6490))
- Fix link in the user directory documentation. ([\#6388](https://github.com/matrix-org/synapse/issues/6388))
- Add build instructions to the docker readme. ([\#6390](https://github.com/matrix-org/synapse/issues/6390))
- Switch Ubuntu package install recommendation to use python3 packages in INSTALL.md. ([\#6443](https://github.com/matrix-org/synapse/issues/6443))
- Write some docs for the quarantine_media api. ([\#6458](https://github.com/matrix-org/synapse/issues/6458))
- Convert CONTRIBUTING.rst to markdown (among other small fixes). ([\#6461](https://github.com/matrix-org/synapse/issues/6461))


Deprecations and Removals
-------------------------

- Remove admin/v1/users_paginate endpoint. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#5925](https://github.com/matrix-org/synapse/issues/5925))
- Remove fallback for federation with old servers which lack the /federation/v1/state_ids API. ([\#6488](https://github.com/matrix-org/synapse/issues/6488))


Internal Changes
----------------

- Add benchmarks for structured logging and improve output performance. ([\#6266](https://github.com/matrix-org/synapse/issues/6266))
- Improve the performance of outputting structured logging. ([\#6322](https://github.com/matrix-org/synapse/issues/6322))
- Refactor some code in the event authentication path for clarity. ([\#6343](https://github.com/matrix-org/synapse/issues/6343), [\#6468](https://github.com/matrix-org/synapse/issues/6468), [\#6480](https://github.com/matrix-org/synapse/issues/6480))
- Clean up some unnecessary quotation marks around the codebase. ([\#6362](https://github.com/matrix-org/synapse/issues/6362))
- Complain on startup instead of 500'ing during runtime when `public_baseurl` isn't set when necessary. ([\#6379](https://github.com/matrix-org/synapse/issues/6379))
- Add a test scenario to make sure room history purges don't break `/messages` in the future. ([\#6392](https://github.com/matrix-org/synapse/issues/6392))
- Clarifications for the email configuration settings. ([\#6423](https://github.com/matrix-org/synapse/issues/6423))
- Add more tests to the blacklist when running in worker mode. ([\#6429](https://github.com/matrix-org/synapse/issues/6429))
- Refactor data store layer to support multiple databases in the future. ([\#6454](https://github.com/matrix-org/synapse/issues/6454), [\#6464](https://github.com/matrix-org/synapse/issues/6464), [\#6469](https://github.com/matrix-org/synapse/issues/6469), [\#6487](https://github.com/matrix-org/synapse/issues/6487))
- Port synapse.rest.client.v1 to async/await. ([\#6482](https://github.com/matrix-org/synapse/issues/6482))
- Port synapse.rest.client.v2_alpha to async/await. ([\#6483](https://github.com/matrix-org/synapse/issues/6483))
- Port SyncHandler to async/await. ([\#6484](https://github.com/matrix-org/synapse/issues/6484))

Synapse 1.6.1 (2019-11-28)
==========================

Security updates
----------------

This release includes a security fix ([\#6426](https://github.com/matrix-org/synapse/issues/6426), below). Administrators are encouraged to upgrade as soon as possible.

Bugfixes
--------

- Clean up local threepids from user on account deactivation. ([\#6426](https://github.com/matrix-org/synapse/issues/6426))
- Fix startup error when http proxy is defined. ([\#6421](https://github.com/matrix-org/synapse/issues/6421))


Synapse 1.6.0 (2019-11-26)
==========================

Bugfixes
--------

- Fix phone home stats reporting. ([\#6418](https://github.com/matrix-org/synapse/issues/6418))


Synapse 1.6.0rc2 (2019-11-25)
=============================

Bugfixes
--------

- Fix a bug which could cause the background database update handler for event labels to get stuck in a loop raising exceptions. ([\#6407](https://github.com/matrix-org/synapse/issues/6407))


Synapse 1.6.0rc1 (2019-11-20)
=============================

Features
--------

- Add federation support for cross-signing. ([\#5727](https://github.com/matrix-org/synapse/issues/5727))
- Increase default room version from 4 to 5, thereby enforcing server key validity period checks. ([\#6220](https://github.com/matrix-org/synapse/issues/6220))
- Add support for outbound http proxying via http_proxy/HTTPS_PROXY env vars. ([\#6238](https://github.com/matrix-org/synapse/issues/6238))
- Implement label-based filtering on `/sync` and `/messages` ([MSC2326](https://github.com/matrix-org/matrix-doc/pull/2326)). ([\#6301](https://github.com/matrix-org/synapse/issues/6301), [\#6310](https://github.com/matrix-org/synapse/issues/6310), [\#6340](https://github.com/matrix-org/synapse/issues/6340))


Bugfixes
--------

- Fix LruCache callback deduplication for Python 3.8. Contributed by @V02460. ([\#6213](https://github.com/matrix-org/synapse/issues/6213))
- Remove a room from a server's public rooms list on room upgrade. ([\#6232](https://github.com/matrix-org/synapse/issues/6232), [\#6235](https://github.com/matrix-org/synapse/issues/6235))
- Delete keys from key backup when deleting backup versions. ([\#6253](https://github.com/matrix-org/synapse/issues/6253))
- Make notification of cross-signing signatures work with workers. ([\#6254](https://github.com/matrix-org/synapse/issues/6254))
- Fix exception when remote servers attempt to join a room that they're not allowed to join. ([\#6278](https://github.com/matrix-org/synapse/issues/6278))
- Prevent errors from appearing on Synapse startup if `git` is not installed. ([\#6284](https://github.com/matrix-org/synapse/issues/6284))
- Appservice requests will no longer contain a double slash prefix when the appservice url provided ends in a slash. ([\#6306](https://github.com/matrix-org/synapse/issues/6306))
- Fix `/purge_room` admin API. ([\#6307](https://github.com/matrix-org/synapse/issues/6307))
- Fix the `hidden` field in the `devices` table for SQLite versions prior to 3.23.0. ([\#6313](https://github.com/matrix-org/synapse/issues/6313))
- Fix bug which caused rejected events to be persisted with the wrong room state. ([\#6320](https://github.com/matrix-org/synapse/issues/6320))
- Fix bug where `rc_login` ratelimiting would prematurely kick in. ([\#6335](https://github.com/matrix-org/synapse/issues/6335))
- Prevent the server taking a long time to start up when guest registration is enabled. ([\#6338](https://github.com/matrix-org/synapse/issues/6338))
- Fix bug where upgrading a guest account to a full user would fail when account validity is enabled. ([\#6359](https://github.com/matrix-org/synapse/issues/6359))
- Fix `to_device` stream ID getting reset every time Synapse restarts, which had the potential to cause unable to decrypt errors. ([\#6363](https://github.com/matrix-org/synapse/issues/6363))
- Fix permission denied error when trying to generate a config file with the docker image. ([\#6389](https://github.com/matrix-org/synapse/issues/6389))


Improved Documentation
----------------------

- Contributor documentation now mentions script to run linters. ([\#6164](https://github.com/matrix-org/synapse/issues/6164))
- Modify CAPTCHA_SETUP.md to update the terms `private key` and `public key` to `secret key` and `site key` respectively. Contributed by Yash Jipkate. ([\#6257](https://github.com/matrix-org/synapse/issues/6257))
- Update `INSTALL.md` Email section to talk about `account_threepid_delegates`. ([\#6272](https://github.com/matrix-org/synapse/issues/6272))
- Fix a small typo in `account_threepid_delegates` configuration option. ([\#6273](https://github.com/matrix-org/synapse/issues/6273))


Internal Changes
----------------

- Add a CI job to test the `synapse_port_db` script. ([\#6140](https://github.com/matrix-org/synapse/issues/6140), [\#6276](https://github.com/matrix-org/synapse/issues/6276))
- Convert EventContext to an attrs. ([\#6218](https://github.com/matrix-org/synapse/issues/6218))
- Move `persist_events` out from main data store. ([\#6240](https://github.com/matrix-org/synapse/issues/6240), [\#6300](https://github.com/matrix-org/synapse/issues/6300))
- Reduce verbosity of user/room stats. ([\#6250](https://github.com/matrix-org/synapse/issues/6250))
- Reduce impact of debug logging. ([\#6251](https://github.com/matrix-org/synapse/issues/6251))
- Expose some homeserver functionality to spam checkers. ([\#6259](https://github.com/matrix-org/synapse/issues/6259))
- Change cache descriptors to always return deferreds. ([\#6263](https://github.com/matrix-org/synapse/issues/6263), [\#6291](https://github.com/matrix-org/synapse/issues/6291))
- Fix incorrect comment regarding the functionality of an `if` statement. ([\#6269](https://github.com/matrix-org/synapse/issues/6269))
- Update CI to run `isort` over the `scripts` and `scripts-dev` directories. ([\#6270](https://github.com/matrix-org/synapse/issues/6270))
- Replace every instance of `logger.warn` method with `logger.warning` as the former is deprecated. ([\#6271](https://github.com/matrix-org/synapse/issues/6271), [\#6314](https://github.com/matrix-org/synapse/issues/6314))
- Port replication http server endpoints to async/await. ([\#6274](https://github.com/matrix-org/synapse/issues/6274))
- Port room rest handlers to async/await. ([\#6275](https://github.com/matrix-org/synapse/issues/6275))
- Remove redundant CLI parameters on CI's `flake8` step. ([\#6277](https://github.com/matrix-org/synapse/issues/6277))
- Port `federation_server.py` to async/await. ([\#6279](https://github.com/matrix-org/synapse/issues/6279))
- Port receipt and read markers to async/wait. ([\#6280](https://github.com/matrix-org/synapse/issues/6280))
- Split out state storage into separate data store. ([\#6294](https://github.com/matrix-org/synapse/issues/6294), [\#6295](https://github.com/matrix-org/synapse/issues/6295))
- Refactor EventContext for clarity. ([\#6298](https://github.com/matrix-org/synapse/issues/6298))
- Update the version of black used to 19.10b0. ([\#6304](https://github.com/matrix-org/synapse/issues/6304))
- Add some documentation about worker replication. ([\#6305](https://github.com/matrix-org/synapse/issues/6305))
- Move admin endpoints into separate files. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#6308](https://github.com/matrix-org/synapse/issues/6308))
- Document the use of `lint.sh` for code style enforcement & extend it to run on specified paths only. ([\#6312](https://github.com/matrix-org/synapse/issues/6312))
- Add optional python dependencies and dependent binary libraries to snapcraft packaging. ([\#6317](https://github.com/matrix-org/synapse/issues/6317))
- Remove the dependency on psutil and replace functionality with the stdlib `resource` module. ([\#6318](https://github.com/matrix-org/synapse/issues/6318), [\#6336](https://github.com/matrix-org/synapse/issues/6336))
- Improve documentation for EventContext fields. ([\#6319](https://github.com/matrix-org/synapse/issues/6319))
- Add some checks that we aren't using state from rejected events. ([\#6330](https://github.com/matrix-org/synapse/issues/6330))
- Add continuous integration for python 3.8. ([\#6341](https://github.com/matrix-org/synapse/issues/6341))
- Correct spacing/case of various instances of the word "homeserver". ([\#6357](https://github.com/matrix-org/synapse/issues/6357))
- Temporarily blacklist the failing unit test PurgeRoomTestCase.test_purge_room. ([\#6361](https://github.com/matrix-org/synapse/issues/6361))


Synapse 1.5.1 (2019-11-06)
==========================

Features
--------

- Limit the length of data returned by url previews, to prevent DoS attacks. ([\#6331](https://github.com/matrix-org/synapse/issues/6331), [\#6334](https://github.com/matrix-org/synapse/issues/6334))


Synapse 1.5.0 (2019-10-29)
==========================

Security updates
----------------

This release includes a security fix ([\#6262](https://github.com/matrix-org/synapse/issues/6262), below). Administrators are encouraged to upgrade as soon as possible.

Bugfixes
--------

- Fix bug where room directory search was case sensitive. ([\#6268](https://github.com/matrix-org/synapse/issues/6268))


Synapse 1.5.0rc2 (2019-10-28)
=============================

Bugfixes
--------

- Update list of boolean columns in `synapse_port_db`. ([\#6247](https://github.com/matrix-org/synapse/issues/6247))
- Fix /keys/query API on workers. ([\#6256](https://github.com/matrix-org/synapse/issues/6256))
- Improve signature checking on some federation APIs. ([\#6262](https://github.com/matrix-org/synapse/issues/6262))


Internal Changes
----------------

- Move schema delta files to the correct data store. ([\#6248](https://github.com/matrix-org/synapse/issues/6248))
- Small performance improvement by removing repeated config lookups in room stats calculation. ([\#6255](https://github.com/matrix-org/synapse/issues/6255))


Synapse 1.5.0rc1 (2019-10-24)
==========================

Features
--------

- Improve quality of thumbnails for 1-bit/8-bit color palette images. ([\#2142](https://github.com/matrix-org/synapse/issues/2142))
- Add ability to upload cross-signing signatures. ([\#5726](https://github.com/matrix-org/synapse/issues/5726))
- Allow uploading of cross-signing keys. ([\#5769](https://github.com/matrix-org/synapse/issues/5769))
- CAS login now provides a default display name for users if a `displayname_attribute` is set in the configuration file. ([\#6114](https://github.com/matrix-org/synapse/issues/6114))
- Reject all pending invites for a user during deactivation. ([\#6125](https://github.com/matrix-org/synapse/issues/6125))
- Add config option to suppress client side resource limit alerting. ([\#6173](https://github.com/matrix-org/synapse/issues/6173))


Bugfixes
--------

- Return an HTTP 404 instead of 400 when requesting a filter by ID that is unknown to the server. Thanks to @krombel for contributing this! ([\#2380](https://github.com/matrix-org/synapse/issues/2380))
- Fix a bug where users could be invited twice to the same group. ([\#3436](https://github.com/matrix-org/synapse/issues/3436))
- Fix `/createRoom` failing with badly-formatted MXIDs in the invitee list. Thanks to @wener291! ([\#4088](https://github.com/matrix-org/synapse/issues/4088))
- Make the `synapse_port_db` script create the right indexes on a new PostgreSQL database. ([\#6102](https://github.com/matrix-org/synapse/issues/6102), [\#6178](https://github.com/matrix-org/synapse/issues/6178), [\#6243](https://github.com/matrix-org/synapse/issues/6243))
- Fix bug when uploading a large file: Synapse responds with `M_UNKNOWN` while it should be `M_TOO_LARGE` according to spec. Contributed by Anshul Angaria. ([\#6109](https://github.com/matrix-org/synapse/issues/6109))
- Fix user push rules being deleted from a room when it is upgraded. ([\#6144](https://github.com/matrix-org/synapse/issues/6144))
- Don't 500 when trying to exchange a revoked 3PID invite. ([\#6147](https://github.com/matrix-org/synapse/issues/6147))
- Fix transferring notifications and tags when joining an upgraded room that is new to your server. ([\#6155](https://github.com/matrix-org/synapse/issues/6155))
- Fix bug where guest account registration can wedge after restart. ([\#6161](https://github.com/matrix-org/synapse/issues/6161))
- Fix monthly active user reaping when reserved users are specified. ([\#6168](https://github.com/matrix-org/synapse/issues/6168))
- Fix `/federation/v1/state` endpoint not supporting newer room versions. ([\#6170](https://github.com/matrix-org/synapse/issues/6170))
- Fix bug where we were updating censored events as bytes rather than text, occaisonally causing invalid JSON being inserted breaking APIs that attempted to fetch such events. ([\#6186](https://github.com/matrix-org/synapse/issues/6186))
- Fix occasional missed updates in the room and user directories. ([\#6187](https://github.com/matrix-org/synapse/issues/6187))
- Fix tracing of non-JSON APIs, `/media`, `/key` etc. ([\#6195](https://github.com/matrix-org/synapse/issues/6195))
- Fix bug where presence would not get timed out correctly if a synchrotron worker is used and restarted. ([\#6212](https://github.com/matrix-org/synapse/issues/6212))
- synapse_port_db: Add 2 additional BOOLEAN_COLUMNS to be able to convert from database schema v56. ([\#6216](https://github.com/matrix-org/synapse/issues/6216))
- Fix a bug where the Synapse demo script blacklisted `::1` (ipv6 localhost) from receiving federation traffic. ([\#6229](https://github.com/matrix-org/synapse/issues/6229))


Updates to the Docker image
---------------------------

- Fix logging getting lost for the docker image. ([\#6197](https://github.com/matrix-org/synapse/issues/6197))


Internal Changes
----------------

- Update `user_filters` table to have a unique index, and non-null columns. Thanks to @pik for contributing this. ([\#1172](https://github.com/matrix-org/synapse/issues/1172), [\#6175](https://github.com/matrix-org/synapse/issues/6175), [\#6184](https://github.com/matrix-org/synapse/issues/6184))
- Allow devices to be marked as hidden, for use by features such as cross-signing.
  This adds a new field with a default value to the devices field in the database,
  and so the database upgrade may take a long time depending on how many devices
  are in the database. ([\#5759](https://github.com/matrix-org/synapse/issues/5759))
- Move lookup-related functions from RoomMemberHandler to IdentityHandler. ([\#5978](https://github.com/matrix-org/synapse/issues/5978))
- Improve performance of the public room list directory. ([\#6019](https://github.com/matrix-org/synapse/issues/6019), [\#6152](https://github.com/matrix-org/synapse/issues/6152), [\#6153](https://github.com/matrix-org/synapse/issues/6153), [\#6154](https://github.com/matrix-org/synapse/issues/6154))
- Edit header dicts docstrings in `SimpleHttpClient` to note that `str` or `bytes` can be passed as header keys. ([\#6077](https://github.com/matrix-org/synapse/issues/6077))
- Add snapcraft packaging information. Contributed by @devec0. ([\#6084](https://github.com/matrix-org/synapse/issues/6084), [\#6191](https://github.com/matrix-org/synapse/issues/6191))
- Kill off half-implemented password-reset via sms. ([\#6101](https://github.com/matrix-org/synapse/issues/6101))
- Remove `get_user_by_req` opentracing span and add some tags. ([\#6108](https://github.com/matrix-org/synapse/issues/6108))
- Drop some unused database tables. ([\#6115](https://github.com/matrix-org/synapse/issues/6115))
- Add env var to turn on tracking of log context changes. ([\#6127](https://github.com/matrix-org/synapse/issues/6127))
- Refactor configuration loading to allow better typechecking. ([\#6137](https://github.com/matrix-org/synapse/issues/6137))
- Log responder when responding to media request. ([\#6139](https://github.com/matrix-org/synapse/issues/6139))
- Improve performance of `find_next_generated_user_id` DB query. ([\#6148](https://github.com/matrix-org/synapse/issues/6148))
- Expand type-checking on modules imported by `synapse.config`. ([\#6150](https://github.com/matrix-org/synapse/issues/6150))
- Use Postgres ANY for selecting many values. ([\#6156](https://github.com/matrix-org/synapse/issues/6156))
- Add more caching to `_get_joined_users_from_context` DB query. ([\#6159](https://github.com/matrix-org/synapse/issues/6159))
- Add some metrics on the federation sender. ([\#6160](https://github.com/matrix-org/synapse/issues/6160))
- Add some logging to the rooms stats updates, to try to track down a flaky test. ([\#6167](https://github.com/matrix-org/synapse/issues/6167))
- Remove unused `timeout` parameter from `_get_public_room_list`. ([\#6179](https://github.com/matrix-org/synapse/issues/6179))
- Reject (accidental) attempts to insert bytes into postgres tables. ([\#6186](https://github.com/matrix-org/synapse/issues/6186))
- Make `version` optional in body of `PUT /room_keys/version/{version}`, since it's redundant. ([\#6189](https://github.com/matrix-org/synapse/issues/6189))
- Make storage layer responsible for adding device names to key, rather than the handler. ([\#6193](https://github.com/matrix-org/synapse/issues/6193))
- Port `synapse.rest.admin` module to use async/await. ([\#6196](https://github.com/matrix-org/synapse/issues/6196))
- Enforce that all boolean configuration values are lowercase in CI. ([\#6203](https://github.com/matrix-org/synapse/issues/6203))
- Remove some unused event-auth code. ([\#6214](https://github.com/matrix-org/synapse/issues/6214))
- Remove `Auth.check` method. ([\#6217](https://github.com/matrix-org/synapse/issues/6217))
- Remove `format_tap.py` script in favour of a perl reimplementation in Sytest's repo. ([\#6219](https://github.com/matrix-org/synapse/issues/6219))
- Refactor storage layer in preparation to support having multiple databases. ([\#6231](https://github.com/matrix-org/synapse/issues/6231))
- Remove some extra quotation marks across the codebase. ([\#6236](https://github.com/matrix-org/synapse/issues/6236))


Synapse 1.4.1 (2019-10-18)
==========================

No changes since 1.4.1rc1.


Synapse 1.4.1rc1 (2019-10-17)
=============================

Bugfixes
--------

- Fix bug where redacted events were sometimes incorrectly censored in the database, breaking APIs that attempted to fetch such events. ([\#6185](https://github.com/matrix-org/synapse/issues/6185), [5b0e9948](https://github.com/matrix-org/synapse/commit/5b0e9948eaae801643e594b5abc8ee4b10bd194e))

Synapse 1.4.0 (2019-10-03)
==========================

Bugfixes
--------

- Redact `client_secret` in server logs. ([\#6158](https://github.com/matrix-org/synapse/issues/6158))


Synapse 1.4.0rc2 (2019-10-02)
=============================

Bugfixes
--------

- Fix bug in background update that adds last seen information to the `devices` table, and improve its performance on Postgres. ([\#6135](https://github.com/matrix-org/synapse/issues/6135))
- Fix bad performance of censoring redactions background task. ([\#6141](https://github.com/matrix-org/synapse/issues/6141))
- Fix fetching censored redactions from DB, which caused APIs like initial sync to fail if it tried to include the censored redaction. ([\#6145](https://github.com/matrix-org/synapse/issues/6145))
- Fix exceptions when storing large retry intervals for down remote servers. ([\#6146](https://github.com/matrix-org/synapse/issues/6146))


Internal Changes
----------------

- Fix up sample config entry for `redaction_retention_period` option. ([\#6117](https://github.com/matrix-org/synapse/issues/6117))


Synapse 1.4.0rc1 (2019-09-26)
=============================

Note that this release includes significant changes around 3pid
verification. Administrators are reminded to review the [upgrade notes](docs/upgrade.md#upgrading-to-v140).

Features
--------

- Changes to 3pid verification:
  - Add the ability to send registration emails from the homeserver rather than delegating to an identity server. ([\#5835](https://github.com/matrix-org/synapse/issues/5835), [\#5940](https://github.com/matrix-org/synapse/issues/5940), [\#5993](https://github.com/matrix-org/synapse/issues/5993), [\#5994](https://github.com/matrix-org/synapse/issues/5994), [\#5868](https://github.com/matrix-org/synapse/issues/5868))
  - Replace `trust_identity_server_for_password_resets` config option with `account_threepid_delegates`, and make the `id_server` parameteter optional on `*/requestToken` endpoints, as per [MSC2263](https://github.com/matrix-org/matrix-doc/pull/2263). ([\#5876](https://github.com/matrix-org/synapse/issues/5876), [\#5969](https://github.com/matrix-org/synapse/issues/5969), [\#6028](https://github.com/matrix-org/synapse/issues/6028))
  - Switch to using the v2 Identity Service `/lookup` API where available, with fallback to v1. (Implements [MSC2134](https://github.com/matrix-org/matrix-doc/pull/2134) plus `id_access_token authentication` for v2 Identity Service APIs from [MSC2140](https://github.com/matrix-org/matrix-doc/pull/2140)). ([\#5897](https://github.com/matrix-org/synapse/issues/5897))
  - Remove `bind_email` and `bind_msisdn` parameters from `/register` ala [MSC2140](https://github.com/matrix-org/matrix-doc/pull/2140). ([\#5964](https://github.com/matrix-org/synapse/issues/5964))
  - Add `m.id_access_token` to `unstable_features` in `/versions` as per [MSC2264](https://github.com/matrix-org/matrix-doc/pull/2264). ([\#5974](https://github.com/matrix-org/synapse/issues/5974))
  - Use the v2 Identity Service API for 3PID invites. ([\#5979](https://github.com/matrix-org/synapse/issues/5979))
  - Add `POST /_matrix/client/unstable/account/3pid/unbind` endpoint from [MSC2140](https://github.com/matrix-org/matrix-doc/pull/2140) for unbinding a 3PID from an identity server without removing it from the homeserver user account. ([\#5980](https://github.com/matrix-org/synapse/issues/5980), [\#6062](https://github.com/matrix-org/synapse/issues/6062))
  - Use `account_threepid_delegate.email` and `account_threepid_delegate.msisdn` for validating threepid sessions. ([\#6011](https://github.com/matrix-org/synapse/issues/6011))
  - Allow homeserver to handle or delegate email validation when adding an email to a user's account. ([\#6042](https://github.com/matrix-org/synapse/issues/6042))
  - Implement new Client Server API endpoints `/account/3pid/add` and `/account/3pid/bind` as per [MSC2290](https://github.com/matrix-org/matrix-doc/pull/2290). ([\#6043](https://github.com/matrix-org/synapse/issues/6043))
  - Add an unstable feature flag for separate add/bind 3pid APIs. ([\#6044](https://github.com/matrix-org/synapse/issues/6044))
  - Remove `bind` parameter from Client Server POST `/account` endpoint as per [MSC2290](https://github.com/matrix-org/matrix-doc/pull/2290/). ([\#6067](https://github.com/matrix-org/synapse/issues/6067))
  - Add `POST /add_threepid/msisdn/submit_token` endpoint for proxying submitToken on an `account_threepid_handler`. ([\#6078](https://github.com/matrix-org/synapse/issues/6078))
  - Add `submit_url` response parameter to `*/msisdn/requestToken` endpoints. ([\#6079](https://github.com/matrix-org/synapse/issues/6079))
  - Add `m.require_identity_server` flag to /version's unstable_features. ([\#5972](https://github.com/matrix-org/synapse/issues/5972))
- Enhancements to OpenTracing support:
  - Make OpenTracing work in worker mode. ([\#5771](https://github.com/matrix-org/synapse/issues/5771))
  - Pass OpenTracing contexts between servers when transmitting EDUs. ([\#5852](https://github.com/matrix-org/synapse/issues/5852))
  - OpenTracing for device list updates. ([\#5853](https://github.com/matrix-org/synapse/issues/5853))
  - Add a tag recording a request's authenticated entity and corresponding servlet in OpenTracing. ([\#5856](https://github.com/matrix-org/synapse/issues/5856))
  - Add minimum OpenTracing for client servlets. ([\#5983](https://github.com/matrix-org/synapse/issues/5983))
  - Check at setup that OpenTracing is installed if it's enabled in the config. ([\#5985](https://github.com/matrix-org/synapse/issues/5985))
  - Trace replication send times. ([\#5986](https://github.com/matrix-org/synapse/issues/5986))
  - Include missing OpenTracing contexts in outbout replication requests. ([\#5982](https://github.com/matrix-org/synapse/issues/5982))
  - Fix sending of EDUs when OpenTracing is enabled with an empty whitelist. ([\#5984](https://github.com/matrix-org/synapse/issues/5984))
  - Fix invalid references to None while OpenTracing if the log context slips. ([\#5988](https://github.com/matrix-org/synapse/issues/5988), [\#5991](https://github.com/matrix-org/synapse/issues/5991))
  - OpenTracing for room and e2e keys. ([\#5855](https://github.com/matrix-org/synapse/issues/5855))
  - Add OpenTracing span over HTTP push processing. ([\#6003](https://github.com/matrix-org/synapse/issues/6003))
- Add an admin API to purge old rooms from the database. ([\#5845](https://github.com/matrix-org/synapse/issues/5845))
- Retry well-known lookups if we have recently seen a valid well-known record for the server. ([\#5850](https://github.com/matrix-org/synapse/issues/5850))
- Add support for filtered room-directory search requests over federation ([MSC2197](https://github.com/matrix-org/matrix-doc/pull/2197), in order to allow upcoming room directory query performance improvements. ([\#5859](https://github.com/matrix-org/synapse/issues/5859))
- Correctly retry all hosts returned from SRV when we fail to connect. ([\#5864](https://github.com/matrix-org/synapse/issues/5864))
- Add admin API endpoint for setting whether or not a user is a server administrator. ([\#5878](https://github.com/matrix-org/synapse/issues/5878))
- Enable cleaning up extremities with dummy events by default to prevent undue build up of forward extremities. ([\#5884](https://github.com/matrix-org/synapse/issues/5884))
- Add config option to sign remote key query responses with a separate key. ([\#5895](https://github.com/matrix-org/synapse/issues/5895))
- Add support for config templating. ([\#5900](https://github.com/matrix-org/synapse/issues/5900))
- Users with the type of "support" or "bot" are no longer required to consent. ([\#5902](https://github.com/matrix-org/synapse/issues/5902))
- Let synctl accept a directory of config files. ([\#5904](https://github.com/matrix-org/synapse/issues/5904))
- Increase max display name size to 256. ([\#5906](https://github.com/matrix-org/synapse/issues/5906))
- Add admin API endpoint for getting whether or not a user is a server administrator. ([\#5914](https://github.com/matrix-org/synapse/issues/5914))
- Redact events in the database that have been redacted for a week. ([\#5934](https://github.com/matrix-org/synapse/issues/5934))
- New prometheus metrics:
  - `synapse_federation_known_servers`: represents the total number of servers your server knows about (i.e. is in rooms with), including itself. Enable by setting `metrics_flags.known_servers` to True in the configuration.([\#5981](https://github.com/matrix-org/synapse/issues/5981))
  - `synapse_build_info`: exposes the Python version, OS version, and Synapse version of the running server. ([\#6005](https://github.com/matrix-org/synapse/issues/6005))
- Give appropriate exit codes when synctl fails. ([\#5992](https://github.com/matrix-org/synapse/issues/5992))
- Apply the federation blacklist to requests to identity servers. ([\#6000](https://github.com/matrix-org/synapse/issues/6000))
- Add `report_stats_endpoint` option to configure where stats are reported to, if enabled. Contributed by @Sorunome. ([\#6012](https://github.com/matrix-org/synapse/issues/6012))
- Add config option to increase ratelimits for room admins redacting messages. ([\#6015](https://github.com/matrix-org/synapse/issues/6015))
- Stop sending federation transactions to servers which have been down for a long time. ([\#6026](https://github.com/matrix-org/synapse/issues/6026))
- Make the process for mapping SAML2 users to matrix IDs more flexible. ([\#6037](https://github.com/matrix-org/synapse/issues/6037))
- Return a clearer error message when a timeout occurs when attempting to contact an identity server. ([\#6073](https://github.com/matrix-org/synapse/issues/6073))
- Prevent password reset's submit_token endpoint from accepting trailing slashes. ([\#6074](https://github.com/matrix-org/synapse/issues/6074))
- Return 403 on `/register/available` if registration has been disabled. ([\#6082](https://github.com/matrix-org/synapse/issues/6082))
- Explicitly log when a homeserver does not have the `trusted_key_servers` config field configured. ([\#6090](https://github.com/matrix-org/synapse/issues/6090))
- Add support for pruning old rows in `user_ips` table. ([\#6098](https://github.com/matrix-org/synapse/issues/6098))

Bugfixes
--------

- Don't create broken room when `power_level_content_override.users` does not contain `creator_id`. ([\#5633](https://github.com/matrix-org/synapse/issues/5633))
- Fix database index so that different backup versions can have the same sessions. ([\#5857](https://github.com/matrix-org/synapse/issues/5857))
- Fix Synapse looking for config options `password_reset_failure_template` and `password_reset_success_template`, when they are actually `password_reset_template_failure_html`, `password_reset_template_success_html`. ([\#5863](https://github.com/matrix-org/synapse/issues/5863))
- Fix stack overflow when recovering an appservice which had an outage. ([\#5885](https://github.com/matrix-org/synapse/issues/5885))
- Fix error message which referred to `public_base_url` instead of `public_baseurl`. Thanks to @aaronraimist for the fix! ([\#5909](https://github.com/matrix-org/synapse/issues/5909))
- Fix 404 for thumbnail download when `dynamic_thumbnails` is `false` and the thumbnail was dynamically generated. Fix reported by rkfg. ([\#5915](https://github.com/matrix-org/synapse/issues/5915))
- Fix a cache-invalidation bug for worker-based deployments. ([\#5920](https://github.com/matrix-org/synapse/issues/5920))
- Fix admin API for listing media in a room not being available with an external media repo. ([\#5966](https://github.com/matrix-org/synapse/issues/5966))
- Fix list media admin API always returning an error. ([\#5967](https://github.com/matrix-org/synapse/issues/5967))
- Fix room and user stats tracking. ([\#5971](https://github.com/matrix-org/synapse/issues/5971), [\#5998](https://github.com/matrix-org/synapse/issues/5998), [\#6029](https://github.com/matrix-org/synapse/issues/6029))
- Return a `M_MISSING_PARAM` if `sid` is not provided to `/account/3pid`. ([\#5995](https://github.com/matrix-org/synapse/issues/5995))
- `federation_certificate_verification_whitelist` now will not cause `TypeErrors` to be raised (a regression in 1.3). Additionally, it now supports internationalised domain names in their non-canonical representation. ([\#5996](https://github.com/matrix-org/synapse/issues/5996))
- Only count real users when checking for auto-creation of auto-join room. ([\#6004](https://github.com/matrix-org/synapse/issues/6004))
- Ensure support users can be registered even if MAU limit is reached. ([\#6020](https://github.com/matrix-org/synapse/issues/6020))
- Fix bug where login error was shown incorrectly on SSO fallback login. ([\#6024](https://github.com/matrix-org/synapse/issues/6024))
- Fix bug in calculating the federation retry backoff period. ([\#6025](https://github.com/matrix-org/synapse/issues/6025))
- Prevent exceptions being logged when extremity-cleanup events fail due to lack of user consent to the terms of service. ([\#6053](https://github.com/matrix-org/synapse/issues/6053))
- Remove POST method from password-reset `submit_token` endpoint until we implement `submit_url` functionality. ([\#6056](https://github.com/matrix-org/synapse/issues/6056))
- Fix logcontext spam on non-Linux platforms. ([\#6059](https://github.com/matrix-org/synapse/issues/6059))
- Ensure query parameters in email validation links are URL-encoded. ([\#6063](https://github.com/matrix-org/synapse/issues/6063))
- Fix a bug which caused SAML attribute maps to be overridden by defaults. ([\#6069](https://github.com/matrix-org/synapse/issues/6069))
- Fix the logged number of updated items for the `users_set_deactivated_flag` background update. ([\#6092](https://github.com/matrix-org/synapse/issues/6092))
- Add `sid` to `next_link` for email validation. ([\#6097](https://github.com/matrix-org/synapse/issues/6097))
- Threepid validity checks on msisdns should not be dependent on `threepid_behaviour_email`. ([\#6104](https://github.com/matrix-org/synapse/issues/6104))
- Ensure that servers which are not configured to support email address verification do not offer it in the registration flows. ([\#6107](https://github.com/matrix-org/synapse/issues/6107))


Updates to the Docker image
---------------------------

- Avoid changing `UID/GID` if they are already correct. ([\#5970](https://github.com/matrix-org/synapse/issues/5970))
- Provide `SYNAPSE_WORKER` envvar to specify python module. ([\#6058](https://github.com/matrix-org/synapse/issues/6058))


Improved Documentation
----------------------

- Convert documentation to markdown (from rst) ([\#5849](https://github.com/matrix-org/synapse/issues/5849))
- Update `INSTALL.md` to say that Python 2 is no longer supported. ([\#5953](https://github.com/matrix-org/synapse/issues/5953))
- Add developer documentation for using SAML2. ([\#6032](https://github.com/matrix-org/synapse/issues/6032))
- Add some notes on rolling back to v1.3.1. ([\#6049](https://github.com/matrix-org/synapse/issues/6049))
- Update the upgrade notes. ([\#6050](https://github.com/matrix-org/synapse/issues/6050))


Deprecations and Removals
-------------------------

- Remove shared-secret registration from `/_matrix/client/r0/register` endpoint. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#5877](https://github.com/matrix-org/synapse/issues/5877))
- Deprecate the `trusted_third_party_id_servers` option. ([\#5875](https://github.com/matrix-org/synapse/issues/5875))


Internal Changes
----------------

- Lay the groundwork for structured logging output. ([\#5680](https://github.com/matrix-org/synapse/issues/5680))
- Retry well-known lookup before the cache expires, giving a grace period where the remote well-known can be down but we still use the old result. ([\#5844](https://github.com/matrix-org/synapse/issues/5844))
- Remove log line for debugging issue #5407. ([\#5860](https://github.com/matrix-org/synapse/issues/5860))
- Refactor the Appservice scheduler code. ([\#5886](https://github.com/matrix-org/synapse/issues/5886))
- Compatibility with v2 Identity Service APIs other than /lookup. ([\#5892](https://github.com/matrix-org/synapse/issues/5892), [\#6013](https://github.com/matrix-org/synapse/issues/6013))
- Stop populating some unused tables. ([\#5893](https://github.com/matrix-org/synapse/issues/5893), [\#6047](https://github.com/matrix-org/synapse/issues/6047))
- Add missing index on `users_in_public_rooms` to improve the performance of directory queries. ([\#5894](https://github.com/matrix-org/synapse/issues/5894))
- Improve the logging when we have an error when fetching signing keys. ([\#5896](https://github.com/matrix-org/synapse/issues/5896))
- Add support for database engine-specific schema deltas, based on file extension. ([\#5911](https://github.com/matrix-org/synapse/issues/5911))
- Update Buildkite pipeline to use plugins instead of buildkite-agent commands. ([\#5922](https://github.com/matrix-org/synapse/issues/5922))
- Add link in sample config to the logging config schema. ([\#5926](https://github.com/matrix-org/synapse/issues/5926))
- Remove unnecessary parentheses in return statements. ([\#5931](https://github.com/matrix-org/synapse/issues/5931))
- Remove unused `jenkins/prepare_sytest.sh` file. ([\#5938](https://github.com/matrix-org/synapse/issues/5938))
- Move Buildkite pipeline config to the pipelines repo. ([\#5943](https://github.com/matrix-org/synapse/issues/5943))
- Remove unnecessary return statements in the codebase which were the result of a regex run. ([\#5962](https://github.com/matrix-org/synapse/issues/5962))
- Remove left-over methods from v1 registration API. ([\#5963](https://github.com/matrix-org/synapse/issues/5963))
- Cleanup event auth type initialisation. ([\#5975](https://github.com/matrix-org/synapse/issues/5975))
- Clean up dependency checking at setup. ([\#5989](https://github.com/matrix-org/synapse/issues/5989))
- Update OpenTracing docs to use the unified `trace` method. ([\#5776](https://github.com/matrix-org/synapse/issues/5776))
- Small refactor of function arguments and docstrings in` RoomMemberHandler`. ([\#6009](https://github.com/matrix-org/synapse/issues/6009))
- Remove unused `origin` argument on `FederationHandler.add_display_name_to_third_party_invite`. ([\#6010](https://github.com/matrix-org/synapse/issues/6010))
- Add a `failure_ts` column to the `destinations` database table. ([\#6016](https://github.com/matrix-org/synapse/issues/6016), [\#6072](https://github.com/matrix-org/synapse/issues/6072))
- Clean up some code in the retry logic. ([\#6017](https://github.com/matrix-org/synapse/issues/6017))
- Fix the structured logging tests stomping on the global log configuration for subsequent tests. ([\#6023](https://github.com/matrix-org/synapse/issues/6023))
- Clean up the sample config for SAML authentication. ([\#6064](https://github.com/matrix-org/synapse/issues/6064))
- Change mailer logging to reflect Synapse doesn't just do chat notifications by email now. ([\#6075](https://github.com/matrix-org/synapse/issues/6075))
- Move last-seen info into devices table. ([\#6089](https://github.com/matrix-org/synapse/issues/6089))
- Remove unused parameter to `get_user_id_by_threepid`. ([\#6099](https://github.com/matrix-org/synapse/issues/6099))
- Refactor the user-interactive auth handling. ([\#6105](https://github.com/matrix-org/synapse/issues/6105))
- Refactor code for calculating registration flows. ([\#6106](https://github.com/matrix-org/synapse/issues/6106))


Synapse 1.3.1 (2019-08-17)
==========================

Features
--------

- Drop hard dependency on `sdnotify` python package. ([\#5871](https://github.com/matrix-org/synapse/issues/5871))


Bugfixes
--------

- Fix startup issue (hang on ACME provisioning) due to ordering of Twisted reactor startup. Thanks to @chrismoos for supplying the fix. ([\#5867](https://github.com/matrix-org/synapse/issues/5867))


Synapse 1.3.0 (2019-08-15)
==========================

Bugfixes
--------

- Fix 500 Internal Server Error on `publicRooms` when the public room list was
  cached. ([\#5851](https://github.com/matrix-org/synapse/issues/5851))


Synapse 1.3.0rc1 (2019-08-13)
==========================

Features
--------

- Use `M_USER_DEACTIVATED` instead of `M_UNKNOWN` for errcode when a deactivated user attempts to login. ([\#5686](https://github.com/matrix-org/synapse/issues/5686))
- Add sd_notify hooks to ease systemd integration and allows usage of Type=Notify. ([\#5732](https://github.com/matrix-org/synapse/issues/5732))
- Synapse will no longer serve any media repo admin endpoints when `enable_media_repo` is set to False in the configuration. If a media repo worker is used, the admin APIs relating to the media repo will be served from it instead. ([\#5754](https://github.com/matrix-org/synapse/issues/5754), [\#5848](https://github.com/matrix-org/synapse/issues/5848))
- Synapse can now be configured to not join remote rooms of a given "complexity" (currently, state events) over federation. This option can be used to prevent adverse performance on resource-constrained homeservers. ([\#5783](https://github.com/matrix-org/synapse/issues/5783))
- Allow defining HTML templates to serve the user on account renewal attempt when using the account validity feature. ([\#5807](https://github.com/matrix-org/synapse/issues/5807))


Bugfixes
--------

- Fix UISIs during homeserver outage. ([\#5693](https://github.com/matrix-org/synapse/issues/5693), [\#5789](https://github.com/matrix-org/synapse/issues/5789))
- Fix stack overflow in server key lookup code. ([\#5724](https://github.com/matrix-org/synapse/issues/5724))
- start.sh no longer uses deprecated cli option. ([\#5725](https://github.com/matrix-org/synapse/issues/5725))
- Log when we receive an event receipt from an unexpected origin. ([\#5743](https://github.com/matrix-org/synapse/issues/5743))
- Fix debian packaging scripts to correctly build sid packages. ([\#5775](https://github.com/matrix-org/synapse/issues/5775))
- Correctly handle redactions of redactions. ([\#5788](https://github.com/matrix-org/synapse/issues/5788))
- Return 404 instead of 403 when accessing /rooms/{roomId}/event/{eventId} for an event without the appropriate permissions. ([\#5798](https://github.com/matrix-org/synapse/issues/5798))
- Fix check that tombstone is a state event in push rules. ([\#5804](https://github.com/matrix-org/synapse/issues/5804))
- Fix error when trying to login as a deactivated user when using a worker to handle login. ([\#5806](https://github.com/matrix-org/synapse/issues/5806))
- Fix bug where user `/sync` stream could get wedged in rare circumstances. ([\#5825](https://github.com/matrix-org/synapse/issues/5825))
- The purge_remote_media.sh script was fixed. ([\#5839](https://github.com/matrix-org/synapse/issues/5839))


Deprecations and Removals
-------------------------

- Synapse now no longer accepts the `-v`/`--verbose`, `-f`/`--log-file`, or `--log-config` command line flags, and removes the deprecated `verbose` and `log_file` configuration file options. Users of these options should migrate their options into the dedicated log configuration. ([\#5678](https://github.com/matrix-org/synapse/issues/5678), [\#5729](https://github.com/matrix-org/synapse/issues/5729))
- Remove non-functional 'expire_access_token' setting. ([\#5782](https://github.com/matrix-org/synapse/issues/5782))


Internal Changes
----------------

- Make Jaeger fully configurable. ([\#5694](https://github.com/matrix-org/synapse/issues/5694))
- Add precautionary measures to prevent future abuse of `window.opener` in default welcome page. ([\#5695](https://github.com/matrix-org/synapse/issues/5695))
- Reduce database IO usage by optimising queries for current membership. ([\#5706](https://github.com/matrix-org/synapse/issues/5706), [\#5738](https://github.com/matrix-org/synapse/issues/5738), [\#5746](https://github.com/matrix-org/synapse/issues/5746), [\#5752](https://github.com/matrix-org/synapse/issues/5752), [\#5770](https://github.com/matrix-org/synapse/issues/5770), [\#5774](https://github.com/matrix-org/synapse/issues/5774), [\#5792](https://github.com/matrix-org/synapse/issues/5792), [\#5793](https://github.com/matrix-org/synapse/issues/5793))
- Improve caching when fetching `get_filtered_current_state_ids`. ([\#5713](https://github.com/matrix-org/synapse/issues/5713))
- Don't accept opentracing data from clients. ([\#5715](https://github.com/matrix-org/synapse/issues/5715))
- Speed up PostgreSQL unit tests in CI. ([\#5717](https://github.com/matrix-org/synapse/issues/5717))
- Update the coding style document. ([\#5719](https://github.com/matrix-org/synapse/issues/5719))
- Improve database query performance when recording retry intervals for remote hosts. ([\#5720](https://github.com/matrix-org/synapse/issues/5720))
- Add a set of opentracing utils. ([\#5722](https://github.com/matrix-org/synapse/issues/5722))
- Cache result of get_version_string to reduce overhead of `/version` federation requests. ([\#5730](https://github.com/matrix-org/synapse/issues/5730))
- Return 'user_type' in admin API user endpoints results. ([\#5731](https://github.com/matrix-org/synapse/issues/5731))
- Don't package the sytest test blacklist file. ([\#5733](https://github.com/matrix-org/synapse/issues/5733))
- Replace uses of returnValue with plain return, as returnValue is not needed on Python 3. ([\#5736](https://github.com/matrix-org/synapse/issues/5736))
- Blacklist some flakey tests in worker mode. ([\#5740](https://github.com/matrix-org/synapse/issues/5740))
- Fix some error cases in the caching layer. ([\#5749](https://github.com/matrix-org/synapse/issues/5749))
- Add a prometheus metric for pending cache lookups. ([\#5750](https://github.com/matrix-org/synapse/issues/5750))
- Stop trying to fetch events with event_id=None. ([\#5753](https://github.com/matrix-org/synapse/issues/5753))
- Convert RedactionTestCase to modern test style. ([\#5768](https://github.com/matrix-org/synapse/issues/5768))
- Allow looping calls to be given arguments. ([\#5780](https://github.com/matrix-org/synapse/issues/5780))
- Set the logs emitted when checking typing and presence timeouts to DEBUG level, not INFO. ([\#5785](https://github.com/matrix-org/synapse/issues/5785))
- Remove DelayedCall debugging from the test suite, as it is no longer required in the vast majority of Synapse's tests. ([\#5787](https://github.com/matrix-org/synapse/issues/5787))
- Remove some spurious exceptions from the logs where we failed to talk to a remote server. ([\#5790](https://github.com/matrix-org/synapse/issues/5790))
- Improve performance when making `.well-known` requests by sharing the SSL options between requests. ([\#5794](https://github.com/matrix-org/synapse/issues/5794))
- Disable codecov GitHub comments on PRs. ([\#5796](https://github.com/matrix-org/synapse/issues/5796))
- Don't allow clients to send tombstone events that reference the room it's sent in. ([\#5801](https://github.com/matrix-org/synapse/issues/5801))
- Deny redactions of events sent in a different room. ([\#5802](https://github.com/matrix-org/synapse/issues/5802))
- Deny sending well known state types as non-state events. ([\#5805](https://github.com/matrix-org/synapse/issues/5805))
- Handle incorrectly encoded query params correctly by returning a 400. ([\#5808](https://github.com/matrix-org/synapse/issues/5808))
- Handle pusher being deleted during processing rather than logging an exception. ([\#5809](https://github.com/matrix-org/synapse/issues/5809))
- Return 502 not 500 when failing to reach any remote server. ([\#5810](https://github.com/matrix-org/synapse/issues/5810))
- Reduce global pauses in the events stream caused by expensive state resolution during persistence. ([\#5826](https://github.com/matrix-org/synapse/issues/5826))
- Add a lower bound to well-known lookup cache time to avoid repeated lookups. ([\#5836](https://github.com/matrix-org/synapse/issues/5836))
- Whitelist history visibility sytests in worker mode tests. ([\#5843](https://github.com/matrix-org/synapse/issues/5843))


Synapse 1.2.1 (2019-07-26)
==========================

Security update
---------------

This release includes *four* security fixes:

- Prevent an attack where a federated server could send redactions for arbitrary events in v1 and v2 rooms. ([\#5767](https://github.com/matrix-org/synapse/issues/5767))
- Prevent a denial-of-service attack where cycles of redaction events would make Synapse spin infinitely. Thanks to `@lrizika:matrix.org` for identifying and responsibly disclosing this issue. ([0f2ecb961](https://github.com/matrix-org/synapse/commit/0f2ecb961))
- Prevent an attack where users could be joined or parted from public rooms without their consent. Thanks to @dylangerdaly for identifying and responsibly disclosing this issue. ([\#5744](https://github.com/matrix-org/synapse/issues/5744))
- Fix a vulnerability where a federated server could spoof read-receipts from
  users on other servers. Thanks to @dylangerdaly for identifying this issue too. ([\#5743](https://github.com/matrix-org/synapse/issues/5743))

Additionally, the following fix was in Synapse **1.2.0**, but was not correctly
identified during the original release:

- It was possible for a room moderator to send a redaction for an `m.room.create` event, which would downgrade the room to version 1. Thanks to `/dev/ponies` for identifying and responsibly disclosing this issue! ([\#5701](https://github.com/matrix-org/synapse/issues/5701))

Synapse 1.2.0 (2019-07-25)
==========================

No significant changes.


Synapse 1.2.0rc2 (2019-07-24)
=============================

Bugfixes
--------

- Fix a regression introduced in v1.2.0rc1 which led to incorrect labels on some prometheus metrics. ([\#5734](https://github.com/matrix-org/synapse/issues/5734))


Synapse 1.2.0rc1 (2019-07-22)
=============================

Security fixes
--------------

This update included a security fix which was initially incorrectly flagged as
a regular bug fix.

- It was possible for a room moderator to send a redaction for an `m.room.create` event, which would downgrade the room to version 1. Thanks to `/dev/ponies` for identifying and responsibly disclosing this issue! ([\#5701](https://github.com/matrix-org/synapse/issues/5701))

Features
--------

- Add support for opentracing. ([\#5544](https://github.com/matrix-org/synapse/issues/5544), [\#5712](https://github.com/matrix-org/synapse/issues/5712))
- Add ability to pull all locally stored events out of synapse that a particular user can see. ([\#5589](https://github.com/matrix-org/synapse/issues/5589))
- Add a basic admin command app to allow server operators to run Synapse admin commands separately from the main production instance. ([\#5597](https://github.com/matrix-org/synapse/issues/5597))
- Add `sender` and `origin_server_ts` fields to `m.replace`. ([\#5613](https://github.com/matrix-org/synapse/issues/5613))
- Add default push rule to ignore reactions. ([\#5623](https://github.com/matrix-org/synapse/issues/5623))
- Include the original event when asking for its relations. ([\#5626](https://github.com/matrix-org/synapse/issues/5626))
- Implement `session_lifetime` configuration option, after which access tokens will expire. ([\#5660](https://github.com/matrix-org/synapse/issues/5660))
- Return "This account has been deactivated" when a deactivated user tries to login. ([\#5674](https://github.com/matrix-org/synapse/issues/5674))
- Enable aggregations support by default ([\#5714](https://github.com/matrix-org/synapse/issues/5714))


Bugfixes
--------

- Fix 'utime went backwards' errors on daemonization. ([\#5609](https://github.com/matrix-org/synapse/issues/5609))
- Various minor fixes to the federation request rate limiter. ([\#5621](https://github.com/matrix-org/synapse/issues/5621))
- Forbid viewing relations on an event once it has been redacted. ([\#5629](https://github.com/matrix-org/synapse/issues/5629))
- Fix requests to the `/store_invite` endpoint of identity servers being sent in the wrong format. ([\#5638](https://github.com/matrix-org/synapse/issues/5638))
- Fix newly-registered users not being able to lookup their own profile without joining a room. ([\#5644](https://github.com/matrix-org/synapse/issues/5644))
- Fix bug in #5626 that prevented the original_event field from actually having the contents of the original event in a call to `/relations`. ([\#5654](https://github.com/matrix-org/synapse/issues/5654))
- Fix 3PID bind requests being sent to identity servers as `application/x-form-www-urlencoded` data, which is deprecated. ([\#5658](https://github.com/matrix-org/synapse/issues/5658))
- Fix some problems with authenticating redactions in recent room versions. ([\#5699](https://github.com/matrix-org/synapse/issues/5699), [\#5700](https://github.com/matrix-org/synapse/issues/5700), [\#5707](https://github.com/matrix-org/synapse/issues/5707))


Updates to the Docker image
---------------------------

- Base Docker image on a newer Alpine Linux version (3.8 -> 3.10). ([\#5619](https://github.com/matrix-org/synapse/issues/5619))
- Add missing space in default logging file format generated by the Docker image. ([\#5620](https://github.com/matrix-org/synapse/issues/5620))


Improved Documentation
----------------------

- Add information about nginx normalisation to reverse_proxy.rst. Contributed by @skalarproduktraum - thanks! ([\#5397](https://github.com/matrix-org/synapse/issues/5397))
- --no-pep517 should be --no-use-pep517 in the documentation to setup the development environment. ([\#5651](https://github.com/matrix-org/synapse/issues/5651))
- Improvements to Postgres setup instructions. Contributed by @Lrizika - thanks! ([\#5661](https://github.com/matrix-org/synapse/issues/5661))
- Minor tweaks to postgres documentation. ([\#5675](https://github.com/matrix-org/synapse/issues/5675))


Deprecations and Removals
-------------------------

- Remove support for the `invite_3pid_guest` configuration setting. ([\#5625](https://github.com/matrix-org/synapse/issues/5625))


Internal Changes
----------------

- Move logging code out of `synapse.util` and into `synapse.logging`. ([\#5606](https://github.com/matrix-org/synapse/issues/5606), [\#5617](https://github.com/matrix-org/synapse/issues/5617))
- Add a blacklist file to the repo to blacklist certain sytests from failing CI. ([\#5611](https://github.com/matrix-org/synapse/issues/5611))
- Make runtime errors surrounding password reset emails much clearer. ([\#5616](https://github.com/matrix-org/synapse/issues/5616))
- Remove dead code for persiting outgoing federation transactions. ([\#5622](https://github.com/matrix-org/synapse/issues/5622))
- Add `lint.sh` to the scripts-dev folder which will run all linting steps required by CI. ([\#5627](https://github.com/matrix-org/synapse/issues/5627))
- Move RegistrationHandler.get_or_create_user to test code. ([\#5628](https://github.com/matrix-org/synapse/issues/5628))
- Add some more common python virtual-environment paths to the black exclusion list. ([\#5630](https://github.com/matrix-org/synapse/issues/5630))
- Some counter metrics exposed over Prometheus have been renamed, with the old names preserved for backwards compatibility and deprecated. See `docs/metrics-howto.rst` for details. ([\#5636](https://github.com/matrix-org/synapse/issues/5636))
- Unblacklist some user_directory sytests. ([\#5637](https://github.com/matrix-org/synapse/issues/5637))
- Factor out some redundant code in the login implementation. ([\#5639](https://github.com/matrix-org/synapse/issues/5639))
- Update ModuleApi to avoid register(generate_token=True). ([\#5640](https://github.com/matrix-org/synapse/issues/5640))
- Remove access-token support from `RegistrationHandler.register`, and rename it. ([\#5641](https://github.com/matrix-org/synapse/issues/5641))
- Remove access-token support from `RegistrationStore.register`, and rename it. ([\#5642](https://github.com/matrix-org/synapse/issues/5642))
- Improve logging for auto-join when a new user is created. ([\#5643](https://github.com/matrix-org/synapse/issues/5643))
- Remove unused and unnecessary check for FederationDeniedError in _exception_to_failure. ([\#5645](https://github.com/matrix-org/synapse/issues/5645))
- Fix a small typo in a code comment. ([\#5655](https://github.com/matrix-org/synapse/issues/5655))
- Clean up exception handling around client access tokens. ([\#5656](https://github.com/matrix-org/synapse/issues/5656))
- Add a mechanism for per-test homeserver configuration in the unit tests. ([\#5657](https://github.com/matrix-org/synapse/issues/5657))
- Inline issue_access_token. ([\#5659](https://github.com/matrix-org/synapse/issues/5659))
- Update the sytest BuildKite configuration to checkout Synapse in `/src`. ([\#5664](https://github.com/matrix-org/synapse/issues/5664))
- Add a `docker` type to the towncrier configuration. ([\#5673](https://github.com/matrix-org/synapse/issues/5673))
- Convert `synapse.federation.transport.server` to `async`. Might improve some stack traces. ([\#5689](https://github.com/matrix-org/synapse/issues/5689))
- Documentation for opentracing. ([\#5703](https://github.com/matrix-org/synapse/issues/5703))


Synapse 1.1.0 (2019-07-04)
==========================

As of v1.1.0, Synapse no longer supports Python 2, nor Postgres version 9.4.
See the [upgrade notes](docs/upgrade.md#upgrading-to-v110) for more details.

This release also deprecates the use of environment variables to configure the
docker image. See the [docker README](https://github.com/matrix-org/synapse/blob/release-v1.1.0/docker/README.md#legacy-dynamic-configuration-file-support)
for more details.

No changes since 1.1.0rc2.


Synapse 1.1.0rc2 (2019-07-03)
=============================

Bugfixes
--------

- Fix regression in 1.1rc1 where OPTIONS requests to the media repo would fail. ([\#5593](https://github.com/matrix-org/synapse/issues/5593))
- Removed the `SYNAPSE_SMTP_*` docker container environment variables. Using these environment variables prevented the docker container from starting in Synapse v1.0, even though they didn't actually allow any functionality anyway. ([\#5596](https://github.com/matrix-org/synapse/issues/5596))
- Fix a number of "Starting txn from sentinel context" warnings. ([\#5605](https://github.com/matrix-org/synapse/issues/5605))


Internal Changes
----------------

- Update github templates. ([\#5552](https://github.com/matrix-org/synapse/issues/5552))


Synapse 1.1.0rc1 (2019-07-02)
=============================

As of v1.1.0, Synapse no longer supports Python 2, nor Postgres version 9.4.
See the [upgrade notes](docs/upgrade.md#upgrading-to-v110) for more details.

Features
--------

- Added possibility to disable local password authentication. Contributed by Daniel Hoffend. ([\#5092](https://github.com/matrix-org/synapse/issues/5092))
- Add monthly active users to phonehome stats. ([\#5252](https://github.com/matrix-org/synapse/issues/5252))
- Allow expired user to trigger renewal email sending manually. ([\#5363](https://github.com/matrix-org/synapse/issues/5363))
- Statistics on forward extremities per room are now exposed via Prometheus. ([\#5384](https://github.com/matrix-org/synapse/issues/5384), [\#5458](https://github.com/matrix-org/synapse/issues/5458), [\#5461](https://github.com/matrix-org/synapse/issues/5461))
- Add --no-daemonize option to run synapse in the foreground, per issue #4130. Contributed by Soham Gumaste. ([\#5412](https://github.com/matrix-org/synapse/issues/5412), [\#5587](https://github.com/matrix-org/synapse/issues/5587))
- Fully support SAML2 authentication. Contributed by [Alexander Trost](https://github.com/galexrt) - thank you! ([\#5422](https://github.com/matrix-org/synapse/issues/5422))
- Allow server admins to define implementations of extra rules for allowing or denying incoming events. ([\#5440](https://github.com/matrix-org/synapse/issues/5440), [\#5474](https://github.com/matrix-org/synapse/issues/5474), [\#5477](https://github.com/matrix-org/synapse/issues/5477))
- Add support for handling pagination APIs on client reader worker. ([\#5505](https://github.com/matrix-org/synapse/issues/5505), [\#5513](https://github.com/matrix-org/synapse/issues/5513), [\#5531](https://github.com/matrix-org/synapse/issues/5531))
- Improve help and cmdline option names for --generate-config options. ([\#5512](https://github.com/matrix-org/synapse/issues/5512))
- Allow configuration of the path used for ACME account keys. ([\#5516](https://github.com/matrix-org/synapse/issues/5516), [\#5521](https://github.com/matrix-org/synapse/issues/5521), [\#5522](https://github.com/matrix-org/synapse/issues/5522))
- Add --data-dir and --open-private-ports options. ([\#5524](https://github.com/matrix-org/synapse/issues/5524))
- Split public rooms directory auth config in two settings, in order to manage client auth independently from the federation part of it. Obsoletes the "restrict_public_rooms_to_local_users" configuration setting. If "restrict_public_rooms_to_local_users" is set in the config, Synapse will act as if both new options are enabled, i.e. require authentication through the client API and deny federation requests. ([\#5534](https://github.com/matrix-org/synapse/issues/5534))
- The minimum TLS version used for outgoing federation requests can now be set with `federation_client_minimum_tls_version`. ([\#5550](https://github.com/matrix-org/synapse/issues/5550))
- Optimise devices changed query to not pull unnecessary rows from the database, reducing database load. ([\#5559](https://github.com/matrix-org/synapse/issues/5559))
- Add new metrics for number of forward extremities being persisted and number of state groups involved in resolution. ([\#5476](https://github.com/matrix-org/synapse/issues/5476))

Bugfixes
--------

- Fix bug processing incoming events over federation if call to `/get_missing_events` fails. ([\#5042](https://github.com/matrix-org/synapse/issues/5042))
- Prevent more than one room upgrade happening simultaneously on the same room. ([\#5051](https://github.com/matrix-org/synapse/issues/5051))
- Fix a bug where running synapse_port_db would cause the account validity feature to fail because it didn't set the type of the email_sent column to boolean. ([\#5325](https://github.com/matrix-org/synapse/issues/5325))
- Warn about disabling email-based password resets when a reset occurs, and remove warning when someone attempts a phone-based reset. ([\#5387](https://github.com/matrix-org/synapse/issues/5387))
- Fix email notifications for unnamed rooms with multiple people. ([\#5388](https://github.com/matrix-org/synapse/issues/5388))
- Fix exceptions in federation reader worker caused by attempting to renew attestations, which should only happen on master worker. ([\#5389](https://github.com/matrix-org/synapse/issues/5389))
- Fix handling of failures fetching remote content to not log failures as exceptions. ([\#5390](https://github.com/matrix-org/synapse/issues/5390))
- Fix a bug where deactivated users could receive renewal emails if the account validity feature is on. ([\#5394](https://github.com/matrix-org/synapse/issues/5394))
- Fix missing invite state after exchanging 3PID invites over federaton. ([\#5464](https://github.com/matrix-org/synapse/issues/5464))
- Fix intermittent exceptions on Apple hardware. Also fix bug that caused database activity times to be under-reported in log lines. ([\#5498](https://github.com/matrix-org/synapse/issues/5498))
- Fix logging error when a tampered event is detected. ([\#5500](https://github.com/matrix-org/synapse/issues/5500))
- Fix bug where clients could tight loop calling `/sync` for a period. ([\#5507](https://github.com/matrix-org/synapse/issues/5507))
- Fix bug with `jinja2` preventing Synapse from starting. Users who had this problem should now simply need to run `pip install matrix-synapse`. ([\#5514](https://github.com/matrix-org/synapse/issues/5514))
- Fix a regression where homeservers on private IP addresses were incorrectly blacklisted. ([\#5523](https://github.com/matrix-org/synapse/issues/5523))
- Fixed m.login.jwt using unregistered user_id and added pyjwt>=1.6.4 as jwt conditional dependencies. Contributed by Pau Rodriguez-Estivill. ([\#5555](https://github.com/matrix-org/synapse/issues/5555), [\#5586](https://github.com/matrix-org/synapse/issues/5586))
- Fix a bug that would cause invited users to receive several emails for a single 3PID invite in case the inviter is rate limited. ([\#5576](https://github.com/matrix-org/synapse/issues/5576))


Updates to the Docker image
---------------------------
- Add ability to change Docker containers [timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) with the `TZ` variable. ([\#5383](https://github.com/matrix-org/synapse/issues/5383))
- Update docker image to use Python 3.7. ([\#5546](https://github.com/matrix-org/synapse/issues/5546))
- Deprecate the use of environment variables for configuration, and make the use of a static configuration the default. ([\#5561](https://github.com/matrix-org/synapse/issues/5561), [\#5562](https://github.com/matrix-org/synapse/issues/5562), [\#5566](https://github.com/matrix-org/synapse/issues/5566), [\#5567](https://github.com/matrix-org/synapse/issues/5567))
- Increase default log level for docker image to INFO. It can still be changed by editing the generated log.config file. ([\#5547](https://github.com/matrix-org/synapse/issues/5547))
- Send synapse logs to the docker logging system, by default. ([\#5565](https://github.com/matrix-org/synapse/issues/5565))
- Open the non-TLS port by default. ([\#5568](https://github.com/matrix-org/synapse/issues/5568))
- Fix failure to start under docker with SAML support enabled. ([\#5490](https://github.com/matrix-org/synapse/issues/5490))
- Use a sensible location for data files when generating a config file. ([\#5563](https://github.com/matrix-org/synapse/issues/5563))


Deprecations and Removals
-------------------------

- Python 2.7 is no longer a supported platform. Synapse now requires Python 3.5+ to run. ([\#5425](https://github.com/matrix-org/synapse/issues/5425))
- PostgreSQL 9.4 is no longer supported. Synapse requires Postgres 9.5+ or above for Postgres support. ([\#5448](https://github.com/matrix-org/synapse/issues/5448))
- Remove support for cpu_affinity setting. ([\#5525](https://github.com/matrix-org/synapse/issues/5525))


Improved Documentation
----------------------
- Improve README section on performance troubleshooting. ([\#4276](https://github.com/matrix-org/synapse/issues/4276))
- Add information about how to install and run `black` on the codebase to code_style.rst. ([\#5537](https://github.com/matrix-org/synapse/issues/5537))
- Improve install docs on choosing server_name. ([\#5558](https://github.com/matrix-org/synapse/issues/5558))


Internal Changes
----------------

- Add logging to 3pid invite signature verification. ([\#5015](https://github.com/matrix-org/synapse/issues/5015))
- Update example haproxy config to a more compatible setup. ([\#5313](https://github.com/matrix-org/synapse/issues/5313))
- Track deactivated accounts in the database. ([\#5378](https://github.com/matrix-org/synapse/issues/5378), [\#5465](https://github.com/matrix-org/synapse/issues/5465), [\#5493](https://github.com/matrix-org/synapse/issues/5493))
- Clean up code for sending federation EDUs. ([\#5381](https://github.com/matrix-org/synapse/issues/5381))
- Add a sponsor button to the repo. ([\#5382](https://github.com/matrix-org/synapse/issues/5382), [\#5386](https://github.com/matrix-org/synapse/issues/5386))
- Don't log non-200 responses from federation queries as exceptions. ([\#5383](https://github.com/matrix-org/synapse/issues/5383))
- Update Python syntax in contrib/ to Python 3. ([\#5446](https://github.com/matrix-org/synapse/issues/5446))
- Update federation_client dev script to support `.well-known` and work with python3. ([\#5447](https://github.com/matrix-org/synapse/issues/5447))
- SyTest has been moved to Buildkite. ([\#5459](https://github.com/matrix-org/synapse/issues/5459))
- Demo script now uses python3. ([\#5460](https://github.com/matrix-org/synapse/issues/5460))
- Synapse can now handle RestServlets that return coroutines. ([\#5475](https://github.com/matrix-org/synapse/issues/5475), [\#5585](https://github.com/matrix-org/synapse/issues/5585))
- The demo servers talk to each other again. ([\#5478](https://github.com/matrix-org/synapse/issues/5478))
- Add an EXPERIMENTAL config option to try and periodically clean up extremities by sending dummy events. ([\#5480](https://github.com/matrix-org/synapse/issues/5480))
- Synapse's codebase is now formatted by `black`. ([\#5482](https://github.com/matrix-org/synapse/issues/5482))
- Some cleanups and sanity-checking in the CPU and database metrics. ([\#5499](https://github.com/matrix-org/synapse/issues/5499))
- Improve email notification logging. ([\#5502](https://github.com/matrix-org/synapse/issues/5502))
- Fix "Unexpected entry in 'full_schemas'" log warning. ([\#5509](https://github.com/matrix-org/synapse/issues/5509))
- Improve logging when generating config files. ([\#5510](https://github.com/matrix-org/synapse/issues/5510))
- Refactor and clean up Config parser for maintainability. ([\#5511](https://github.com/matrix-org/synapse/issues/5511))
- Make the config clearer in that email.template_dir is relative to the Synapse's root directory, not the `synapse/` folder within it. ([\#5543](https://github.com/matrix-org/synapse/issues/5543))
- Update v1.0.0 release changelog to include more information about changes to password resets. ([\#5545](https://github.com/matrix-org/synapse/issues/5545))
- Remove non-functioning check_event_hash.py dev script. ([\#5548](https://github.com/matrix-org/synapse/issues/5548))
- Synapse will now only allow TLS v1.2 connections when serving federation, if it terminates TLS. As Synapse's allowed ciphers were only able to be used in TLSv1.2 before, this does not change behaviour. ([\#5550](https://github.com/matrix-org/synapse/issues/5550))
- Logging when running GC collection on generation 0 is now at the DEBUG level, not INFO. ([\#5557](https://github.com/matrix-org/synapse/issues/5557))
- Reduce the amount of stuff we send in the docker context. ([\#5564](https://github.com/matrix-org/synapse/issues/5564))
- Point the reverse links in the Purge History contrib scripts at the intended location. ([\#5570](https://github.com/matrix-org/synapse/issues/5570))


Synapse 1.0.0 (2019-06-11)
==========================

Bugfixes
--------

- Fix bug where attempting to send transactions with large number of EDUs can fail. ([\#5418](https://github.com/matrix-org/synapse/issues/5418))


Improved Documentation
----------------------

- Expand the federation guide to include relevant content from the MSC1711 FAQ ([\#5419](https://github.com/matrix-org/synapse/issues/5419))


Internal Changes
----------------

- Move password reset links to /_matrix/client/unstable namespace. ([\#5424](https://github.com/matrix-org/synapse/issues/5424))


Synapse 1.0.0rc3 (2019-06-10)
=============================

Security: Fix authentication bug introduced in 1.0.0rc1. Please upgrade to rc3 immediately


Synapse 1.0.0rc2 (2019-06-10)
=============================

Bugfixes
--------

- Remove redundant warning about key server response validation. ([\#5392](https://github.com/matrix-org/synapse/issues/5392))
- Fix bug where old keys stored in the database with a null valid until timestamp caused all verification requests for that key to fail. ([\#5415](https://github.com/matrix-org/synapse/issues/5415))
- Fix excessive memory using with default `federation_verify_certificates: true` configuration. ([\#5417](https://github.com/matrix-org/synapse/issues/5417))


Synapse 1.0.0rc1 (2019-06-07)
=============================

Features
--------

- Synapse now more efficiently collates room statistics. ([\#4338](https://github.com/matrix-org/synapse/issues/4338), [\#5260](https://github.com/matrix-org/synapse/issues/5260), [\#5324](https://github.com/matrix-org/synapse/issues/5324))
- Add experimental support for relations (aka reactions and edits). ([\#5220](https://github.com/matrix-org/synapse/issues/5220))
- Ability to configure default room version. ([\#5223](https://github.com/matrix-org/synapse/issues/5223), [\#5249](https://github.com/matrix-org/synapse/issues/5249))
- Allow configuring a range for the account validity startup job. ([\#5276](https://github.com/matrix-org/synapse/issues/5276))
- CAS login will now hit the r0 API, not the deprecated v1 one. ([\#5286](https://github.com/matrix-org/synapse/issues/5286))
- Validate federation server TLS certificates by default (implements [MSC1711](https://github.com/matrix-org/matrix-doc/blob/master/proposals/1711-x509-for-federation.md)). ([\#5359](https://github.com/matrix-org/synapse/issues/5359))
- Update /_matrix/client/versions to reference support for r0.5.0. ([\#5360](https://github.com/matrix-org/synapse/issues/5360))
- Add a script to generate new signing-key files. ([\#5361](https://github.com/matrix-org/synapse/issues/5361))
- Update upgrade and installation guides ahead of 1.0. ([\#5371](https://github.com/matrix-org/synapse/issues/5371))
- Replace the `perspectives` configuration section with `trusted_key_servers`, and make validating the signatures on responses optional (since TLS will do this job for us). ([\#5374](https://github.com/matrix-org/synapse/issues/5374))
- Add ability to perform password reset via email without trusting the identity server. **As a result of this PR, password resets will now be disabled on the default configuration.**

  Password reset emails are now sent from the homeserver by default, instead of the identity server. To enable this functionality, ensure `email` and `public_baseurl` config options are filled out.

  If you would like to re-enable password resets being sent from the identity server (warning: this is dangerous! See [#5345](https://github.com/matrix-org/synapse/pull/5345)), set `email.trust_identity_server_for_password_resets` to true. ([\#5377](https://github.com/matrix-org/synapse/issues/5377))
- Set default room version to v4. ([\#5379](https://github.com/matrix-org/synapse/issues/5379))


Bugfixes
--------

- Fixes client-server API not sending "m.heroes" to lazy-load /sync requests when a rooms name or its canonical alias are empty. Thanks to @dnaf for this work! ([\#5089](https://github.com/matrix-org/synapse/issues/5089))
- Prevent federation device list updates breaking when processing multiple updates at once. ([\#5156](https://github.com/matrix-org/synapse/issues/5156))
- Fix worker registration bug caused by ClientReaderSlavedStore being unable to see get_profileinfo. ([\#5200](https://github.com/matrix-org/synapse/issues/5200))
- Fix race when backfilling in rooms with worker mode. ([\#5221](https://github.com/matrix-org/synapse/issues/5221))
- Fix appservice timestamp massaging. ([\#5233](https://github.com/matrix-org/synapse/issues/5233))
- Ensure that server_keys fetched via a notary server are correctly signed. ([\#5251](https://github.com/matrix-org/synapse/issues/5251))
- Show the correct error when logging out and access token is missing. ([\#5256](https://github.com/matrix-org/synapse/issues/5256))
- Fix error code when there is an invalid parameter on /_matrix/client/r0/publicRooms ([\#5257](https://github.com/matrix-org/synapse/issues/5257))
- Fix error when downloading thumbnail with missing width/height parameter. ([\#5258](https://github.com/matrix-org/synapse/issues/5258))
- Fix schema update for account validity. ([\#5268](https://github.com/matrix-org/synapse/issues/5268))
- Fix bug where we leaked extremities when we soft failed events, leading to performance degradation. ([\#5274](https://github.com/matrix-org/synapse/issues/5274), [\#5278](https://github.com/matrix-org/synapse/issues/5278), [\#5291](https://github.com/matrix-org/synapse/issues/5291))
- Fix "db txn 'update_presence' from sentinel context" log messages. ([\#5275](https://github.com/matrix-org/synapse/issues/5275))
- Fix dropped logcontexts during high outbound traffic. ([\#5277](https://github.com/matrix-org/synapse/issues/5277))
- Fix a bug where it is not possible to get events in the federation format with the request `GET /_matrix/client/r0/rooms/{roomId}/messages`. ([\#5293](https://github.com/matrix-org/synapse/issues/5293))
- Fix performance problems with the rooms stats background update. ([\#5294](https://github.com/matrix-org/synapse/issues/5294))
- Fix noisy 'no key for server' logs. ([\#5300](https://github.com/matrix-org/synapse/issues/5300))
- Fix bug where a notary server would sometimes forget old keys. ([\#5307](https://github.com/matrix-org/synapse/issues/5307))
- Prevent users from setting huge displaynames and avatar URLs. ([\#5309](https://github.com/matrix-org/synapse/issues/5309))
- Fix handling of failures when processing incoming events where calling `/event_auth` on remote server fails. ([\#5317](https://github.com/matrix-org/synapse/issues/5317))
- Ensure that we have an up-to-date copy of the signing key when validating incoming federation requests. ([\#5321](https://github.com/matrix-org/synapse/issues/5321))
- Fix various problems which made the signing-key notary server time out for some requests. ([\#5333](https://github.com/matrix-org/synapse/issues/5333))
- Fix bug which would make certain operations (such as room joins) block for 20 minutes while attemoting to fetch verification keys. ([\#5334](https://github.com/matrix-org/synapse/issues/5334))
- Fix a bug where we could rapidly mark a server as unreachable even though it was only down for a few minutes. ([\#5335](https://github.com/matrix-org/synapse/issues/5335), [\#5340](https://github.com/matrix-org/synapse/issues/5340))
- Fix a bug where account validity renewal emails could only be sent when email notifs were enabled. ([\#5341](https://github.com/matrix-org/synapse/issues/5341))
- Fix failure when fetching batches of events during backfill, etc. ([\#5342](https://github.com/matrix-org/synapse/issues/5342))
- Add a new room version where the timestamps on events are checked against the validity periods on signing keys. ([\#5348](https://github.com/matrix-org/synapse/issues/5348), [\#5354](https://github.com/matrix-org/synapse/issues/5354))
- Fix room stats and presence background updates to correctly handle missing events. ([\#5352](https://github.com/matrix-org/synapse/issues/5352))
- Include left members in room summaries' heroes. ([\#5355](https://github.com/matrix-org/synapse/issues/5355))
- Fix `federation_custom_ca_list` configuration option. ([\#5362](https://github.com/matrix-org/synapse/issues/5362))
- Fix missing logcontext warnings on shutdown. ([\#5369](https://github.com/matrix-org/synapse/issues/5369))


Improved Documentation
----------------------

- Fix docs on resetting the user directory. ([\#5282](https://github.com/matrix-org/synapse/issues/5282))
- Fix notes about ACME in the MSC1711 faq. ([\#5357](https://github.com/matrix-org/synapse/issues/5357))


Internal Changes
----------------

- Synapse will now serve the experimental "room complexity" API endpoint. ([\#5216](https://github.com/matrix-org/synapse/issues/5216))
- The base classes for the v1 and v2_alpha REST APIs have been unified. ([\#5226](https://github.com/matrix-org/synapse/issues/5226), [\#5328](https://github.com/matrix-org/synapse/issues/5328))
- Simplifications and comments in do_auth. ([\#5227](https://github.com/matrix-org/synapse/issues/5227))
- Remove urllib3 pin as requests 2.22.0 has been released supporting urllib3 1.25.2. ([\#5230](https://github.com/matrix-org/synapse/issues/5230))
- Preparatory work for key-validity features. ([\#5232](https://github.com/matrix-org/synapse/issues/5232), [\#5234](https://github.com/matrix-org/synapse/issues/5234), [\#5235](https://github.com/matrix-org/synapse/issues/5235), [\#5236](https://github.com/matrix-org/synapse/issues/5236), [\#5237](https://github.com/matrix-org/synapse/issues/5237), [\#5244](https://github.com/matrix-org/synapse/issues/5244), [\#5250](https://github.com/matrix-org/synapse/issues/5250), [\#5296](https://github.com/matrix-org/synapse/issues/5296), [\#5299](https://github.com/matrix-org/synapse/issues/5299), [\#5343](https://github.com/matrix-org/synapse/issues/5343), [\#5347](https://github.com/matrix-org/synapse/issues/5347), [\#5356](https://github.com/matrix-org/synapse/issues/5356))
- Specify the type of reCAPTCHA key to use. ([\#5283](https://github.com/matrix-org/synapse/issues/5283))
- Improve sample config for monthly active user blocking. ([\#5284](https://github.com/matrix-org/synapse/issues/5284))
- Remove spurious debug from MatrixFederationHttpClient.get_json. ([\#5287](https://github.com/matrix-org/synapse/issues/5287))
- Improve logging for logcontext leaks. ([\#5288](https://github.com/matrix-org/synapse/issues/5288))
- Clarify that the admin change password API logs the user out. ([\#5303](https://github.com/matrix-org/synapse/issues/5303))
- New installs will now use the v54 full schema, rather than the full schema v14 and applying incremental updates to v54. ([\#5320](https://github.com/matrix-org/synapse/issues/5320))
- Improve docstrings on MatrixFederationClient. ([\#5332](https://github.com/matrix-org/synapse/issues/5332))
- Clean up FederationClient.get_events for clarity. ([\#5344](https://github.com/matrix-org/synapse/issues/5344))
- Various improvements to debug logging. ([\#5353](https://github.com/matrix-org/synapse/issues/5353))
- Don't run CI build checks until sample config check has passed. ([\#5370](https://github.com/matrix-org/synapse/issues/5370))
- Automatically retry buildkite builds (max twice) when an agent is lost. ([\#5380](https://github.com/matrix-org/synapse/issues/5380))

**Changelogs for versions older than 1.0.0 can be found [here](CHANGES-pre-1.0.md).**
