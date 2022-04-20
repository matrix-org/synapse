Synapse 1.57.1 (2022-04-20)
===========================

This is a patch release that only affects the Docker image. It is only of interest to administrators using the LDAP module to authenticate their users.
If you have already upgraded to Synapse 1.57.0 without problem, then you have no need to upgrade to this patch release.


Updates to the Docker image
---------------------------

- Include version 0.2.0 of the Synapse LDAP Auth Provider module in the Docker image. ([\#12512](https://github.com/matrix-org/synapse/issues/12512))


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
- Update type annotations for compatiblity with prometheus_client 0.14. ([\#12389](https://github.com/matrix-org/synapse/issues/12389))
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

- Use the proper serialization format for bundled thread aggregations. The bug has existed since Synapse v1.48.0. ([\#12090](https://github.com/matrix-org/synapse/issues/12090))
- Fix a long-standing bug when redacting events with relations. ([\#12113](https://github.com/matrix-org/synapse/issues/12113), [\#12121](https://github.com/matrix-org/synapse/issues/12121), [\#12130](https://github.com/matrix-org/synapse/issues/12130), [\#12189](https://github.com/matrix-org/synapse/issues/12189))
- Fix a bug introduced in Synapse 1.7.2 whereby background updates are never run with the default background batch size. ([\#12157](https://github.com/matrix-org/synapse/issues/12157))
- Fix a bug where non-standard information was returned from the `/hierarchy` API. Introduced in Synapse v1.41.0. ([\#12175](https://github.com/matrix-org/synapse/issues/12175))
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
- Remove backwards compatibilty with pagination tokens from the `/relations` and `/aggregations` endpoints generated from Synapse < v1.52.0. ([\#12138](https://github.com/matrix-org/synapse/issues/12138))
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
- Fix an error that occurs whilst trying to get the federation status of a destination server that was working normally. This admin API was newly introduced in Synapse v1.49.0. ([\#11593](https://github.com/matrix-org/synapse/issues/11593))
- Fix bundled aggregations not being included in the `/sync` response, per [MSC2675](https://github.com/matrix-org/matrix-doc/pull/2675). ([\#11612](https://github.com/matrix-org/synapse/issues/11612), [\#11659](https://github.com/matrix-org/synapse/issues/11659), [\#11791](https://github.com/matrix-org/synapse/issues/11791))
- Fix the `/_matrix/client/v1/room/{roomId}/hierarchy` endpoint returning incorrect fields which have been present since Synapse 1.49.0. ([\#11667](https://github.com/matrix-org/synapse/issues/11667))
- Fix preview of some GIF URLs (like tenor.com). Contributed by Philippe Daouadi. ([\#11669](https://github.com/matrix-org/synapse/issues/11669))
- Fix a bug where only the first 50 rooms from a space were returned from the `/hierarchy` API. This has existed since the introduction of the API in Synapse v1.41.0. ([\#11695](https://github.com/matrix-org/synapse/issues/11695))
- Fix a bug introduced in Synapse v1.18.0 where password reset and address validation emails would not be sent if their subject was configured to use the 'app' template variable. Contributed by @br4nnigan. ([\#11710](https://github.com/matrix-org/synapse/issues/11710), [\#11745](https://github.com/matrix-org/synapse/issues/11745))
- Make the 'List Rooms' Admin API sort stable. Contributed by Daniël Sonck. ([\#11737](https://github.com/matrix-org/synapse/issues/11737))
- Fix a long-standing bug where space hierarchy over federation would only work correctly some of the time. ([\#11775](https://github.com/matrix-org/synapse/issues/11775))
- Fix a bug introduced in Synapse v1.46.0 that prevented `on_logged_out` module callbacks from being correctly awaited by Synapse. ([\#11786](https://github.com/matrix-org/synapse/issues/11786))


Improved Documentation
----------------------

- Warn against using a Let's Encrypt certificate for TLS/DTLS TURN server client connections, and suggest using ZeroSSL certificate instead. This works around client-side connectivity errors caused by WebRTC libraries that reject Let's Encrypt certificates. Contibuted by @AndrewFerr. ([\#11686](https://github.com/matrix-org/synapse/issues/11686))
- Document the new `SYNAPSE_TEST_PERSIST_SQLITE_DB` environment variable in the contributing guide. ([\#11715](https://github.com/matrix-org/synapse/issues/11715))
- Document that the minimum supported PostgreSQL version is now 10. ([\#11725](https://github.com/matrix-org/synapse/issues/11725))
- Fix typo in demo docs: differnt. ([\#11735](https://github.com/matrix-org/synapse/issues/11735))
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

- Fix a bug introduced in Synapse v1.0.0 whereby some device list updates would not be sent to remote homeservers if there were too many to send at once. ([\#11729](https://github.com/matrix-org/synapse/issues/11729))
- Fix a bug introduced in Synapse v1.50.0rc1 whereby outbound federation could fail because too many EDUs were produced for device updates. ([\#11730](https://github.com/matrix-org/synapse/issues/11730))


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
- Add details for how to configure a TURN server when behind a NAT. Contibuted by @AndrewFerr. ([\#11553](https://github.com/matrix-org/synapse/issues/11553))
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


**Changelogs for older versions can be found [here](docs/changelogs/).**
