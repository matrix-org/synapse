Synapse 0.33.7rc1 (2018-10-15)
==============================

Features
--------

- Add support for end-to-end key backup (MSC1687) ([\#4019](https://github.com/matrix-org/synapse/issues/4019))


Bugfixes
--------

- Fix bug in event persistence logic which caused 'NoneType is not iterable' ([\#3995](https://github.com/matrix-org/synapse/issues/3995))
- Fix exception in background metrics collection ([\#3996](https://github.com/matrix-org/synapse/issues/3996))
- Fix exception handling in fetching remote profiles ([\#3997](https://github.com/matrix-org/synapse/issues/3997))
- Fix handling of rejected threepid invites ([\#3999](https://github.com/matrix-org/synapse/issues/3999))
- Workers now start on Python 3. ([\#4027](https://github.com/matrix-org/synapse/issues/4027))
- Synapse now starts on Python 3.7. ([\#4033](https://github.com/matrix-org/synapse/issues/4033))


Internal Changes
----------------

- Log exceptions in looping calls ([\#4008](https://github.com/matrix-org/synapse/issues/4008))
- Optimisation for serving federation requests ([\#4017](https://github.com/matrix-org/synapse/issues/4017))
- Add metric to count number of non-empty sync responses ([\#4022](https://github.com/matrix-org/synapse/issues/4022))


Synapse 0.33.6 (2018-10-04)
===========================

Internal Changes
----------------

- Pin to prometheus_client<0.4 to avoid renaming all of our metrics ([\#4002](https://github.com/matrix-org/synapse/issues/4002))


Synapse 0.33.6rc1 (2018-10-03)
==============================

Features
--------

- Adding the ability to change MAX_UPLOAD_SIZE for the docker container variables. ([\#3883](https://github.com/matrix-org/synapse/issues/3883))
- Report "python_version" in the phone home stats ([\#3894](https://github.com/matrix-org/synapse/issues/3894))
- Always LL ourselves if we're in a room ([\#3916](https://github.com/matrix-org/synapse/issues/3916))
- Include eventid in log lines when processing incoming federation transactions ([\#3959](https://github.com/matrix-org/synapse/issues/3959))
- Remove spurious check which made 'localhost' servers not work ([\#3964](https://github.com/matrix-org/synapse/issues/3964))


Bugfixes
--------

- Fix problem when playing media from Chrome using direct URL (thanks @remjey!) ([\#3578](https://github.com/matrix-org/synapse/issues/3578))
- support registering regular users non-interactively with register_new_matrix_user script ([\#3836](https://github.com/matrix-org/synapse/issues/3836))
- Fix broken invite email links for self hosted riots ([\#3868](https://github.com/matrix-org/synapse/issues/3868))
- Don't ratelimit autojoins ([\#3879](https://github.com/matrix-org/synapse/issues/3879))
- Fix 500 error when deleting unknown room alias ([\#3889](https://github.com/matrix-org/synapse/issues/3889))
- Fix some b'abcd' noise in logs and metrics ([\#3892](https://github.com/matrix-org/synapse/issues/3892), [\#3895](https://github.com/matrix-org/synapse/issues/3895))
- When we join a room, always try the server we used for the alias lookup first, to avoid unresponsive and out-of-date servers. ([\#3899](https://github.com/matrix-org/synapse/issues/3899))
- Fix incorrect server-name indication for outgoing federation requests ([\#3907](https://github.com/matrix-org/synapse/issues/3907))
- Fix adding client IPs to the database failing on Python 3. ([\#3908](https://github.com/matrix-org/synapse/issues/3908))
- Fix bug where things occaisonally were not being timed out correctly. ([\#3910](https://github.com/matrix-org/synapse/issues/3910))
- Fix bug where outbound federation would stop talking to some servers when using workers ([\#3914](https://github.com/matrix-org/synapse/issues/3914))
- Fix some instances of ExpiringCache not expiring cache items ([\#3932](https://github.com/matrix-org/synapse/issues/3932), [\#3980](https://github.com/matrix-org/synapse/issues/3980))
- Fix out-of-bounds error when LLing yourself ([\#3936](https://github.com/matrix-org/synapse/issues/3936))
- Sending server notices regarding user consent now works on Python 3. ([\#3938](https://github.com/matrix-org/synapse/issues/3938))
- Fix exceptions from metrics handler ([\#3956](https://github.com/matrix-org/synapse/issues/3956))
- Fix error message for events with m.room.create missing from auth_events ([\#3960](https://github.com/matrix-org/synapse/issues/3960))
- Fix errors due to concurrent monthly_active_user upserts ([\#3961](https://github.com/matrix-org/synapse/issues/3961))
- Fix exceptions when processing incoming events over federation ([\#3968](https://github.com/matrix-org/synapse/issues/3968))
- Replaced all occurences of e.message with str(e). Contributed by Schnuffle ([\#3970](https://github.com/matrix-org/synapse/issues/3970))
- Fix lazy loaded sync in the presence of rejected state events ([\#3986](https://github.com/matrix-org/synapse/issues/3986))
- Fix error when logging incomplete HTTP requests ([\#3990](https://github.com/matrix-org/synapse/issues/3990))


Internal Changes
----------------

- Unit tests can now be run under PostgreSQL in Docker using ``test_postgresql.sh``. ([\#3699](https://github.com/matrix-org/synapse/issues/3699))
- Speed up calculation of typing updates for replication ([\#3794](https://github.com/matrix-org/synapse/issues/3794))
- Remove documentation regarding installation on Cygwin, the use of WSL is recommended instead. ([\#3873](https://github.com/matrix-org/synapse/issues/3873))
- Fix typo in README, synaspse -> synapse ([\#3897](https://github.com/matrix-org/synapse/issues/3897))
- Increase the timeout when filling missing events in federation requests ([\#3903](https://github.com/matrix-org/synapse/issues/3903))
- Improve the logging when handling a federation transaction ([\#3904](https://github.com/matrix-org/synapse/issues/3904), [\#3966](https://github.com/matrix-org/synapse/issues/3966))
- Improve logging of outbound federation requests ([\#3906](https://github.com/matrix-org/synapse/issues/3906), [\#3909](https://github.com/matrix-org/synapse/issues/3909))
- Fix the docker image building on python 3 ([\#3911](https://github.com/matrix-org/synapse/issues/3911))
- Add a regression test for logging failed HTTP requests on Python 3. ([\#3912](https://github.com/matrix-org/synapse/issues/3912))
- Comments and interface cleanup for on_receive_pdu ([\#3924](https://github.com/matrix-org/synapse/issues/3924))
- Fix spurious exceptions when remote http client closes conncetion ([\#3925](https://github.com/matrix-org/synapse/issues/3925))
- Log exceptions thrown by background tasks ([\#3927](https://github.com/matrix-org/synapse/issues/3927))
- Add a cache to get_destination_retry_timings ([\#3933](https://github.com/matrix-org/synapse/issues/3933), [\#3991](https://github.com/matrix-org/synapse/issues/3991))
- Automate pushes to docker hub ([\#3946](https://github.com/matrix-org/synapse/issues/3946))
- Require attrs 16.0.0 or later ([\#3947](https://github.com/matrix-org/synapse/issues/3947))
- Fix incompatibility with python3 on alpine ([\#3948](https://github.com/matrix-org/synapse/issues/3948))
- Run the test suite on the oldest supported versions of our dependencies in CI. ([\#3952](https://github.com/matrix-org/synapse/issues/3952))
- CircleCI now only runs merged jobs on PRs, and commit jobs on develop, master, and release branches. ([\#3957](https://github.com/matrix-org/synapse/issues/3957))
- Fix docstrings and add tests for state store methods ([\#3958](https://github.com/matrix-org/synapse/issues/3958))
- fix docstring for FederationClient.get_state_for_room ([\#3963](https://github.com/matrix-org/synapse/issues/3963))
- Run notify_app_services as a bg process ([\#3965](https://github.com/matrix-org/synapse/issues/3965))
- Clarifications in FederationHandler ([\#3967](https://github.com/matrix-org/synapse/issues/3967))
- Further reduce the docker image size ([\#3972](https://github.com/matrix-org/synapse/issues/3972))
- Build py3 docker images for docker hub too ([\#3976](https://github.com/matrix-org/synapse/issues/3976))
- Updated the installation instructions to point to the matrix-synapse package on PyPI. ([\#3985](https://github.com/matrix-org/synapse/issues/3985))
- Disable USE_FROZEN_DICTS for unittests by default. ([\#3987](https://github.com/matrix-org/synapse/issues/3987))
- Remove unused Jenkins and development related files from the repo. ([\#3988](https://github.com/matrix-org/synapse/issues/3988))
- Improve stacktraces in certain exceptions in the logs ([\#3989](https://github.com/matrix-org/synapse/issues/3989))


Synapse 0.33.5.1 (2018-09-25)
=============================

Internal Changes
----------------

- Fix incompatibility with older Twisted version in tests. Thanks @OlegGirko! ([\#3940](https://github.com/matrix-org/synapse/issues/3940))


Synapse 0.33.5 (2018-09-24)
===========================

No significant changes.


Synapse 0.33.5rc1 (2018-09-17)
==============================

Features
--------

- Python 3.5 and 3.6 support is now in beta. ([\#3576](https://github.com/matrix-org/synapse/issues/3576))
- Implement `event_format` filter param in `/sync` ([\#3790](https://github.com/matrix-org/synapse/issues/3790))
- Add synapse_admin_mau:registered_reserved_users metric to expose number of real reaserved users ([\#3846](https://github.com/matrix-org/synapse/issues/3846))


Bugfixes
--------

- Remove connection ID for replication prometheus metrics, as it creates a large number of new series. ([\#3788](https://github.com/matrix-org/synapse/issues/3788))
- guest users should not be part of mau total ([\#3800](https://github.com/matrix-org/synapse/issues/3800))
- Bump dependency on pyopenssl 16.x, to avoid incompatibility with recent Twisted. ([\#3804](https://github.com/matrix-org/synapse/issues/3804))
- Fix existing room tags not coming down sync when joining a room ([\#3810](https://github.com/matrix-org/synapse/issues/3810))
- Fix jwt import check ([\#3824](https://github.com/matrix-org/synapse/issues/3824))
- fix VOIP crashes under Python 3 (#3821) ([\#3835](https://github.com/matrix-org/synapse/issues/3835))
- Fix manhole so that it works with latest openssh clients ([\#3841](https://github.com/matrix-org/synapse/issues/3841))
- Fix outbound requests occasionally wedging, which can result in federation breaking between servers. ([\#3845](https://github.com/matrix-org/synapse/issues/3845))
- Show heroes if room name/canonical alias has been deleted ([\#3851](https://github.com/matrix-org/synapse/issues/3851))
- Fix handling of redacted events from federation ([\#3859](https://github.com/matrix-org/synapse/issues/3859))
-  ([\#3874](https://github.com/matrix-org/synapse/issues/3874))
- Mitigate outbound federation randomly becoming wedged ([\#3875](https://github.com/matrix-org/synapse/issues/3875))


Internal Changes
----------------

- CircleCI tests now run on the potential merge of a PR. ([\#3704](https://github.com/matrix-org/synapse/issues/3704))
- http/ is now ported to Python 3. ([\#3771](https://github.com/matrix-org/synapse/issues/3771))
- Improve human readable error messages for threepid registration/account update ([\#3789](https://github.com/matrix-org/synapse/issues/3789))
- Make /sync slightly faster by avoiding needless copies ([\#3795](https://github.com/matrix-org/synapse/issues/3795))
- handlers/ is now ported to Python 3. ([\#3803](https://github.com/matrix-org/synapse/issues/3803))
- Limit the number of PDUs/EDUs per federation transaction ([\#3805](https://github.com/matrix-org/synapse/issues/3805))
- Only start postgres instance for postgres tests on Travis CI ([\#3806](https://github.com/matrix-org/synapse/issues/3806))
- tests/ is now ported to Python 3. ([\#3808](https://github.com/matrix-org/synapse/issues/3808))
- crypto/ is now ported to Python 3. ([\#3822](https://github.com/matrix-org/synapse/issues/3822))
- rest/ is now ported to Python 3. ([\#3823](https://github.com/matrix-org/synapse/issues/3823))
- add some logging for the keyring queue ([\#3826](https://github.com/matrix-org/synapse/issues/3826))
- speed up lazy loading by 2-3x ([\#3827](https://github.com/matrix-org/synapse/issues/3827))
- Improved Dockerfile to remove build requirements after building reducing the image size. ([\#3834](https://github.com/matrix-org/synapse/issues/3834))
- Disable lazy loading for incremental syncs for now ([\#3840](https://github.com/matrix-org/synapse/issues/3840))
- federation/ is now ported to Python 3. ([\#3847](https://github.com/matrix-org/synapse/issues/3847))
- Log when we retry outbound requests ([\#3853](https://github.com/matrix-org/synapse/issues/3853))
- Removed some excess logging messages. ([\#3855](https://github.com/matrix-org/synapse/issues/3855))
- Speed up purge history for rooms that have been previously purged ([\#3856](https://github.com/matrix-org/synapse/issues/3856))
- Refactor some HTTP timeout code. ([\#3857](https://github.com/matrix-org/synapse/issues/3857))
- Fix running merged builds on CircleCI ([\#3858](https://github.com/matrix-org/synapse/issues/3858))
- Fix typo in replication stream exception. ([\#3860](https://github.com/matrix-org/synapse/issues/3860))
- Add in flight real time metrics for Measure blocks ([\#3871](https://github.com/matrix-org/synapse/issues/3871))
- Disable buffering and automatic retrying in treq requests to prevent timeouts. ([\#3872](https://github.com/matrix-org/synapse/issues/3872))
- mention jemalloc in the README ([\#3877](https://github.com/matrix-org/synapse/issues/3877))
- Remove unmaintained "nuke-room-from-db.sh" script ([\#3888](https://github.com/matrix-org/synapse/issues/3888))


Synapse 0.33.4 (2018-09-07)
===========================

Internal Changes
----------------

- Unignore synctl in .dockerignore to fix docker builds ([\#3802](https://github.com/matrix-org/synapse/issues/3802))


Synapse 0.33.4rc2 (2018-09-06)
==============================

Pull in security fixes from v0.33.3.1


Synapse 0.33.3.1 (2018-09-06)
=============================

SECURITY FIXES
--------------

- Fix an issue where event signatures were not always correctly validated ([\#3796](https://github.com/matrix-org/synapse/issues/3796))
- Fix an issue where server_acls could be circumvented for incoming events ([\#3796](https://github.com/matrix-org/synapse/issues/3796))


Internal Changes
----------------

- Unignore synctl in .dockerignore to fix docker builds ([\#3802](https://github.com/matrix-org/synapse/issues/3802))


Synapse 0.33.4rc1 (2018-09-04)
==============================

Features
--------

- Support profile API endpoints on workers ([\#3659](https://github.com/matrix-org/synapse/issues/3659))
- Server notices for resource limit blocking ([\#3680](https://github.com/matrix-org/synapse/issues/3680))
- Allow guests to use /rooms/:roomId/event/:eventId ([\#3724](https://github.com/matrix-org/synapse/issues/3724))
- Add mau_trial_days config param, so that users only get counted as MAU after N days. ([\#3749](https://github.com/matrix-org/synapse/issues/3749))
- Require twisted 17.1 or later (fixes [#3741](https://github.com/matrix-org/synapse/issues/3741)). ([\#3751](https://github.com/matrix-org/synapse/issues/3751))


Bugfixes
--------

- Fix error collecting prometheus metrics when run on dedicated thread due to threading concurrency issues ([\#3722](https://github.com/matrix-org/synapse/issues/3722))
- Fix bug where we resent "limit exceeded" server notices repeatedly ([\#3747](https://github.com/matrix-org/synapse/issues/3747))
- Fix bug where we broke sync when using limit_usage_by_mau but hadn't configured server notices ([\#3753](https://github.com/matrix-org/synapse/issues/3753))
- Fix 'federation_domain_whitelist' such that an empty list correctly blocks all outbound federation traffic ([\#3754](https://github.com/matrix-org/synapse/issues/3754))
- Fix tagging of server notice rooms ([\#3755](https://github.com/matrix-org/synapse/issues/3755), [\#3756](https://github.com/matrix-org/synapse/issues/3756))
- Fix 'admin_uri' config variable and error parameter to be 'admin_contact' to match the spec. ([\#3758](https://github.com/matrix-org/synapse/issues/3758))
- Don't return non-LL-member state in incremental sync state blocks ([\#3760](https://github.com/matrix-org/synapse/issues/3760))
- Fix bug in sending presence over federation ([\#3768](https://github.com/matrix-org/synapse/issues/3768))
- Fix bug where preserved threepid user comes to sign up and server is mau blocked ([\#3777](https://github.com/matrix-org/synapse/issues/3777))

Internal Changes
----------------

- Removed the link to the unmaintained matrix-synapse-auto-deploy project from the readme. ([\#3378](https://github.com/matrix-org/synapse/issues/3378))
- Refactor state module to support multiple room versions ([\#3673](https://github.com/matrix-org/synapse/issues/3673))
- The synapse.storage module has been ported to Python 3. ([\#3725](https://github.com/matrix-org/synapse/issues/3725))
- Split the state_group_cache into member and non-member state events (and so speed up LL /sync) ([\#3726](https://github.com/matrix-org/synapse/issues/3726))
- Log failure to authenticate remote servers as warnings (without stack traces) ([\#3727](https://github.com/matrix-org/synapse/issues/3727))
- The CONTRIBUTING guidelines have been updated to mention our use of Markdown and that .misc files have content. ([\#3730](https://github.com/matrix-org/synapse/issues/3730))
- Reference the need for an HTTP replication port when using the federation_reader worker ([\#3734](https://github.com/matrix-org/synapse/issues/3734))
- Fix minor spelling error in federation client documentation. ([\#3735](https://github.com/matrix-org/synapse/issues/3735))
- Remove redundant state resolution function ([\#3737](https://github.com/matrix-org/synapse/issues/3737))
- The test suite now passes on PostgreSQL. ([\#3740](https://github.com/matrix-org/synapse/issues/3740))
- Fix MAU cache invalidation due to missing yield ([\#3746](https://github.com/matrix-org/synapse/issues/3746))
- Make sure that we close db connections opened during init ([\#3764](https://github.com/matrix-org/synapse/issues/3764))


Synapse 0.33.3 (2018-08-22)
===========================

Bugfixes
--------

- Fix bug introduced in v0.33.3rc1 which made the ToS give a 500 error ([\#3732](https://github.com/matrix-org/synapse/issues/3732))


Synapse 0.33.3rc2 (2018-08-21)
==============================

Bugfixes
--------

- Fix bug in v0.33.3rc1 which caused infinite loops and OOMs ([\#3723](https://github.com/matrix-org/synapse/issues/3723))


Synapse 0.33.3rc1 (2018-08-21)
==============================

Features
--------

- Add support for the SNI extension to federation TLS connections. Thanks to @vojeroen! ([\#3439](https://github.com/matrix-org/synapse/issues/3439))
- Add /_media/r0/config ([\#3184](https://github.com/matrix-org/synapse/issues/3184))
- speed up /members API and add `at` and `membership` params as per MSC1227 ([\#3568](https://github.com/matrix-org/synapse/issues/3568))
- implement `summary` block in /sync response as per MSC688 ([\#3574](https://github.com/matrix-org/synapse/issues/3574))
- Add lazy-loading support to /messages as per MSC1227 ([\#3589](https://github.com/matrix-org/synapse/issues/3589))
- Add ability to limit number of monthly active users on the server ([\#3633](https://github.com/matrix-org/synapse/issues/3633))
- Support more federation endpoints on workers ([\#3653](https://github.com/matrix-org/synapse/issues/3653))
- Basic support for room versioning ([\#3654](https://github.com/matrix-org/synapse/issues/3654))
- Ability to disable client/server Synapse via conf toggle ([\#3655](https://github.com/matrix-org/synapse/issues/3655))
- Ability to whitelist specific threepids against monthly active user limiting ([\#3662](https://github.com/matrix-org/synapse/issues/3662))
- Add some metrics for the appservice and federation event sending loops ([\#3664](https://github.com/matrix-org/synapse/issues/3664))
- Where server is disabled, block ability for locked out users to read new messages ([\#3670](https://github.com/matrix-org/synapse/issues/3670))
- set admin uri via config, to be used in error messages where the user should contact the administrator ([\#3687](https://github.com/matrix-org/synapse/issues/3687))
- Synapse's presence functionality can now be disabled with the "use_presence" configuration option. ([\#3694](https://github.com/matrix-org/synapse/issues/3694))
- For resource limit blocked users, prevent writing into rooms ([\#3708](https://github.com/matrix-org/synapse/issues/3708))


Bugfixes
--------

- Fix occasional glitches in the synapse_event_persisted_position metric ([\#3658](https://github.com/matrix-org/synapse/issues/3658))
- Fix bug on deleting 3pid when using identity servers that don't support unbind API ([\#3661](https://github.com/matrix-org/synapse/issues/3661))
- Make the tests pass on Twisted < 18.7.0 ([\#3676](https://github.com/matrix-org/synapse/issues/3676))
- Don’t ship recaptcha_ajax.js, use it directly from Google ([\#3677](https://github.com/matrix-org/synapse/issues/3677))
- Fixes test_reap_monthly_active_users so it passes under postgres ([\#3681](https://github.com/matrix-org/synapse/issues/3681))
- Fix mau blocking calulation bug on login ([\#3689](https://github.com/matrix-org/synapse/issues/3689))
- Fix missing yield in synapse.storage.monthly_active_users.initialise_reserved_users ([\#3692](https://github.com/matrix-org/synapse/issues/3692))
- Improve HTTP request logging to include all requests ([\#3700](https://github.com/matrix-org/synapse/issues/3700))
- Avoid timing out requests while we are streaming back the response ([\#3701](https://github.com/matrix-org/synapse/issues/3701))
- Support more federation endpoints on workers ([\#3705](https://github.com/matrix-org/synapse/issues/3705), [\#3713](https://github.com/matrix-org/synapse/issues/3713))
- Fix "Starting db txn 'get_all_updated_receipts' from sentinel context" warning ([\#3710](https://github.com/matrix-org/synapse/issues/3710))
- Fix bug where `state_cache` cache factor ignored environment variables ([\#3719](https://github.com/matrix-org/synapse/issues/3719))


Deprecations and Removals
-------------------------

- The Shared-Secret registration method of the legacy v1/register REST endpoint has been removed. For a replacement, please see [the admin/register API documentation](https://github.com/matrix-org/synapse/blob/master/docs/admin_api/register_api.rst). ([\#3703](https://github.com/matrix-org/synapse/issues/3703))


Internal Changes
----------------

- The test suite now can run under PostgreSQL. ([\#3423](https://github.com/matrix-org/synapse/issues/3423))
- Refactor HTTP replication endpoints to reduce code duplication ([\#3632](https://github.com/matrix-org/synapse/issues/3632))
- Tests now correctly execute on Python 3. ([\#3647](https://github.com/matrix-org/synapse/issues/3647))
- Sytests can now be run inside a Docker container. ([\#3660](https://github.com/matrix-org/synapse/issues/3660))
- Port over enough to Python 3 to allow the sytests to start. ([\#3668](https://github.com/matrix-org/synapse/issues/3668))
- Update docker base image from alpine 3.7 to 3.8. ([\#3669](https://github.com/matrix-org/synapse/issues/3669))
- Rename synapse.util.async to synapse.util.async_helpers to mitigate async becoming a keyword on Python 3.7. ([\#3678](https://github.com/matrix-org/synapse/issues/3678))
- Synapse's tests are now formatted with the black autoformatter. ([\#3679](https://github.com/matrix-org/synapse/issues/3679))
- Implemented a new testing base class to reduce test boilerplate. ([\#3684](https://github.com/matrix-org/synapse/issues/3684))
- Rename MAU prometheus metrics ([\#3690](https://github.com/matrix-org/synapse/issues/3690))
- add new error type ResourceLimit ([\#3707](https://github.com/matrix-org/synapse/issues/3707))
- Logcontexts for replication command handlers ([\#3709](https://github.com/matrix-org/synapse/issues/3709))
- Update admin register API documentation to reference a real user ID. ([\#3712](https://github.com/matrix-org/synapse/issues/3712))


Synapse 0.33.2 (2018-08-09)
===========================

No significant changes.


Synapse 0.33.2rc1 (2018-08-07)
==============================

Features
--------

- add support for the lazy_loaded_members filter as per MSC1227 ([\#2970](https://github.com/matrix-org/synapse/issues/2970))
- add support for the include_redundant_members filter param as per MSC1227 ([\#3331](https://github.com/matrix-org/synapse/issues/3331))
- Add metrics to track resource usage by background processes ([\#3553](https://github.com/matrix-org/synapse/issues/3553), [\#3556](https://github.com/matrix-org/synapse/issues/3556), [\#3604](https://github.com/matrix-org/synapse/issues/3604), [\#3610](https://github.com/matrix-org/synapse/issues/3610))
- Add `code` label to `synapse_http_server_response_time_seconds` prometheus metric ([\#3554](https://github.com/matrix-org/synapse/issues/3554))
- Add support for client_reader to handle more APIs ([\#3555](https://github.com/matrix-org/synapse/issues/3555), [\#3597](https://github.com/matrix-org/synapse/issues/3597))
- make the /context API filter & lazy-load aware as per MSC1227 ([\#3567](https://github.com/matrix-org/synapse/issues/3567))
- Add ability to limit number of monthly active users on the server ([\#3630](https://github.com/matrix-org/synapse/issues/3630))
- When we fail to join a room over federation, pass the error code back to the client. ([\#3639](https://github.com/matrix-org/synapse/issues/3639))
- Add a new /admin/register API for non-interactively creating users. ([\#3415](https://github.com/matrix-org/synapse/issues/3415))


Bugfixes
--------

- Make /directory/list API return 404 for room not found instead of 400. Thanks to @fuzzmz! ([\#3620](https://github.com/matrix-org/synapse/issues/3620))
- Default inviter_display_name to mxid for email invites ([\#3391](https://github.com/matrix-org/synapse/issues/3391))
- Don't generate TURN credentials if no TURN config options are set ([\#3514](https://github.com/matrix-org/synapse/issues/3514))
- Correctly announce deleted devices over federation ([\#3520](https://github.com/matrix-org/synapse/issues/3520))
- Catch failures saving metrics captured by Measure, and instead log the faulty metrics information for further analysis. ([\#3548](https://github.com/matrix-org/synapse/issues/3548))
- Unicode passwords are now normalised before hashing, preventing the instance where two different devices or browsers might send a different UTF-8 sequence for the password. ([\#3569](https://github.com/matrix-org/synapse/issues/3569))
- Fix potential stack overflow and deadlock under heavy load ([\#3570](https://github.com/matrix-org/synapse/issues/3570))
- Respond with M_NOT_FOUND when profiles are not found locally or over federation. Fixes #3585 ([\#3585](https://github.com/matrix-org/synapse/issues/3585))
- Fix failure to persist events over federation under load ([\#3601](https://github.com/matrix-org/synapse/issues/3601))
- Fix updating of cached remote profiles ([\#3605](https://github.com/matrix-org/synapse/issues/3605))
- Fix 'tuple index out of range' error ([\#3607](https://github.com/matrix-org/synapse/issues/3607))
- Only import secrets when available (fix for py < 3.6) ([\#3626](https://github.com/matrix-org/synapse/issues/3626))


Internal Changes
----------------

- Remove redundant checks on who_forgot_in_room ([\#3350](https://github.com/matrix-org/synapse/issues/3350))
- Remove unnecessary event re-signing hacks ([\#3367](https://github.com/matrix-org/synapse/issues/3367))
- Rewrite cache list decorator ([\#3384](https://github.com/matrix-org/synapse/issues/3384))
- Move v1-only REST APIs into their own module. ([\#3460](https://github.com/matrix-org/synapse/issues/3460))
- Replace more instances of Python 2-only iteritems and itervalues uses. ([\#3562](https://github.com/matrix-org/synapse/issues/3562))
- Refactor EventContext to accept state during init ([\#3577](https://github.com/matrix-org/synapse/issues/3577))
- Improve Dockerfile and docker-compose instructions ([\#3543](https://github.com/matrix-org/synapse/issues/3543))
- Release notes are now in the Markdown format. ([\#3552](https://github.com/matrix-org/synapse/issues/3552))
- add config for pep8 ([\#3559](https://github.com/matrix-org/synapse/issues/3559))
- Merge Linearizer and Limiter ([\#3571](https://github.com/matrix-org/synapse/issues/3571), [\#3572](https://github.com/matrix-org/synapse/issues/3572))
- Lazily load state on master process when using workers to reduce DB consumption ([\#3579](https://github.com/matrix-org/synapse/issues/3579), [\#3581](https://github.com/matrix-org/synapse/issues/3581), [\#3582](https://github.com/matrix-org/synapse/issues/3582), [\#3584](https://github.com/matrix-org/synapse/issues/3584))
- Fixes and optimisations for resolve_state_groups ([\#3586](https://github.com/matrix-org/synapse/issues/3586))
- Improve logging for exceptions when handling PDUs ([\#3587](https://github.com/matrix-org/synapse/issues/3587))
- Add some measure blocks to persist_events ([\#3590](https://github.com/matrix-org/synapse/issues/3590))
- Fix some random logcontext leaks. ([\#3591](https://github.com/matrix-org/synapse/issues/3591), [\#3606](https://github.com/matrix-org/synapse/issues/3606))
- Speed up calculating state deltas in persist_event loop ([\#3592](https://github.com/matrix-org/synapse/issues/3592))
- Attempt to reduce amount of state pulled out of DB during persist_events ([\#3595](https://github.com/matrix-org/synapse/issues/3595))
- Fix a documentation typo in on_make_leave_request ([\#3609](https://github.com/matrix-org/synapse/issues/3609))
- Make EventStore inherit from EventFederationStore ([\#3612](https://github.com/matrix-org/synapse/issues/3612))
- Remove some redundant joins on event_edges.room_id ([\#3613](https://github.com/matrix-org/synapse/issues/3613))
- Stop populating events.content ([\#3614](https://github.com/matrix-org/synapse/issues/3614))
- Update the /send_leave path registration to use event_id rather than a transaction ID. ([\#3616](https://github.com/matrix-org/synapse/issues/3616))
- Refactor FederationHandler to move DB writes into separate functions ([\#3621](https://github.com/matrix-org/synapse/issues/3621))
- Remove unused field "pdu_failures" from transactions. ([\#3628](https://github.com/matrix-org/synapse/issues/3628))
- rename replication_layer to federation_client ([\#3634](https://github.com/matrix-org/synapse/issues/3634))
- Factor out exception handling in federation_client ([\#3638](https://github.com/matrix-org/synapse/issues/3638))
- Refactor location of docker build script. ([\#3644](https://github.com/matrix-org/synapse/issues/3644))
- Update CONTRIBUTING to mention newsfragments. ([\#3645](https://github.com/matrix-org/synapse/issues/3645))


Synapse 0.33.1 (2018-08-02)
===========================

SECURITY FIXES
--------------

- Fix a potential issue where servers could request events for rooms they have not joined. ([\#3641](https://github.com/matrix-org/synapse/issues/3641))
- Fix a potential issue where users could see events in private rooms before they joined. ([\#3642](https://github.com/matrix-org/synapse/issues/3642))

Synapse 0.33.0 (2018-07-19)
===========================

Bugfixes
--------

-   Disable a noisy warning about logcontexts. ([\#3561](https://github.com/matrix-org/synapse/issues/3561))

Synapse 0.33.0rc1 (2018-07-18)
==============================

Features
--------

-   Enforce the specified API for report\_event. ([\#3316](https://github.com/matrix-org/synapse/issues/3316))
-   Include CPU time from database threads in request/block metrics. ([\#3496](https://github.com/matrix-org/synapse/issues/3496), [\#3501](https://github.com/matrix-org/synapse/issues/3501))
-   Add CPU metrics for \_fetch\_event\_list. ([\#3497](https://github.com/matrix-org/synapse/issues/3497))
-   Optimisation to make handling incoming federation requests more efficient. ([\#3541](https://github.com/matrix-org/synapse/issues/3541))

Bugfixes
--------

-   Fix a significant performance regression in /sync. ([\#3505](https://github.com/matrix-org/synapse/issues/3505), [\#3521](https://github.com/matrix-org/synapse/issues/3521), [\#3530](https://github.com/matrix-org/synapse/issues/3530), [\#3544](https://github.com/matrix-org/synapse/issues/3544))
-   Use more portable syntax in our use of the attrs package, widening the supported versions. ([\#3498](https://github.com/matrix-org/synapse/issues/3498))
-   Fix queued federation requests being processed in the wrong order. ([\#3533](https://github.com/matrix-org/synapse/issues/3533))
-   Ensure that erasure requests are correctly honoured for publicly accessible rooms when accessed over federation. ([\#3546](https://github.com/matrix-org/synapse/issues/3546))

Misc
----

-   Refactoring to improve testability. ([\#3351](https://github.com/matrix-org/synapse/issues/3351), [\#3499](https://github.com/matrix-org/synapse/issues/3499))
-   Use `isort` to sort imports. ([\#3463](https://github.com/matrix-org/synapse/issues/3463), [\#3464](https://github.com/matrix-org/synapse/issues/3464), [\#3540](https://github.com/matrix-org/synapse/issues/3540))
-   Use parse and asserts from http.servlet. ([\#3534](https://github.com/matrix-org/synapse/issues/3534), [\#3535](https://github.com/matrix-org/synapse/issues/3535)).

Synapse 0.32.2 (2018-07-07)
===========================

Bugfixes
--------

-   Amend the Python dependencies to depend on attrs from PyPI, not attr ([\#3492](https://github.com/matrix-org/synapse/issues/3492))

Synapse 0.32.1 (2018-07-06)
===========================

Bugfixes
--------

-   Add explicit dependency on netaddr ([\#3488](https://github.com/matrix-org/synapse/issues/3488))

Changes in synapse v0.32.0 (2018-07-06)
=======================================

No changes since 0.32.0rc1

Synapse 0.32.0rc1 (2018-07-05)
==============================

Features
--------

-   Add blacklist & whitelist of servers allowed to send events to a room via `m.room.server_acl` event.
-   Cache factor override system for specific caches ([\#3334](https://github.com/matrix-org/synapse/issues/3334))
-   Add metrics to track appservice transactions ([\#3344](https://github.com/matrix-org/synapse/issues/3344))
-   Try to log more helpful info when a sig verification fails ([\#3372](https://github.com/matrix-org/synapse/issues/3372))
-   Synapse now uses the best performing JSON encoder/decoder according to your runtime (simplejson on CPython, stdlib json on PyPy). ([\#3462](https://github.com/matrix-org/synapse/issues/3462))
-   Add optional ip\_range\_whitelist param to AS registration files to lock AS IP access ([\#3465](https://github.com/matrix-org/synapse/issues/3465))
-   Reject invalid server names in federation requests ([\#3480](https://github.com/matrix-org/synapse/issues/3480))
-   Reject invalid server names in homeserver.yaml ([\#3483](https://github.com/matrix-org/synapse/issues/3483))

Bugfixes
--------

-   Strip access\_token from outgoing requests ([\#3327](https://github.com/matrix-org/synapse/issues/3327))
-   Redact AS tokens in logs ([\#3349](https://github.com/matrix-org/synapse/issues/3349))
-   Fix federation backfill from SQLite servers ([\#3355](https://github.com/matrix-org/synapse/issues/3355))
-   Fix event-purge-by-ts admin API ([\#3363](https://github.com/matrix-org/synapse/issues/3363))
-   Fix event filtering in get\_missing\_events handler ([\#3371](https://github.com/matrix-org/synapse/issues/3371))
-   Synapse is now stricter regarding accepting events which it cannot retrieve the prev\_events for. ([\#3456](https://github.com/matrix-org/synapse/issues/3456))
-   Fix bug where synapse would explode when receiving unicode in HTTP User-Agent header ([\#3470](https://github.com/matrix-org/synapse/issues/3470))
-   Invalidate cache on correct thread to avoid race ([\#3473](https://github.com/matrix-org/synapse/issues/3473))

Improved Documentation
----------------------

-   `doc/postgres.rst`: fix display of the last command block. Thanks to @ArchangeGabriel! ([\#3340](https://github.com/matrix-org/synapse/issues/3340))

Deprecations and Removals
-------------------------

-   Remove was\_forgotten\_at ([\#3324](https://github.com/matrix-org/synapse/issues/3324))

Misc
----

-   [\#3332](https://github.com/matrix-org/synapse/issues/3332), [\#3341](https://github.com/matrix-org/synapse/issues/3341), [\#3347](https://github.com/matrix-org/synapse/issues/3347), [\#3348](https://github.com/matrix-org/synapse/issues/3348), [\#3356](https://github.com/matrix-org/synapse/issues/3356), [\#3385](https://github.com/matrix-org/synapse/issues/3385), [\#3446](https://github.com/matrix-org/synapse/issues/3446), [\#3447](https://github.com/matrix-org/synapse/issues/3447), [\#3467](https://github.com/matrix-org/synapse/issues/3467), [\#3474](https://github.com/matrix-org/synapse/issues/3474)

Changes in synapse v0.31.2 (2018-06-14)
=======================================

SECURITY UPDATE: Prevent unauthorised users from setting state events in a room when there is no `m.room.power_levels` event in force in the room. (PR #3397)

Discussion around the Matrix Spec change proposal for this change can be followed at <https://github.com/matrix-org/matrix-doc/issues/1304>.

Changes in synapse v0.31.1 (2018-06-08)
=======================================

v0.31.1 fixes a security bug in the `get_missing_events` federation API where event visibility rules were not applied correctly.

We are not aware of it being actively exploited but please upgrade asap.

Bug Fixes:

-   Fix event filtering in get\_missing\_events handler (PR #3371)

Changes in synapse v0.31.0 (2018-06-06)
=======================================

Most notable change from v0.30.0 is to switch to the python prometheus library to improve system stats reporting. WARNING: this changes a number of prometheus metrics in a backwards-incompatible manner. For more details, see [docs/metrics-howto.rst](docs/metrics-howto.rst#removal-of-deprecated-metrics--time-based-counters-becoming-histograms-in-0310).

Bug Fixes:

-   Fix metric documentation tables (PR #3341)
-   Fix LaterGauge error handling (694968f)
-   Fix replication metrics (b7e7fd2)

Changes in synapse v0.31.0-rc1 (2018-06-04)
===========================================

Features:

-   Switch to the Python Prometheus library (PR #3256, #3274)
-   Let users leave the server notice room after joining (PR #3287)

Changes:

-   daily user type phone home stats (PR #3264)
-   Use iter\* methods for \_filter\_events\_for\_server (PR #3267)
-   Docs on consent bits (PR #3268)
-   Remove users from user directory on deactivate (PR #3277)
-   Avoid sending consent notice to guest users (PR #3288)
-   disable CPUMetrics if no /proc/self/stat (PR #3299)
-   Consistently use six\'s iteritems and wrap lazy keys/values in list() if they\'re not meant to be lazy (PR #3307)
-   Add private IPv6 addresses to example config for url preview blacklist (PR #3317) Thanks to @thegcat!
-   Reduce stuck read-receipts: ignore depth when updating (PR #3318)
-   Put python\'s logs into Trial when running unit tests (PR #3319)

Changes, python 3 migration:

-   Replace some more comparisons with six (PR #3243) Thanks to @NotAFile!
-   replace some iteritems with six (PR #3244) Thanks to @NotAFile!
-   Add batch\_iter to utils (PR #3245) Thanks to @NotAFile!
-   use repr, not str (PR #3246) Thanks to @NotAFile!
-   Misc Python3 fixes (PR #3247) Thanks to @NotAFile!
-   Py3 storage/\_base.py (PR #3278) Thanks to @NotAFile!
-   more six iteritems (PR #3279) Thanks to @NotAFile!
-   More Misc. py3 fixes (PR #3280) Thanks to @NotAFile!
-   remaining isintance fixes (PR #3281) Thanks to @NotAFile!
-   py3-ize state.py (PR #3283) Thanks to @NotAFile!
-   extend tox testing for py3 to avoid regressions (PR #3302) Thanks to @krombel!
-   use memoryview in py3 (PR #3303) Thanks to @NotAFile!

Bugs:

-   Fix federation backfill bugs (PR #3261)
-   federation: fix LaterGauge usage (PR #3328) Thanks to @intelfx!

Changes in synapse v0.30.0 (2018-05-24)
=======================================

\'Server Notices\' are a new feature introduced in Synapse 0.30. They provide a channel whereby server administrators can send messages to users on the server.

They are used as part of communication of the server policies (see `docs/consent_tracking.md`), however the intention is that they may also find a use for features such as \"Message of the day\".

This feature is specific to Synapse, but uses standard Matrix communication mechanisms, so should work with any Matrix client. For more details see `docs/server_notices.md`

Further Server Notices/Consent Tracking Support:

-   Allow overriding the server\_notices user\'s avatar (PR #3273)
-   Use the localpart in the consent uri (PR #3272)
-   Support for putting %(consent\_uri)s in messages (PR #3271)
-   Block attempts to send server notices to remote users (PR #3270)
-   Docs on consent bits (PR #3268)

Changes in synapse v0.30.0-rc1 (2018-05-23)
===========================================

Server Notices/Consent Tracking Support:

-   ConsentResource to gather policy consent from users (PR #3213)
-   Move RoomCreationHandler out of synapse.handlers.Handlers (PR #3225)
-   Infrastructure for a server notices room (PR #3232)
-   Send users a server notice about consent (PR #3236)
-   Reject attempts to send event before privacy consent is given (PR #3257)
-   Add a \'has\_consented\' template var to consent forms (PR #3262)
-   Fix dependency on jinja2 (PR #3263)

Features:

-   Cohort analytics (PR #3163, #3241, #3251)
-   Add lxml to docker image for web previews (PR #3239) Thanks to @ptman!
-   Add in flight request metrics (PR #3252)

Changes:

-   Remove unused update\_external\_syncs (PR #3233)
-   Use stream rather depth ordering for push actions (PR #3212)
-   Make purge\_history operate on tokens (PR #3221)
-   Don\'t support limitless pagination (PR #3265)

Bug Fixes:

-   Fix logcontext resource usage tracking (PR #3258)
-   Fix error in handling receipts (PR #3235)
-   Stop the transaction cache caching failures (PR #3255)

Changes in synapse v0.29.1 (2018-05-17)
=======================================

Changes:

-   Update docker documentation (PR #3222)

Changes in synapse v0.29.0 (2018-05-16)
=======================================

Not changes since v0.29.0-rc1

Changes in synapse v0.29.0-rc1 (2018-05-14)
===========================================

Notable changes, a docker file for running Synapse (Thanks to @kaiyou!) and a closed spec bug in the Client Server API. Additionally further prep for Python 3 migration.

Potentially breaking change:

-   Make Client-Server API return 401 for invalid token (PR #3161).

    This changes the Client-server spec to return a 401 error code instead of 403 when the access token is unrecognised. This is the behaviour required by the specification, but some clients may be relying on the old, incorrect behaviour.

    Thanks to @NotAFile for fixing this.

Features:

-   Add a Dockerfile for synapse (PR #2846) Thanks to @kaiyou!

Changes - General:

-   nuke-room-from-db.sh: added postgresql option and help (PR #2337) Thanks to @rubo77!
-   Part user from rooms on account deactivate (PR #3201)
-   Make \'unexpected logging context\' into warnings (PR #3007)
-   Set Server header in SynapseRequest (PR #3208)
-   remove duplicates from groups tables (PR #3129)
-   Improve exception handling for background processes (PR #3138)
-   Add missing consumeErrors to improve exception handling (PR #3139)
-   reraise exceptions more carefully (PR #3142)
-   Remove redundant call to preserve\_fn (PR #3143)
-   Trap exceptions thrown within run\_in\_background (PR #3144)

Changes - Refactors:

-   Refactor /context to reuse pagination storage functions (PR #3193)
-   Refactor recent events func to use pagination func (PR #3195)
-   Refactor pagination DB API to return concrete type (PR #3196)
-   Refactor get\_recent\_events\_for\_room return type (PR #3198)
-   Refactor sync APIs to reuse pagination API (PR #3199)
-   Remove unused code path from member change DB func (PR #3200)
-   Refactor request handling wrappers (PR #3203)
-   transaction\_id, destination defined twice (PR #3209) Thanks to @damir-manapov!
-   Refactor event storage to prepare for changes in state calculations (PR #3141)
-   Set Server header in SynapseRequest (PR #3208)
-   Use deferred.addTimeout instead of time\_bound\_deferred (PR #3127, #3178)
-   Use run\_in\_background in preference to preserve\_fn (PR #3140)

Changes - Python 3 migration:

-   Construct HMAC as bytes on py3 (PR #3156) Thanks to @NotAFile!
-   run config tests on py3 (PR #3159) Thanks to @NotAFile!
-   Open certificate files as bytes (PR #3084) Thanks to @NotAFile!
-   Open config file in non-bytes mode (PR #3085) Thanks to @NotAFile!
-   Make event properties raise AttributeError instead (PR #3102) Thanks to @NotAFile!
-   Use six.moves.urlparse (PR #3108) Thanks to @NotAFile!
-   Add py3 tests to tox with folders that work (PR #3145) Thanks to @NotAFile!
-   Don\'t yield in list comprehensions (PR #3150) Thanks to @NotAFile!
-   Move more xrange to six (PR #3151) Thanks to @NotAFile!
-   make imports local (PR #3152) Thanks to @NotAFile!
-   move httplib import to six (PR #3153) Thanks to @NotAFile!
-   Replace stringIO imports with six (PR #3154, #3168) Thanks to @NotAFile!
-   more bytes strings (PR #3155) Thanks to @NotAFile!

Bug Fixes:

-   synapse fails to start under Twisted \>= 18.4 (PR #3157)
-   Fix a class of logcontext leaks (PR #3170)
-   Fix a couple of logcontext leaks in unit tests (PR #3172)
-   Fix logcontext leak in media repo (PR #3174)
-   Escape label values in prometheus metrics (PR #3175, #3186)
-   Fix \'Unhandled Error\' logs with Twisted 18.4 (PR #3182) Thanks to @Half-Shot!
-   Fix logcontext leaks in rate limiter (PR #3183)
-   notifications: Convert next\_token to string according to the spec (PR #3190) Thanks to @mujx!
-   nuke-room-from-db.sh: fix deletion from search table (PR #3194) Thanks to @rubo77!
-   add guard for None on purge\_history api (PR #3160) Thanks to @krombel!

Changes in synapse v0.28.1 (2018-05-01)
=======================================

SECURITY UPDATE

-   Clamp the allowed values of event depth received over federation to be \[0, 2\^63 - 1\]. This mitigates an attack where malicious events injected with depth = 2\^63 - 1 render rooms unusable. Depth is used to determine the cosmetic ordering of events within a room, and so the ordering of events in such a room will default to using stream\_ordering rather than depth (topological\_ordering).

    This is a temporary solution to mitigate abuse in the wild, whilst a long term solution is being implemented to improve how the depth parameter is used.

    Full details at <https://docs.google.com/document/d/1I3fi2S-XnpO45qrpCsowZv8P8dHcNZ4fsBsbOW7KABI>

-   Pin Twisted to \<18.4 until we stop using the private \_OpenSSLECCurve API.

Changes in synapse v0.28.0 (2018-04-26)
=======================================

Bug Fixes:

-   Fix quarantine media admin API and search reindex (PR #3130)
-   Fix media admin APIs (PR #3134)

Changes in synapse v0.28.0-rc1 (2018-04-24)
===========================================

Minor performance improvement to federation sending and bug fixes.

(Note: This release does not include the delta state resolution implementation discussed in matrix live)

Features:

-   Add metrics for event processing lag (PR #3090)
-   Add metrics for ResponseCache (PR #3092)

Changes:

-   Synapse on PyPy (PR #2760) Thanks to @Valodim!
-   move handling of auto\_join\_rooms to RegisterHandler (PR #2996) Thanks to @krombel!
-   Improve handling of SRV records for federation connections (PR #3016) Thanks to @silkeh!
-   Document the behaviour of ResponseCache (PR #3059)
-   Preparation for py3 (PR #3061, #3073, #3074, #3075, #3103, #3104, #3106, #3107, #3109, #3110) Thanks to @NotAFile!
-   update prometheus dashboard to use new metric names (PR #3069) Thanks to @krombel!
-   use python3-compatible prints (PR #3074) Thanks to @NotAFile!
-   Send federation events concurrently (PR #3078)
-   Limit concurrent event sends for a room (PR #3079)
-   Improve R30 stat definition (PR #3086)
-   Send events to ASes concurrently (PR #3088)
-   Refactor ResponseCache usage (PR #3093)
-   Clarify that SRV may not point to a CNAME (PR #3100) Thanks to @silkeh!
-   Use str(e) instead of e.message (PR #3103) Thanks to @NotAFile!
-   Use six.itervalues in some places (PR #3106) Thanks to @NotAFile!
-   Refactor store.have\_events (PR #3117)

Bug Fixes:

-   Return 401 for invalid access\_token on logout (PR #2938) Thanks to @dklug!
-   Return a 404 rather than a 500 on rejoining empty rooms (PR #3080)
-   fix federation\_domain\_whitelist (PR #3099)
-   Avoid creating events with huge numbers of prev\_events (PR #3113)
-   Reject events which have lots of prev\_events (PR #3118)

Changes in synapse v0.27.4 (2018-04-13)
=======================================

Changes:

-   Update canonicaljson dependency (\#3095)

Changes in synapse v0.27.3 (2018-04-11)
======================================

Bug fixes:

-   URL quote path segments over federation (\#3082)

Changes in synapse v0.27.3-rc2 (2018-04-09)
===========================================

v0.27.3-rc1 used a stale version of the develop branch so the changelog overstates the functionality. v0.27.3-rc2 is up to date, rc1 should be ignored.

Changes in synapse v0.27.3-rc1 (2018-04-09)
===========================================

Notable changes include API support for joinability of groups. Also new metrics and phone home stats. Phone home stats include better visibility of system usage so we can tweak synpase to work better for all users rather than our own experience with matrix.org. Also, recording \'r30\' stat which is the measure we use to track overal growth of the Matrix ecosystem. It is defined as:-

Counts the number of native 30 day retained users, defined as:- \* Users who have created their accounts more than 30 days

:   -   Where last seen at most 30 days ago
    -   Where account creation and last\_seen are \> 30 days\"

Features:

-   Add joinability for groups (PR #3045)
-   Implement group join API (PR #3046)
-   Add counter metrics for calculating state delta (PR #3033)
-   R30 stats (PR #3041)
-   Measure time it takes to calculate state group ID (PR #3043)
-   Add basic performance statistics to phone home (PR #3044)
-   Add response size metrics (PR #3071)
-   phone home cache size configurations (PR #3063)

Changes:

-   Add a blurb explaining the main synapse worker (PR #2886) Thanks to @turt2live!
-   Replace old style error catching with \'as\' keyword (PR #3000) Thanks to @NotAFile!
-   Use .iter\* to avoid copies in StateHandler (PR #3006)
-   Linearize calls to \_generate\_user\_id (PR #3029)
-   Remove last usage of ujson (PR #3030)
-   Use simplejson throughout (PR #3048)
-   Use static JSONEncoders (PR #3049)
-   Remove uses of events.content (PR #3060)
-   Improve database cache performance (PR #3068)

Bug fixes:

-   Add room\_id to the response of rooms/{roomId}/join (PR #2986) Thanks to @jplatte!
-   Fix replication after switch to simplejson (PR #3015)
-   404 correctly on missing paths via NoResource (PR #3022)
-   Fix error when claiming e2e keys from offline servers (PR #3034)
-   fix tests/storage/test\_user\_directory.py (PR #3042)
-   use PUT instead of POST for federating groups/m.join\_policy (PR #3070) Thanks to @krombel!
-   postgres port script: fix state\_groups\_pkey error (PR #3072)

Changes in synapse v0.27.2 (2018-03-26)
=======================================

Bug fixes:

-   Fix bug which broke TCP replication between workers (PR #3015)

Changes in synapse v0.27.1 (2018-03-26)
=======================================

Meta release as v0.27.0 temporarily pointed to the wrong commit

Changes in synapse v0.27.0 (2018-03-26)
=======================================

No changes since v0.27.0-rc2

Changes in synapse v0.27.0-rc2 (2018-03-19)
===========================================

Pulls in v0.26.1

Bug fixes:

-   Fix bug introduced in v0.27.0-rc1 that causes much increased memory usage in state cache (PR #3005)

Changes in synapse v0.26.1 (2018-03-15)
=======================================

Bug fixes:

-   Fix bug where an invalid event caused server to stop functioning correctly, due to parsing and serializing bugs in ujson library (PR #3008)

Changes in synapse v0.27.0-rc1 (2018-03-14)
===========================================

The common case for running Synapse is not to run separate workers, but for those that do, be aware that synctl no longer starts the main synapse when using `-a` option with workers. A new worker file should be added with `worker_app: synapse.app.homeserver`.

This release also begins the process of renaming a number of the metrics reported to prometheus. See [docs/metrics-howto.rst](docs/metrics-howto.rst#block-and-response-metrics-renamed-for-0-27-0). Note that the v0.28.0 release will remove the deprecated metric names.

Features:

-   Add ability for ASes to override message send time (PR #2754)
-   Add support for custom storage providers for media repository (PR #2867, #2777, #2783, #2789, #2791, #2804, #2812, #2814, #2857, #2868, #2767)
-   Add purge API features, see [docs/admin\_api/purge\_history\_api.rst](docs/admin_api/purge_history_api.rst) for full details (PR #2858, #2867, #2882, #2946, #2962, #2943)
-   Add support for whitelisting 3PIDs that users can register. (PR #2813)
-   Add `/room/{id}/event/{id}` API (PR #2766)
-   Add an admin API to get all the media in a room (PR #2818) Thanks to @turt2live!
-   Add `federation_domain_whitelist` option (PR #2820, #2821)

Changes:

-   Continue to factor out processing from main process and into worker processes. See updated [docs/workers.rst](docs/workers.rst) (PR #2892 - \#2904, #2913, #2920 - \#2926, #2947, #2847, #2854, #2872, #2873, #2874, #2928, #2929, #2934, #2856, #2976 - \#2984, #2987 - \#2989, #2991 - \#2993, #2995, #2784)
-   Ensure state cache is used when persisting events (PR #2864, #2871, #2802, #2835, #2836, #2841, #2842, #2849)
-   Change the default config to bind on both IPv4 and IPv6 on all platforms (PR #2435) Thanks to @silkeh!
-   No longer require a specific version of saml2 (PR #2695) Thanks to @okurz!
-   Remove `verbosity`/`log_file` from generated config (PR #2755)
-   Add and improve metrics and logging (PR #2770, #2778, #2785, #2786, #2787, #2793, #2794, #2795, #2809, #2810, #2833, #2834, #2844, #2965, #2927, #2975, #2790, #2796, #2838)
-   When using synctl with workers, don\'t start the main synapse automatically (PR #2774)
-   Minor performance improvements (PR #2773, #2792)
-   Use a connection pool for non-federation outbound connections (PR #2817)
-   Make it possible to run unit tests against postgres (PR #2829)
-   Update pynacl dependency to 1.2.1 or higher (PR #2888) Thanks to @bachp!
-   Remove ability for AS users to call /events and /sync (PR #2948)
-   Use bcrypt.checkpw (PR #2949) Thanks to @krombel!

Bug fixes:

-   Fix broken `ldap_config` config option (PR #2683) Thanks to @seckrv!
-   Fix error message when user is not allowed to unban (PR #2761) Thanks to @turt2live!
-   Fix publicised groups GET API (singular) over federation (PR #2772)
-   Fix user directory when using `user_directory_search_all_users` config option (PR #2803, #2831)
-   Fix error on `/publicRooms` when no rooms exist (PR #2827)
-   Fix bug in quarantine\_media (PR #2837)
-   Fix url\_previews when no Content-Type is returned from URL (PR #2845)
-   Fix rare race in sync API when joining room (PR #2944)
-   Fix slow event search, switch back from GIST to GIN indexes (PR #2769, #2848)

Changes in synapse v0.26.0 (2018-01-05)
=======================================

No changes since v0.26.0-rc1

Changes in synapse v0.26.0-rc1 (2017-12-13)
===========================================

Features:

-   Add ability for ASes to publicise groups for their users (PR #2686)
-   Add all local users to the user\_directory and optionally search them (PR #2723)
-   Add support for custom login types for validating users (PR #2729)

Changes:

-   Update example Prometheus config to new format (PR #2648) Thanks to @krombel!
-   Rename redact\_content option to include\_content in Push API (PR #2650)
-   Declare support for r0.3.0 (PR #2677)
-   Improve upserts (PR #2684, #2688, #2689, #2713)
-   Improve documentation of workers (PR #2700)
-   Improve tracebacks on exceptions (PR #2705)
-   Allow guest access to group APIs for reading (PR #2715)
-   Support for posting content in federation\_client script (PR #2716)
-   Delete devices and pushers on logouts etc (PR #2722)

Bug fixes:

-   Fix database port script (PR #2673)
-   Fix internal server error on login with ldap\_auth\_provider (PR #2678) Thanks to @jkolo!
-   Fix error on sqlite 3.7 (PR #2697)
-   Fix OPTIONS on preview\_url (PR #2707)
-   Fix error handling on dns lookup (PR #2711)
-   Fix wrong avatars when inviting multiple users when creating room (PR #2717)
-   Fix 500 when joining matrix-dev (PR #2719)

Changes in synapse v0.25.1 (2017-11-17)
=======================================

Bug fixes:

-   Fix login with LDAP and other password provider modules (PR #2678). Thanks to @jkolo!

Changes in synapse v0.25.0 (2017-11-15)
=======================================

Bug fixes:

-   Fix port script (PR #2673)

Changes in synapse v0.25.0-rc1 (2017-11-14)
===========================================

Features:

-   Add is\_public to groups table to allow for private groups (PR #2582)
-   Add a route for determining who you are (PR #2668) Thanks to @turt2live!
-   Add more features to the password providers (PR #2608, #2610, #2620, #2622, #2623, #2624, #2626, #2628, #2629)
-   Add a hook for custom rest endpoints (PR #2627)
-   Add API to update group room visibility (PR #2651)

Changes:

-   Ignore \<noscript\> tags when generating URL preview descriptions (PR #2576) Thanks to @maximevaillancourt!
-   Register some /unstable endpoints in /r0 as well (PR #2579) Thanks to @krombel!
-   Support /keys/upload on /r0 as well as /unstable (PR #2585)
-   Front-end proxy: pass through auth header (PR #2586)
-   Allow ASes to deactivate their own users (PR #2589)
-   Remove refresh tokens (PR #2613)
-   Automatically set default displayname on register (PR #2617)
-   Log login requests (PR #2618)
-   Always return is\_public in the /groups/:group\_id/rooms API (PR #2630)
-   Avoid no-op media deletes (PR #2637) Thanks to @spantaleev!
-   Fix various embarrassing typos around user\_directory and add some doc. (PR #2643)
-   Return whether a user is an admin within a group (PR #2647)
-   Namespace visibility options for groups (PR #2657)
-   Downcase UserIDs on registration (PR #2662)
-   Cache failures when fetching URL previews (PR #2669)

Bug fixes:

-   Fix port script (PR #2577)
-   Fix error when running synapse with no logfile (PR #2581)
-   Fix UI auth when deleting devices (PR #2591)
-   Fix typo when checking if user is invited to group (PR #2599)
-   Fix the port script to drop NUL values in all tables (PR #2611)
-   Fix appservices being backlogged and not receiving new events due to a bug in notify\_interested\_services (PR #2631) Thanks to @xyzz!
-   Fix updating rooms avatar/display name when modified by admin (PR #2636) Thanks to @farialima!
-   Fix bug in state group storage (PR #2649)
-   Fix 500 on invalid utf-8 in request (PR #2663)

Changes in synapse v0.24.1 (2017-10-24)
=======================================

Bug fixes:

-   Fix updating group profiles over federation (PR #2567)

Changes in synapse v0.24.0 (2017-10-23)
=======================================

No changes since v0.24.0-rc1

Changes in synapse v0.24.0-rc1 (2017-10-19)
===========================================

Features:

-   Add Group Server (PR #2352, #2363, #2374, #2377, #2378, #2382, #2410, #2426, #2430, #2454, #2471, #2472, #2544)
-   Add support for channel notifications (PR #2501)
-   Add basic implementation of backup media store (PR #2538)
-   Add config option to auto-join new users to rooms (PR #2545)

Changes:

-   Make the spam checker a module (PR #2474)
-   Delete expired url cache data (PR #2478)
-   Ignore incoming events for rooms that we have left (PR #2490)
-   Allow spam checker to reject invites too (PR #2492)
-   Add room creation checks to spam checker (PR #2495)
-   Spam checking: add the invitee to user\_may\_invite (PR #2502)
-   Process events from federation for different rooms in parallel (PR #2520)
-   Allow error strings from spam checker (PR #2531)
-   Improve error handling for missing files in config (PR #2551)

Bug fixes:

-   Fix handling SERVFAILs when doing AAAA lookups for federation (PR #2477)
-   Fix incompatibility with newer versions of ujson (PR #2483) Thanks to @jeremycline!
-   Fix notification keywords that start/end with non-word chars (PR #2500)
-   Fix stack overflow and logcontexts from linearizer (PR #2532)
-   Fix 500 error when fields missing from power\_levels event (PR #2552)
-   Fix 500 error when we get an error handling a PDU (PR #2553)

Changes in synapse v0.23.1 (2017-10-02)
=======================================

Changes:

-   Make \'affinity\' package optional, as it is not supported on some platforms

Changes in synapse v0.23.0 (2017-10-02)
=======================================

No changes since v0.23.0-rc2

Changes in synapse v0.23.0-rc2 (2017-09-26)
===========================================

Bug fixes:

-   Fix regression in performance of syncs (PR #2470)

Changes in synapse v0.23.0-rc1 (2017-09-25)
===========================================

Features:

-   Add a frontend proxy worker (PR #2344)
-   Add support for event\_id\_only push format (PR #2450)
-   Add a PoC for filtering spammy events (PR #2456)
-   Add a config option to block all room invites (PR #2457)

Changes:

-   Use bcrypt module instead of py-bcrypt (PR #2288) Thanks to @kyrias!
-   Improve performance of generating push notifications (PR #2343, #2357, #2365, #2366, #2371)
-   Improve DB performance for device list handling in sync (PR #2362)
-   Include a sample prometheus config (PR #2416)
-   Document known to work postgres version (PR #2433) Thanks to @ptman!

Bug fixes:

-   Fix caching error in the push evaluator (PR #2332)
-   Fix bug where pusherpool didn\'t start and broke some rooms (PR #2342)
-   Fix port script for user directory tables (PR #2375)
-   Fix device lists notifications when user rejoins a room (PR #2443, #2449)
-   Fix sync to always send down current state events in timeline (PR #2451)
-   Fix bug where guest users were incorrectly kicked (PR #2453)
-   Fix bug talking to IPv6 only servers using SRV records (PR #2462)

Changes in synapse v0.22.1 (2017-07-06)
=======================================

Bug fixes:

-   Fix bug where pusher pool didn\'t start and caused issues when interacting with some rooms (PR #2342)

Changes in synapse v0.22.0 (2017-07-06)
=======================================

No changes since v0.22.0-rc2

Changes in synapse v0.22.0-rc2 (2017-07-04)
===========================================

Changes:

-   Improve performance of storing user IPs (PR #2307, #2308)
-   Slightly improve performance of verifying access tokens (PR #2320)
-   Slightly improve performance of event persistence (PR #2321)
-   Increase default cache factor size from 0.1 to 0.5 (PR #2330)

Bug fixes:

-   Fix bug with storing registration sessions that caused frequent CPU churn (PR #2319)

Changes in synapse v0.22.0-rc1 (2017-06-26)
===========================================

Features:

-   Add a user directory API (PR #2252, and many more)
-   Add shutdown room API to remove room from local server (PR #2291)
-   Add API to quarantine media (PR #2292)
-   Add new config option to not send event contents to push servers (PR #2301) Thanks to @cjdelisle!

Changes:

-   Various performance fixes (PR #2177, #2233, #2230, #2238, #2248, #2256, #2274)
-   Deduplicate sync filters (PR #2219) Thanks to @krombel!
-   Correct a typo in UPGRADE.rst (PR #2231) Thanks to @aaronraimist!
-   Add count of one time keys to sync stream (PR #2237)
-   Only store event\_auth for state events (PR #2247)
-   Store URL cache preview downloads separately (PR #2299)

Bug fixes:

-   Fix users not getting notifications when AS listened to that user\_id (PR #2216) Thanks to @slipeer!
-   Fix users without push set up not getting notifications after joining rooms (PR #2236)
-   Fix preview url API to trim long descriptions (PR #2243)
-   Fix bug where we used cached but unpersisted state group as prev group, resulting in broken state of restart (PR #2263)
-   Fix removing of pushers when using workers (PR #2267)
-   Fix CORS headers to allow Authorization header (PR #2285) Thanks to @krombel!

Changes in synapse v0.21.1 (2017-06-15)
=======================================

Bug fixes:

-   Fix bug in anonymous usage statistic reporting (PR #2281)

Changes in synapse v0.21.0 (2017-05-18)
=======================================

No changes since v0.21.0-rc3

Changes in synapse v0.21.0-rc3 (2017-05-17)
===========================================

Features:

-   Add per user rate-limiting overrides (PR #2208)
-   Add config option to limit maximum number of events requested by `/sync` and `/messages` (PR #2221) Thanks to @psaavedra!

Changes:

-   Various small performance fixes (PR #2201, #2202, #2224, #2226, #2227, #2228, #2229)
-   Update username availability checker API (PR #2209, #2213)
-   When purging, don\'t de-delta state groups we\'re about to delete (PR #2214)
-   Documentation to check synapse version (PR #2215) Thanks to @hamber-dick!
-   Add an index to event\_search to speed up purge history API (PR #2218)

Bug fixes:

-   Fix API to allow clients to upload one-time-keys with new sigs (PR #2206)

Changes in synapse v0.21.0-rc2 (2017-05-08)
===========================================

Changes:

-   Always mark remotes as up if we receive a signed request from them (PR #2190)

Bug fixes:

-   Fix bug where users got pushed for rooms they had muted (PR #2200)

Changes in synapse v0.21.0-rc1 (2017-05-08)
===========================================

Features:

-   Add username availability checker API (PR #2183)
-   Add read marker API (PR #2120)

Changes:

-   Enable guest access for the 3pl/3pid APIs (PR #1986)
-   Add setting to support TURN for guests (PR #2011)
-   Various performance improvements (PR #2075, #2076, #2080, #2083, #2108, #2158, #2176, #2185)
-   Make synctl a bit more user friendly (PR #2078, #2127) Thanks @APwhitehat!
-   Replace HTTP replication with TCP replication (PR #2082, #2097, #2098, #2099, #2103, #2014, #2016, #2115, #2116, #2117)
-   Support authenticated SMTP (PR #2102) Thanks @DanielDent!
-   Add a counter metric for successfully-sent transactions (PR #2121)
-   Propagate errors sensibly from proxied IS requests (PR #2147)
-   Add more granular event send metrics (PR #2178)

Bug fixes:

-   Fix nuke-room script to work with current schema (PR #1927) Thanks @zuckschwerdt!
-   Fix db port script to not assume postgres tables are in the public schema (PR #2024) Thanks @jerrykan!
-   Fix getting latest device IP for user with no devices (PR #2118)
-   Fix rejection of invites to unreachable servers (PR #2145)
-   Fix code for reporting old verify keys in synapse (PR #2156)
-   Fix invite state to always include all events (PR #2163)
-   Fix bug where synapse would always fetch state for any missing event (PR #2170)
-   Fix a leak with timed out HTTP connections (PR #2180)
-   Fix bug where we didn\'t time out HTTP requests to ASes (PR #2192)

Docs:

-   Clarify doc for SQLite to PostgreSQL port (PR #1961) Thanks @benhylau!
-   Fix typo in synctl help (PR #2107) Thanks @HarHarLinks!
-   `web_client_location` documentation fix (PR #2131) Thanks @matthewjwolff!
-   Update README.rst with FreeBSD changes (PR #2132) Thanks @feld!
-   Clarify setting up metrics (PR #2149) Thanks @encks!

Changes in synapse v0.20.0 (2017-04-11)
=======================================

Bug fixes:

-   Fix joining rooms over federation where not all servers in the room saw the new server had joined (PR #2094)

Changes in synapse v0.20.0-rc1 (2017-03-30)
===========================================

Features:

-   Add delete\_devices API (PR #1993)
-   Add phone number registration/login support (PR #1994, #2055)

Changes:

-   Use JSONSchema for validation of filters. Thanks @pik! (PR #1783)
-   Reread log config on SIGHUP (PR #1982)
-   Speed up public room list (PR #1989)
-   Add helpful texts to logger config options (PR #1990)
-   Minor `/sync` performance improvements. (PR #2002, #2013, #2022)
-   Add some debug to help diagnose weird federation issue (PR #2035)
-   Correctly limit retries for all federation requests (PR #2050, #2061)
-   Don\'t lock table when persisting new one time keys (PR #2053)
-   Reduce some CPU work on DB threads (PR #2054)
-   Cache hosts in room (PR #2060)
-   Batch sending of device list pokes (PR #2063)
-   Speed up persist event path in certain edge cases (PR #2070)

Bug fixes:

-   Fix bug where current\_state\_events renamed to current\_state\_ids (PR #1849)
-   Fix routing loop when fetching remote media (PR #1992)
-   Fix current\_state\_events table to not lie (PR #1996)
-   Fix CAS login to handle PartialDownloadError (PR #1997)
-   Fix assertion to stop transaction queue getting wedged (PR #2010)
-   Fix presence to fallback to last\_active\_ts if it beats the last sync time. Thanks @Half-Shot! (PR #2014)
-   Fix bug when federation received a PDU while a room join is in progress (PR #2016)
-   Fix resetting state on rejected events (PR #2025)
-   Fix installation issues in readme. Thanks @ricco386 (PR #2037)
-   Fix caching of remote servers\' signature keys (PR #2042)
-   Fix some leaking log context (PR #2048, #2049, #2057, #2058)
-   Fix rejection of invites not reaching sync (PR #2056)

Changes in synapse v0.19.3 (2017-03-20)
=======================================

No changes since v0.19.3-rc2

Changes in synapse v0.19.3-rc2 (2017-03-13)
===========================================

Bug fixes:

-   Fix bug in handling of incoming device list updates over federation.

Changes in synapse v0.19.3-rc1 (2017-03-08)
===========================================

Features:

-   Add some administration functionalities. Thanks to morteza-araby! (PR #1784)

Changes:

-   Reduce database table sizes (PR #1873, #1916, #1923, #1963)
-   Update contrib/ to not use syutil. Thanks to andrewshadura! (PR #1907)
-   Don\'t fetch current state when sending an event in common case (PR #1955)

Bug fixes:

-   Fix synapse\_port\_db failure. Thanks to Pneumaticat! (PR #1904)
-   Fix caching to not cache error responses (PR #1913)
-   Fix APIs to make kick & ban reasons work (PR #1917)
-   Fix bugs in the /keys/changes api (PR #1921)
-   Fix bug where users couldn\'t forget rooms they were banned from (PR #1922)
-   Fix issue with long language values in pushers API (PR #1925)
-   Fix a race in transaction queue (PR #1930)
-   Fix dynamic thumbnailing to preserve aspect ratio. Thanks to jkolo! (PR #1945)
-   Fix device list update to not constantly resync (PR #1964)
-   Fix potential for huge memory usage when getting device that have changed (PR #1969)

Changes in synapse v0.19.2 (2017-02-20)
=======================================

-   Fix bug with event visibility check in /context/ API. Thanks to Tokodomo for pointing it out! (PR #1929)

Changes in synapse v0.19.1 (2017-02-09)
=======================================

-   Fix bug where state was incorrectly reset in a room when synapse received an event over federation that did not pass auth checks (PR #1892)

Changes in synapse v0.19.0 (2017-02-04)
=======================================

No changes since RC 4.

Changes in synapse v0.19.0-rc4 (2017-02-02)
===========================================

-   Bump cache sizes for common membership queries (PR #1879)

Changes in synapse v0.19.0-rc3 (2017-02-02)
===========================================

-   Fix email push in pusher worker (PR #1875)
-   Make presence.get\_new\_events a bit faster (PR #1876)
-   Make /keys/changes a bit more performant (PR #1877)

Changes in synapse v0.19.0-rc2 (2017-02-02)
===========================================

-   Include newly joined users in /keys/changes API (PR #1872)

Changes in synapse v0.19.0-rc1 (2017-02-02)
===========================================

Features:

-   Add support for specifying multiple bind addresses (PR #1709, #1712, #1795, #1835). Thanks to @kyrias!
-   Add /account/3pid/delete endpoint (PR #1714)
-   Add config option to configure the Riot URL used in notification emails (PR #1811). Thanks to @aperezdc!
-   Add username and password config options for turn server (PR #1832). Thanks to @xsteadfastx!
-   Implement device lists updates over federation (PR #1857, #1861, #1864)
-   Implement /keys/changes (PR #1869, #1872)

Changes:

-   Improve IPv6 support (PR #1696). Thanks to @kyrias and @glyph!
-   Log which files we saved attachments to in the media\_repository (PR #1791)
-   Linearize updates to membership via PUT /state/ to better handle multiple joins (PR #1787)
-   Limit number of entries to prefill from cache on startup (PR #1792)
-   Remove full\_twisted\_stacktraces option (PR #1802)
-   Measure size of some caches by sum of the size of cached values (PR #1815)
-   Measure metrics of string\_cache (PR #1821)
-   Reduce logging verbosity (PR #1822, #1823, #1824)
-   Don\'t clobber a displayname or avatar\_url if provided by an m.room.member event (PR #1852)
-   Better handle 401/404 response for federation /send/ (PR #1866, #1871)

Fixes:

-   Fix ability to change password to a non-ascii one (PR #1711)
-   Fix push getting stuck due to looking at the wrong view of state (PR #1820)
-   Fix email address comparison to be case insensitive (PR #1827)
-   Fix occasional inconsistencies of room membership (PR #1836, #1840)

Performance:

-   Don\'t block messages sending on bumping presence (PR #1789)
-   Change device\_inbox stream index to include user (PR #1793)
-   Optimise state resolution (PR #1818)
-   Use DB cache of joined users for presence (PR #1862)
-   Add an index to make membership queries faster (PR #1867)

Changes in synapse v0.18.7 (2017-01-09)
=======================================

No changes from v0.18.7-rc2

Changes in synapse v0.18.7-rc2 (2017-01-07)
===========================================

Bug fixes:

-   Fix error in rc1\'s discarding invalid inbound traffic logic that was incorrectly discarding missing events

Changes in synapse v0.18.7-rc1 (2017-01-06)
===========================================

Bug fixes:

-   Fix error in \#PR 1764 to actually fix the nightmare \#1753 bug.
-   Improve deadlock logging further
-   Discard inbound federation traffic from invalid domains, to immunise against \#1753

Changes in synapse v0.18.6 (2017-01-06)
=======================================

Bug fixes:

-   Fix bug when checking if a guest user is allowed to join a room (PR #1772) Thanks to Patrik Oldsberg for diagnosing and the fix!

Changes in synapse v0.18.6-rc3 (2017-01-05)
===========================================

Bug fixes:

-   Fix bug where we failed to send ban events to the banned server (PR #1758)
-   Fix bug where we sent event that didn\'t originate on this server to other servers (PR #1764)
-   Fix bug where processing an event from a remote server took a long time because we were making long HTTP requests (PR #1765, PR #1744)

Changes:

-   Improve logging for debugging deadlocks (PR #1766, PR #1767)

Changes in synapse v0.18.6-rc2 (2016-12-30)
===========================================

Bug fixes:

-   Fix memory leak in twisted by initialising logging correctly (PR #1731)
-   Fix bug where fetching missing events took an unacceptable amount of time in large rooms (PR #1734)

Changes in synapse v0.18.6-rc1 (2016-12-29)
===========================================

Bug fixes:

-   Make sure that outbound connections are closed (PR #1725)

Changes in synapse v0.18.5 (2016-12-16)
=======================================

Bug fixes:

-   Fix federation /backfill returning events it shouldn\'t (PR #1700)
-   Fix crash in url preview (PR #1701)

Changes in synapse v0.18.5-rc3 (2016-12-13)
===========================================

Features:

-   Add support for E2E for guests (PR #1653)
-   Add new API appservice specific public room list (PR #1676)
-   Add new room membership APIs (PR #1680)

Changes:

-   Enable guest access for private rooms by default (PR #653)
-   Limit the number of events that can be created on a given room concurrently (PR #1620)
-   Log the args that we have on UI auth completion (PR #1649)
-   Stop generating refresh\_tokens (PR #1654)
-   Stop putting a time caveat on access tokens (PR #1656)
-   Remove unspecced GET endpoints for e2e keys (PR #1694)

Bug fixes:

-   Fix handling of 500 and 429\'s over federation (PR #1650)
-   Fix Content-Type header parsing (PR #1660)
-   Fix error when previewing sites that include unicode, thanks to kyrias (PR #1664)
-   Fix some cases where we drop read receipts (PR #1678)
-   Fix bug where calls to `/sync` didn\'t correctly timeout (PR #1683)
-   Fix bug where E2E key query would fail if a single remote host failed (PR #1686)

Changes in synapse v0.18.5-rc2 (2016-11-24)
===========================================

Bug fixes:

-   Don\'t send old events over federation, fixes bug in -rc1.

Changes in synapse v0.18.5-rc1 (2016-11-24)
===========================================

Features:

-   Implement \"event\_fields\" in filters (PR #1638)

Changes:

-   Use external ldap auth pacakge (PR #1628)
-   Split out federation transaction sending to a worker (PR #1635)
-   Fail with a coherent error message if /sync?filter= is invalid (PR #1636)
-   More efficient notif count queries (PR #1644)

Changes in synapse v0.18.4 (2016-11-22)
=======================================

Bug fixes:

-   Add workaround for buggy clients that the fail to register (PR #1632)

Changes in synapse v0.18.4-rc1 (2016-11-14)
===========================================

Changes:

-   Various database efficiency improvements (PR #1188, #1192)
-   Update default config to blacklist more internal IPs, thanks to Euan Kemp (PR #1198)
-   Allow specifying duration in minutes in config, thanks to Daniel Dent (PR #1625)

Bug fixes:

-   Fix media repo to set CORs headers on responses (PR #1190)
-   Fix registration to not error on non-ascii passwords (PR #1191)
-   Fix create event code to limit the number of prev\_events (PR #1615)
-   Fix bug in transaction ID deduplication (PR #1624)

Changes in synapse v0.18.3 (2016-11-08)
=======================================

SECURITY UPDATE

Explicitly require authentication when using LDAP3. This is the default on versions of `ldap3` above 1.0, but some distributions will package an older version.

If you are using LDAP3 login and have a version of `ldap3` older than 1.0 it is **CRITICAL to updgrade**.

Changes in synapse v0.18.2 (2016-11-01)
=======================================

No changes since v0.18.2-rc5

Changes in synapse v0.18.2-rc5 (2016-10-28)
===========================================

Bug fixes:

-   Fix prometheus process metrics in worker processes (PR #1184)

Changes in synapse v0.18.2-rc4 (2016-10-27)
===========================================

Bug fixes:

-   Fix `user_threepids` schema delta, which in some instances prevented startup after upgrade (PR #1183)

Changes in synapse v0.18.2-rc3 (2016-10-27)
===========================================

Changes:

-   Allow clients to supply access tokens as headers (PR #1098)
-   Clarify error codes for GET /filter/, thanks to Alexander Maznev (PR #1164)
-   Make password reset email field case insensitive (PR #1170)
-   Reduce redundant database work in email pusher (PR #1174)
-   Allow configurable rate limiting per AS (PR #1175)
-   Check whether to ratelimit sooner to avoid work (PR #1176)
-   Standardise prometheus metrics (PR #1177)

Bug fixes:

-   Fix incredibly slow back pagination query (PR #1178)
-   Fix infinite typing bug (PR #1179)

Changes in synapse v0.18.2-rc2 (2016-10-25)
===========================================

(This release did not include the changes advertised and was identical to RC1)

Changes in synapse v0.18.2-rc1 (2016-10-17)
===========================================

Changes:

-   Remove redundant event\_auth index (PR #1113)
-   Reduce DB hits for replication (PR #1141)
-   Implement pluggable password auth (PR #1155)
-   Remove rate limiting from app service senders and fix get\_or\_create\_user requester, thanks to Patrik Oldsberg (PR #1157)
-   window.postmessage for Interactive Auth fallback (PR #1159)
-   Use sys.executable instead of hardcoded python, thanks to Pedro Larroy (PR #1162)
-   Add config option for adding additional TLS fingerprints (PR #1167)
-   User-interactive auth on delete device (PR #1168)

Bug fixes:

-   Fix not being allowed to set your own state\_key, thanks to Patrik Oldsberg (PR #1150)
-   Fix interactive auth to return 401 from for incorrect password (PR #1160, #1166)
-   Fix email push notifs being dropped (PR #1169)

Changes in synapse v0.18.1 (2016-10-05)
=======================================

No changes since v0.18.1-rc1

Changes in synapse v0.18.1-rc1 (2016-09-30)
===========================================

Features:

-   Add total\_room\_count\_estimate to `/publicRooms` (PR #1133)

Changes:

-   Time out typing over federation (PR #1140)
-   Restructure LDAP authentication (PR #1153)

Bug fixes:

-   Fix 3pid invites when server is already in the room (PR #1136)
-   Fix upgrading with SQLite taking lots of CPU for a few days after upgrade (PR #1144)
-   Fix upgrading from very old database versions (PR #1145)
-   Fix port script to work with recently added tables (PR #1146)

Changes in synapse v0.18.0 (2016-09-19)
=======================================

The release includes major changes to the state storage database schemas, which significantly reduce database size. Synapse will attempt to upgrade the current data in the background. Servers with large SQLite database may experience degradation of performance while this upgrade is in progress, therefore you may want to consider migrating to using Postgres before upgrading very large SQLite databases

Changes:

-   Make public room search case insensitive (PR #1127)

Bug fixes:

-   Fix and clean up publicRooms pagination (PR #1129)

Changes in synapse v0.18.0-rc1 (2016-09-16)
===========================================

Features:

-   Add `only=highlight` on `/notifications` (PR #1081)
-   Add server param to /publicRooms (PR #1082)
-   Allow clients to ask for the whole of a single state event (PR #1094)
-   Add is\_direct param to /createRoom (PR #1108)
-   Add pagination support to publicRooms (PR #1121)
-   Add very basic filter API to /publicRooms (PR #1126)
-   Add basic direct to device messaging support for E2E (PR #1074, #1084, #1104, #1111)

Changes:

-   Move to storing state\_groups\_state as deltas, greatly reducing DB size (PR #1065)
-   Reduce amount of state pulled out of the DB during common requests (PR #1069)
-   Allow PDF to be rendered from media repo (PR #1071)
-   Reindex state\_groups\_state after pruning (PR #1085)
-   Clobber EDUs in send queue (PR #1095)
-   Conform better to the CAS protocol specification (PR #1100)
-   Limit how often we ask for keys from dead servers (PR #1114)

Bug fixes:

-   Fix /notifications API when used with `from` param (PR #1080)
-   Fix backfill when cannot find an event. (PR #1107)

Changes in synapse v0.17.3 (2016-09-09)
=======================================

This release fixes a major bug that stopped servers from handling rooms with over 1000 members.

Changes in synapse v0.17.2 (2016-09-08)
=======================================

This release contains security bug fixes. Please upgrade.

No changes since v0.17.2-rc1

Changes in synapse v0.17.2-rc1 (2016-09-05)
===========================================

Features:

-   Start adding store-and-forward direct-to-device messaging (PR #1046, #1050, #1062, #1066)

Changes:

-   Avoid pulling the full state of a room out so often (PR #1047, #1049, #1063, #1068)
-   Don\'t notify for online to online presence transitions. (PR #1054)
-   Occasionally persist unpersisted presence updates (PR #1055)
-   Allow application services to have an optional \'url\' (PR #1056)
-   Clean up old sent transactions from DB (PR #1059)

Bug fixes:

-   Fix None check in backfill (PR #1043)
-   Fix membership changes to be idempotent (PR #1067)
-   Fix bug in get\_pdu where it would sometimes return events with incorrect signature

Changes in synapse v0.17.1 (2016-08-24)
=======================================

Changes:

-   Delete old received\_transactions rows (PR #1038)
-   Pass through user-supplied content in /join/\$room\_id (PR #1039)

Bug fixes:

-   Fix bug with backfill (PR #1040)

Changes in synapse v0.17.1-rc1 (2016-08-22)
===========================================

Features:

-   Add notification API (PR #1028)

Changes:

-   Don\'t print stack traces when failing to get remote keys (PR #996)
-   Various federation /event/ perf improvements (PR #998)
-   Only process one local membership event per room at a time (PR #1005)
-   Move default display name push rule (PR #1011, #1023)
-   Fix up preview URL API. Add tests. (PR #1015)
-   Set `Content-Security-Policy` on media repo (PR #1021)
-   Make notify\_interested\_services faster (PR #1022)
-   Add usage stats to prometheus monitoring (PR #1037)

Bug fixes:

-   Fix token login (PR #993)
-   Fix CAS login (PR #994, #995)
-   Fix /sync to not clobber status\_msg (PR #997)
-   Fix redacted state events to include prev\_content (PR #1003)
-   Fix some bugs in the auth/ldap handler (PR #1007)
-   Fix backfill request to limit URI length, so that remotes don\'t reject the requests due to path length limits (PR #1012)
-   Fix AS push code to not send duplicate events (PR #1025)

Changes in synapse v0.17.0 (2016-08-08)
=======================================

This release contains significant security bug fixes regarding authenticating events received over federation. PLEASE UPGRADE.

This release changes the LDAP configuration format in a backwards incompatible way, see PR #843 for details.

Changes:

-   Add federation /version API (PR #990)
-   Make psutil dependency optional (PR #992)

Bug fixes:

-   Fix URL preview API to exclude HTML comments in description (PR #988)
-   Fix error handling of remote joins (PR #991)

Changes in synapse v0.17.0-rc4 (2016-08-05)
===========================================

Changes:

-   Change the way we summarize URLs when previewing (PR #973)
-   Add new `/state_ids/` federation API (PR #979)
-   Speed up processing of `/state/` response (PR #986)

Bug fixes:

-   Fix event persistence when event has already been partially persisted (PR #975, #983, #985)
-   Fix port script to also copy across backfilled events (PR #982)

Changes in synapse v0.17.0-rc3 (2016-08-02)
===========================================

Changes:

-   Forbid non-ASes from registering users whose names begin with \'\_\' (PR #958)
-   Add some basic admin API docs (PR #963)

Bug fixes:

-   Send the correct host header when fetching keys (PR #941)
-   Fix joining a room that has missing auth events (PR #964)
-   Fix various push bugs (PR #966, #970)
-   Fix adding emails on registration (PR #968)

Changes in synapse v0.17.0-rc2 (2016-08-02)
===========================================

(This release did not include the changes advertised and was identical to RC1)

Changes in synapse v0.17.0-rc1 (2016-07-28)
===========================================

This release changes the LDAP configuration format in a backwards incompatible way, see PR #843 for details.

Features:

-   Add purge\_media\_cache admin API (PR #902)
-   Add deactivate account admin API (PR #903)
-   Add optional pepper to password hashing (PR #907, #910 by KentShikama)
-   Add an admin option to shared secret registration (breaks backwards compat) (PR #909)
-   Add purge local room history API (PR #911, #923, #924)
-   Add requestToken endpoints (PR #915)
-   Add an /account/deactivate endpoint (PR #921)
-   Add filter param to /messages. Add \'contains\_url\' to filter. (PR #922)
-   Add device\_id support to /login (PR #929)
-   Add device\_id support to /v2/register flow. (PR #937, #942)
-   Add GET /devices endpoint (PR #939, #944)
-   Add GET /device/{deviceId} (PR #943)
-   Add update and delete APIs for devices (PR #949)

Changes:

-   Rewrite LDAP Authentication against ldap3 (PR #843 by mweinelt)
-   Linearize some federation endpoints based on (origin, room\_id) (PR #879)
-   Remove the legacy v0 content upload API. (PR #888)
-   Use similar naming we use in email notifs for push (PR #894)
-   Optionally include password hash in createUser endpoint (PR #905 by KentShikama)
-   Use a query that postgresql optimises better for get\_events\_around (PR #906)
-   Fall back to \'username\' if \'user\' is not given for appservice registration. (PR #927 by Half-Shot)
-   Add metrics for psutil derived memory usage (PR #936)
-   Record device\_id in client\_ips (PR #938)
-   Send the correct host header when fetching keys (PR #941)
-   Log the hostname the reCAPTCHA was completed on (PR #946)
-   Make the device id on e2e key upload optional (PR #956)
-   Add r0.2.0 to the \"supported versions\" list (PR #960)
-   Don\'t include name of room for invites in push (PR #961)

Bug fixes:

-   Fix substitution failure in mail template (PR #887)
-   Put most recent 20 messages in email notif (PR #892)
-   Ensure that the guest user is in the database when upgrading accounts (PR #914)
-   Fix various edge cases in auth handling (PR #919)
-   Fix 500 ISE when sending alias event without a state\_key (PR #925)
-   Fix bug where we stored rejections in the state\_group, persist all rejections (PR #948)
-   Fix lack of check of if the user is banned when handling 3pid invites (PR #952)
-   Fix a couple of bugs in the transaction and keyring code (PR #954, #955)

Changes in synapse v0.16.1-r1 (2016-07-08)
==========================================

THIS IS A CRITICAL SECURITY UPDATE.

This fixes a bug which allowed users\' accounts to be accessed by unauthorised users.

Changes in synapse v0.16.1 (2016-06-20)
=======================================

Bug fixes:

-   Fix assorted bugs in `/preview_url` (PR #872)
-   Fix TypeError when setting unicode passwords (PR #873)

Performance improvements:

-   Turn `use_frozen_events` off by default (PR #877)
-   Disable responding with canonical json for federation (PR #878)

Changes in synapse v0.16.1-rc1 (2016-06-15)
===========================================

Features: None

Changes:

-   Log requester for `/publicRoom` endpoints when possible (PR #856)
-   502 on `/thumbnail` when can\'t connect to remote server (PR #862)
-   Linearize fetching of gaps on incoming events (PR #871)

Bugs fixes:

-   Fix bug where rooms where marked as published by default (PR #857)
-   Fix bug where joining room with an event with invalid sender (PR #868)
-   Fix bug where backfilled events were sent down sync streams (PR #869)
-   Fix bug where outgoing connections could wedge indefinitely, causing push notifications to be unreliable (PR #870)

Performance improvements:

-   Improve `/publicRooms` performance(PR #859)

Changes in synapse v0.16.0 (2016-06-09)
=======================================

NB: As of v0.14 all AS config files must have an ID field.

Bug fixes:

-   Don\'t make rooms published by default (PR #857)

Changes in synapse v0.16.0-rc2 (2016-06-08)
===========================================

Features:

-   Add configuration option for tuning GC via `gc.set_threshold` (PR #849)

Changes:

-   Record metrics about GC (PR #771, #847, #852)
-   Add metric counter for number of persisted events (PR #841)

Bug fixes:

-   Fix \'From\' header in email notifications (PR #843)
-   Fix presence where timeouts were not being fired for the first 8h after restarts (PR #842)
-   Fix bug where synapse sent malformed transactions to AS\'s when retrying transactions (Commits 310197b, 8437906)

Performance improvements:

-   Remove event fetching from DB threads (PR #835)
-   Change the way we cache events (PR #836)
-   Add events to cache when we persist them (PR #840)

Changes in synapse v0.16.0-rc1 (2016-06-03)
===========================================

Version 0.15 was not released. See v0.15.0-rc1 below for additional changes.

Features:

-   Add email notifications for missed messages (PR #759, #786, #799, #810, #815, #821)
-   Add a `url_preview_ip_range_whitelist` config param (PR #760)
-   Add /report endpoint (PR #762)
-   Add basic ignore user API (PR #763)
-   Add an openidish mechanism for proving that you own a given user\_id (PR #765)
-   Allow clients to specify a server\_name to avoid \'No known servers\' (PR #794)
-   Add secondary\_directory\_servers option to fetch room list from other servers (PR #808, #813)

Changes:

-   Report per request metrics for all of the things using request\_handler (PR #756)
-   Correctly handle `NULL` password hashes from the database (PR #775)
-   Allow receipts for events we haven\'t seen in the db (PR #784)
-   Make synctl read a cache factor from config file (PR #785)
-   Increment badge count per missed convo, not per msg (PR #793)
-   Special case m.room.third\_party\_invite event auth to match invites (PR #814)

Bug fixes:

-   Fix typo in event\_auth servlet path (PR #757)
-   Fix password reset (PR #758)

Performance improvements:

-   Reduce database inserts when sending transactions (PR #767)
-   Queue events by room for persistence (PR #768)
-   Add cache to `get_user_by_id` (PR #772)
-   Add and use `get_domain_from_id` (PR #773)
-   Use tree cache for `get_linearized_receipts_for_room` (PR #779)
-   Remove unused indices (PR #782)
-   Add caches to `bulk_get_push_rules*` (PR #804)
-   Cache `get_event_reference_hashes` (PR #806)
-   Add `get_users_with_read_receipts_in_room` cache (PR #809)
-   Use state to calculate `get_users_in_room` (PR #811)
-   Load push rules in storage layer so that they get cached (PR #825)
-   Make `get_joined_hosts_for_room` use get\_users\_in\_room (PR #828)
-   Poke notifier on next reactor tick (PR #829)
-   Change CacheMetrics to be quicker (PR #830)

Changes in synapse v0.15.0-rc1 (2016-04-26)
===========================================

Features:

-   Add login support for Javascript Web Tokens, thanks to Niklas Riekenbrauck (PR #671,\#687)
-   Add URL previewing support (PR #688)
-   Add login support for LDAP, thanks to Christoph Witzany (PR #701)
-   Add GET endpoint for pushers (PR #716)

Changes:

-   Never notify for member events (PR #667)
-   Deduplicate identical `/sync` requests (PR #668)
-   Require user to have left room to forget room (PR #673)
-   Use DNS cache if within TTL (PR #677)
-   Let users see their own leave events (PR #699)
-   Deduplicate membership changes (PR #700)
-   Increase performance of pusher code (PR #705)
-   Respond with error status 504 if failed to talk to remote server (PR #731)
-   Increase search performance on postgres (PR #745)

Bug fixes:

-   Fix bug where disabling all notifications still resulted in push (PR #678)
-   Fix bug where users couldn\'t reject remote invites if remote refused (PR #691)
-   Fix bug where synapse attempted to backfill from itself (PR #693)
-   Fix bug where profile information was not correctly added when joining remote rooms (PR #703)
-   Fix bug where register API required incorrect key name for AS registration (PR #727)

Changes in synapse v0.14.0 (2016-03-30)
=======================================

No changes from v0.14.0-rc2

Changes in synapse v0.14.0-rc2 (2016-03-23)
===========================================

Features:

-   Add published room list API (PR #657)

Changes:

-   Change various caches to consume less memory (PR #656, #658, #660, #662, #663, #665)
-   Allow rooms to be published without requiring an alias (PR #664)
-   Intern common strings in caches to reduce memory footprint (\#666)

Bug fixes:

-   Fix reject invites over federation (PR #646)
-   Fix bug where registration was not idempotent (PR #649)
-   Update aliases event after deleting aliases (PR #652)
-   Fix unread notification count, which was sometimes wrong (PR #661)

Changes in synapse v0.14.0-rc1 (2016-03-14)
===========================================

Features:

-   Add event\_id to response to state event PUT (PR #581)
-   Allow guest users access to messages in rooms they have joined (PR #587)
-   Add config for what state is included in a room invite (PR #598)
-   Send the inviter\'s member event in room invite state (PR #607)
-   Add error codes for malformed/bad JSON in /login (PR #608)
-   Add support for changing the actions for default rules (PR #609)
-   Add environment variable SYNAPSE\_CACHE\_FACTOR, default it to 0.1 (PR #612)
-   Add ability for alias creators to delete aliases (PR #614)
-   Add profile information to invites (PR #624)

Changes:

-   Enforce user\_id exclusivity for AS registrations (PR #572)
-   Make adding push rules idempotent (PR #587)
-   Improve presence performance (PR #582, #586)
-   Change presence semantics for `last_active_ago` (PR #582, #586)
-   Don\'t allow `m.room.create` to be changed (PR #596)
-   Add 800x600 to default list of valid thumbnail sizes (PR #616)
-   Always include kicks and bans in full /sync (PR #625)
-   Send history visibility on boundary changes (PR #626)
-   Register endpoint now returns a refresh\_token (PR #637)

Bug fixes:

-   Fix bug where we returned incorrect state in /sync (PR #573)
-   Always return a JSON object from push rule API (PR #606)
-   Fix bug where registering without a user id sometimes failed (PR #610)
-   Report size of ExpiringCache in cache size metrics (PR #611)
-   Fix rejection of invites to empty rooms (PR #615)
-   Fix usage of `bcrypt` to not use `checkpw` (PR #619)
-   Pin `pysaml2` dependency (PR #634)
-   Fix bug in `/sync` where timeline order was incorrect for backfilled events (PR #635)

Changes in synapse v0.13.3 (2016-02-11)
=======================================

-   Fix bug where `/sync` would occasionally return events in the wrong room.

Changes in synapse v0.13.2 (2016-02-11)
=======================================

-   Fix bug where `/events` would fail to skip some events if there had been more events than the limit specified since the last request (PR #570)

Changes in synapse v0.13.1 (2016-02-10)
=======================================

-   Bump matrix-angular-sdk (matrix web console) dependency to 0.6.8 to pull in the fix for SYWEB-361 so that the default client can display HTML messages again(!)

Changes in synapse v0.13.0 (2016-02-10)
=======================================

This version includes an upgrade of the schema, specifically adding an index to the `events` table. This may cause synapse to pause for several minutes the first time it is started after the upgrade.

Changes:

-   Improve general performance (PR #540, #543. \#544, #54, #549, #567)
-   Change guest user ids to be incrementing integers (PR #550)
-   Improve performance of public room list API (PR #552)
-   Change profile API to omit keys rather than return null (PR #557)
-   Add `/media/r0` endpoint prefix, which is equivalent to `/media/v1/` (PR #595)

Bug fixes:

-   Fix bug with upgrading guest accounts where it would fail if you opened the registration email on a different device (PR #547)
-   Fix bug where unread count could be wrong (PR #568)

Changes in synapse v0.12.1-rc1 (2016-01-29)
===========================================

Features:

-   Add unread notification counts in `/sync` (PR #456)
-   Add support for inviting 3pids in `/createRoom` (PR #460)
-   Add ability for guest accounts to upgrade (PR #462)
-   Add `/versions` API (PR #468)
-   Add `event` to `/context` API (PR #492)
-   Add specific error code for invalid user names in `/register` (PR #499)
-   Add support for push badge counts (PR #507)
-   Add support for non-guest users to peek in rooms using `/events` (PR #510)

Changes:

-   Change `/sync` so that guest users only get rooms they\'ve joined (PR #469)
-   Change to require unbanning before other membership changes (PR #501)
-   Change default push rules to notify for all messages (PR #486)
-   Change default push rules to not notify on membership changes (PR #514)
-   Change default push rules in one to one rooms to only notify for events that are messages (PR #529)
-   Change `/sync` to reject requests with a `from` query param (PR #512)
-   Change server manhole to use SSH rather than telnet (PR #473)
-   Change server to require AS users to be registered before use (PR #487)
-   Change server not to start when ASes are invalidly configured (PR #494)
-   Change server to require ID and `as_token` to be unique for AS\'s (PR #496)
-   Change maximum pagination limit to 1000 (PR #497)

Bug fixes:

-   Fix bug where `/sync` didn\'t return when something under the leave key changed (PR #461)
-   Fix bug where we returned smaller rather than larger than requested thumbnails when `method=crop` (PR #464)
-   Fix thumbnails API to only return cropped thumbnails when asking for a cropped thumbnail (PR #475)
-   Fix bug where we occasionally still logged access tokens (PR #477)
-   Fix bug where `/events` would always return immediately for guest users (PR #480)
-   Fix bug where `/sync` unexpectedly returned old left rooms (PR #481)
-   Fix enabling and disabling push rules (PR #498)
-   Fix bug where `/register` returned 500 when given unicode username (PR #513)

Changes in synapse v0.12.0 (2016-01-04)
=======================================

-   Expose `/login` under `r0` (PR #459)

Changes in synapse v0.12.0-rc3 (2015-12-23)
===========================================

-   Allow guest accounts access to `/sync` (PR #455)
-   Allow filters to include/exclude rooms at the room level rather than just from the components of the sync for each room. (PR #454)
-   Include urls for room avatars in the response to `/publicRooms` (PR #453)
-   Don\'t set a identicon as the avatar for a user when they register (PR #450)
-   Add a `display_name` to third-party invites (PR #449)
-   Send more information to the identity server for third-party invites so that it can send richer messages to the invitee (PR #446)
-   Cache the responses to `/initialSync` for 5 minutes. If a client retries a request to `/initialSync` before the a response was computed to the first request then the same response is used for both requests (PR #457)
-   Fix a bug where synapse would always request the signing keys of remote servers even when the key was cached locally (PR #452)
-   Fix 500 when pagination search results (PR #447)
-   Fix a bug where synapse was leaking raw email address in third-party invites (PR #448)

Changes in synapse v0.12.0-rc2 (2015-12-14)
===========================================

-   Add caches for whether rooms have been forgotten by a user (PR #434)
-   Remove instructions to use `--process-dependency-link` since all of the dependencies of synapse are on PyPI (PR #436)
-   Parallelise the processing of `/sync` requests (PR #437)
-   Fix race updating presence in `/events` (PR #444)
-   Fix bug back-populating search results (PR #441)
-   Fix bug calculating state in `/sync` requests (PR #442)

Changes in synapse v0.12.0-rc1 (2015-12-10)
===========================================

-   Host the client APIs released as r0 by <https://matrix.org/docs/spec/r0.0.0/client_server.html> on paths prefixed by `/_matrix/client/r0`. (PR #430, PR #415, PR #400)
-   Updates the client APIs to match r0 of the matrix specification.
    -   All APIs return events in the new event format, old APIs also include the fields needed to parse the event using the old format for compatibility. (PR #402)
    -   Search results are now given as a JSON array rather than a JSON object (PR #405)
    -   Miscellaneous changes to search (PR #403, PR #406, PR #412)
    -   Filter JSON objects may now be passed as query parameters to `/sync` (PR #431)
    -   Fix implementation of `/admin/whois` (PR #418)
    -   Only include the rooms that user has left in `/sync` if the client requests them in the filter (PR #423)
    -   Don\'t push for `m.room.message` by default (PR #411)
    -   Add API for setting per account user data (PR #392)
    -   Allow users to forget rooms (PR #385)
-   Performance improvements and monitoring:
    -   Add per-request counters for CPU time spent on the main python thread. (PR #421, PR #420)
    -   Add per-request counters for time spent in the database (PR #429)
    -   Make state updates in the C+S API idempotent (PR #416)
    -   Only fire `user_joined_room` if the user has actually joined. (PR #410)
    -   Reuse a single http client, rather than creating new ones (PR #413)
-   Fixed a bug upgrading from older versions of synapse on postgresql (PR #417)

Changes in synapse v0.11.1 (2015-11-20)
=======================================

-   Add extra options to search API (PR #394)
-   Fix bug where we did not correctly cap federation retry timers. This meant it could take several hours for servers to start talking to ressurected servers, even when they were receiving traffic from them (PR #393)
-   Don\'t advertise login token flow unless CAS is enabled. This caused issues where some clients would always use the fallback API if they did not recognize all login flows (PR #391)
-   Change /v2 sync API to rename `private_user_data` to `account_data` (PR #386)
-   Change /v2 sync API to remove the `event_map` and rename keys in `rooms` object (PR #389)

Changes in synapse v0.11.0-r2 (2015-11-19)
==========================================

-   Fix bug in database port script (PR #387)

Changes in synapse v0.11.0-r1 (2015-11-18)
==========================================

-   Retry and fail federation requests more aggressively for requests that block client side requests (PR #384)

Changes in synapse v0.11.0 (2015-11-17)
=======================================

-   Change CAS login API (PR #349)

Changes in synapse v0.11.0-rc2 (2015-11-13)
===========================================

-   Various changes to /sync API response format (PR #373)
-   Fix regression when setting display name in newly joined room over federation (PR #368)
-   Fix problem where /search was slow when using SQLite (PR #366)

Changes in synapse v0.11.0-rc1 (2015-11-11)
===========================================

-   Add Search API (PR #307, #324, #327, #336, #350, #359)
-   Add \'archived\' state to v2 /sync API (PR #316)
-   Add ability to reject invites (PR #317)
-   Add config option to disable password login (PR #322)
-   Add the login fallback API (PR #330)
-   Add room context API (PR #334)
-   Add room tagging support (PR #335)
-   Update v2 /sync API to match spec (PR #305, #316, #321, #332, #337, #341)
-   Change retry schedule for application services (PR #320)
-   Change retry schedule for remote servers (PR #340)
-   Fix bug where we hosted static content in the incorrect place (PR #329)
-   Fix bug where we didn\'t increment retry interval for remote servers (PR #343)

Changes in synapse v0.10.1-rc1 (2015-10-15)
===========================================

-   Add support for CAS, thanks to Steven Hammerton (PR #295, #296)
-   Add support for using macaroons for `access_token` (PR #256, #229)
-   Add support for `m.room.canonical_alias` (PR #287)
-   Add support for viewing the history of rooms that they have left. (PR #276, #294)
-   Add support for refresh tokens (PR #240)
-   Add flag on creation which disables federation of the room (PR #279)
-   Add some room state to invites. (PR #275)
-   Atomically persist events when joining a room over federation (PR #283)
-   Change default history visibility for private rooms (PR #271)
-   Allow users to redact their own sent events (PR #262)
-   Use tox for tests (PR #247)
-   Split up syutil into separate libraries (PR #243)

Changes in synapse v0.10.0-r2 (2015-09-16)
==========================================

-   Fix bug where we always fetched remote server signing keys instead of using ones in our cache.
-   Fix adding threepids to an existing account.
-   Fix bug with invinting over federation where remote server was already in the room. (PR #281, SYN-392)

Changes in synapse v0.10.0-r1 (2015-09-08)
==========================================

-   Fix bug with python packaging

Changes in synapse v0.10.0 (2015-09-03)
=======================================

No change from release candidate.

Changes in synapse v0.10.0-rc6 (2015-09-02)
===========================================

-   Remove some of the old database upgrade scripts.
-   Fix database port script to work with newly created sqlite databases.

Changes in synapse v0.10.0-rc5 (2015-08-27)
===========================================

-   Fix bug that broke downloading files with ascii filenames across federation.

Changes in synapse v0.10.0-rc4 (2015-08-27)
===========================================

-   Allow UTF-8 filenames for upload. (PR #259)

Changes in synapse v0.10.0-rc3 (2015-08-25)
===========================================

-   Add `--keys-directory` config option to specify where files such as certs and signing keys should be stored in, when using `--generate-config` or `--generate-keys`. (PR #250)
-   Allow `--config-path` to specify a directory, causing synapse to use all \*.yaml files in the directory as config files. (PR #249)
-   Add `web_client_location` config option to specify static files to be hosted by synapse under `/_matrix/client`. (PR #245)
-   Add helper utility to synapse to read and parse the config files and extract the value of a given key. For example:

        $ python -m synapse.config read server_name -c homeserver.yaml
        localhost

    (PR #246)

Changes in synapse v0.10.0-rc2 (2015-08-24)
===========================================

-   Fix bug where we incorrectly populated the `event_forward_extremities` table, resulting in problems joining large remote rooms (e.g. `#matrix:matrix.org`)
-   Reduce the number of times we wake up pushers by not listening for presence or typing events, reducing the CPU cost of each pusher.

Changes in synapse v0.10.0-rc1 (2015-08-21)
===========================================

Also see v0.9.4-rc1 changelog, which has been amalgamated into this release.

General:

-   Upgrade to Twisted 15 (PR #173)
-   Add support for serving and fetching encryption keys over federation. (PR #208)
-   Add support for logging in with email address (PR #234)
-   Add support for new `m.room.canonical_alias` event. (PR #233)
-   Change synapse to treat user IDs case insensitively during registration and login. (If two users already exist with case insensitive matching user ids, synapse will continue to require them to specify their user ids exactly.)
-   Error if a user tries to register with an email already in use. (PR #211)
-   Add extra and improve existing caches (PR #212, #219, #226, #228)
-   Batch various storage request (PR #226, #228)
-   Fix bug where we didn\'t correctly log the entity that triggered the request if the request came in via an application service (PR #230)
-   Fix bug where we needlessly regenerated the full list of rooms an AS is interested in. (PR #232)
-   Add support for AS\'s to use v2\_alpha registration API (PR #210)

Configuration:

-   Add `--generate-keys` that will generate any missing cert and key files in the configuration files. This is equivalent to running `--generate-config` on an existing configuration file. (PR #220)
-   `--generate-config` now no longer requires a `--server-name` parameter when used on existing configuration files. (PR #220)
-   Add `--print-pidfile` flag that controls the printing of the pid to stdout of the demonised process. (PR #213)

Media Repository:

-   Fix bug where we picked a lower resolution image than requested. (PR #205)
-   Add support for specifying if a the media repository should dynamically thumbnail images or not. (PR #206)

Metrics:

-   Add statistics from the reactor to the metrics API. (PR #224, #225)

Demo Homeservers:

-   Fix starting the demo homeservers without rate-limiting enabled. (PR #182)
-   Fix enabling registration on demo homeservers (PR #223)

Changes in synapse v0.9.4-rc1 (2015-07-21)
==========================================

General:

-   Add basic implementation of receipts. (SPEC-99)
-   Add support for configuration presets in room creation API. (PR #203)
-   Add auth event that limits the visibility of history for new users. (SPEC-134)
-   Add SAML2 login/registration support. (PR #201. Thanks Muthu Subramanian!)
-   Add client side key management APIs for end to end encryption. (PR #198)
-   Change power level semantics so that you cannot kick, ban or change power levels of users that have equal or greater power level than you. (SYN-192)
-   Improve performance by bulk inserting events where possible. (PR #193)
-   Improve performance by bulk verifying signatures where possible. (PR #194)

Configuration:

-   Add support for including TLS certificate chains.

Media Repository:

-   Add Content-Disposition headers to content repository responses. (SYN-150)

Changes in synapse v0.9.3 (2015-07-01)
======================================

No changes from v0.9.3 Release Candidate 1.

Changes in synapse v0.9.3-rc1 (2015-06-23)
==========================================

General:

-   Fix a memory leak in the notifier. (SYN-412)
-   Improve performance of room initial sync. (SYN-418)
-   General improvements to logging.
-   Remove `access_token` query params from `INFO` level logging.

Configuration:

-   Add support for specifying and configuring multiple listeners. (SYN-389)

Application services:

-   Fix bug where synapse failed to send user queries to application services.

Changes in synapse v0.9.2-r2 (2015-06-15)
=========================================

Fix packaging so that schema delta python files get included in the package.

Changes in synapse v0.9.2 (2015-06-12)
======================================

General:

-   Use ultrajson for json (de)serialisation when a canonical encoding is not required. Ultrajson is significantly faster than simplejson in certain circumstances.
-   Use connection pools for outgoing HTTP connections.
-   Process thumbnails on separate threads.

Configuration:

-   Add option, `gzip_responses`, to disable HTTP response compression.

Federation:

-   Improve resilience of backfill by ensuring we fetch any missing auth events.
-   Improve performance of backfill and joining remote rooms by removing unnecessary computations. This included handling events we\'d previously handled as well as attempting to compute the current state for outliers.

Changes in synapse v0.9.1 (2015-05-26)
======================================

General:

-   Add support for backfilling when a client paginates. This allows servers to request history for a room from remote servers when a client tries to paginate history the server does not have - SYN-36
-   Fix bug where you couldn\'t disable non-default pushrules - SYN-378
-   Fix `register_new_user` script - SYN-359
-   Improve performance of fetching events from the database, this improves both initialSync and sending of events.
-   Improve performance of event streams, allowing synapse to handle more simultaneous connected clients.

Federation:

-   Fix bug with existing backfill implementation where it returned the wrong selection of events in some circumstances.
-   Improve performance of joining remote rooms.

Configuration:

-   Add support for changing the bind host of the metrics listener via the `metrics_bind_host` option.

Changes in synapse v0.9.0-r5 (2015-05-21)
=========================================

-   Add more database caches to reduce amount of work done for each pusher. This radically reduces CPU usage when multiple pushers are set up in the same room.

Changes in synapse v0.9.0 (2015-05-07)
======================================

General:

-   Add support for using a PostgreSQL database instead of SQLite. See [docs/postgres.rst](docs/postgres.rst) for details.
-   Add password change and reset APIs. See [Registration](https://github.com/matrix-org/matrix-doc/blob/master/specification/10_client_server_api.rst#registration) in the spec.
-   Fix memory leak due to not releasing stale notifiers - SYN-339.
-   Fix race in caches that occasionally caused some presence updates to be dropped - SYN-369.
-   Check server name has not changed on restart.
-   Add a sample systemd unit file and a logger configuration in contrib/systemd. Contributed Ivan Shapovalov.

Federation:

-   Add key distribution mechanisms for fetching public keys of unavailable remote home servers. See [Retrieving Server Keys](https://github.com/matrix-org/matrix-doc/blob/6f2698/specification/30_server_server_api.rst#retrieving-server-keys) in the spec.

Configuration:

-   Add support for multiple config files.
-   Add support for dictionaries in config files.
-   Remove support for specifying config options on the command line, except for:
    -   `--daemonize` - Daemonize the home server.
    -   `--manhole` - Turn on the twisted telnet manhole service on the given port.
    -   `--database-path` - The path to a sqlite database to use.
    -   `--verbose` - The verbosity level.
    -   `--log-file` - File to log to.
    -   `--log-config` - Python logging config file.
    -   `--enable-registration` - Enable registration for new users.

Application services:

-   Reliably retry sending of events from Synapse to application services, as per [Application Services](https://github.com/matrix-org/matrix-doc/blob/0c6bd9/specification/25_application_service_api.rst#home-server---application-service-api) spec.
-   Application services can no longer register via the `/register` API, instead their configuration should be saved to a file and listed in the synapse `app_service_config_files` config option. The AS configuration file has the same format as the old `/register` request. See [docs/application\_services.rst](docs/application_services.rst) for more information.

Changes in synapse v0.8.1 (2015-03-18)
======================================

-   Disable registration by default. New users can be added using the command `register_new_matrix_user` or by enabling registration in the config.
-   Add metrics to synapse. To enable metrics use config options `enable_metrics` and `metrics_port`.
-   Fix bug where banning only kicked the user.

Changes in synapse v0.8.0 (2015-03-06)
======================================

General:

-   Add support for registration fallback. This is a page hosted on the server which allows a user to register for an account, regardless of what client they are using (e.g. mobile devices).
-   Added new default push rules and made them configurable by clients:
    -   Suppress all notice messages.
    -   Notify when invited to a new room.
    -   Notify for messages that don\'t match any rule.
    -   Notify on incoming call.

Federation:

-   Added per host server side rate-limiting of incoming federation requests.
-   Added a `/get_missing_events/` API to federation to reduce number of `/events/` requests.

Configuration:

-   Added configuration option to disable registration: `disable_registration`.
-   Added configuration option to change soft limit of number of open file descriptors: `soft_file_limit`.
-   Make `tls_private_key_path` optional when running with `no_tls`.

Application services:

-   Application services can now poll on the CS API `/events` for their events, by providing their application service `access_token`.
-   Added exclusive namespace support to application services API.

Changes in synapse v0.7.1 (2015-02-19)
======================================

-   Initial alpha implementation of parts of the Application Services API. Including:
    -   AS Registration / Unregistration
    -   User Query API
    -   Room Alias Query API
    -   Push transport for receiving events.
    -   User/Alias namespace admin control
-   Add cache when fetching events from remote servers to stop repeatedly fetching events with bad signatures.
-   Respect the per remote server retry scheme when fetching both events and server keys to reduce the number of times we send requests to dead servers.
-   Inform remote servers when the local server fails to handle a received event.
-   Turn off python bytecode generation due to problems experienced when upgrading from previous versions.

Changes in synapse v0.7.0 (2015-02-12)
======================================

-   Add initial implementation of the query auth federation API, allowing servers to agree on whether an event should be allowed or rejected.
-   Persist events we have rejected from federation, fixing the bug where servers would keep requesting the same events.
-   Various federation performance improvements, including:
    -   Add in memory caches on queries such as:

        > -   Computing the state of a room at a point in time, used for authorization on federation requests.
        > -   Fetching events from the database.
        > -   User\'s room membership, used for authorizing presence updates.

    -   Upgraded JSON library to improve parsing and serialisation speeds.

-   Add default avatars to new user accounts using pydenticon library.
-   Correctly time out federation requests.
-   Retry federation requests against different servers.
-   Add support for push and push rules.
-   Add alpha versions of proposed new CSv2 APIs, including `/sync` API.

Changes in synapse 0.6.1 (2015-01-07)
=====================================

-   Major optimizations to improve performance of initial sync and event sending in large rooms (by up to 10x)
-   Media repository now includes a Content-Length header on media downloads.
-   Improve quality of thumbnails by changing resizing algorithm.

Changes in synapse 0.6.0 (2014-12-16)
=====================================

-   Add new API for media upload and download that supports thumbnailing.
-   Replicate media uploads over multiple homeservers so media is always served to clients from their local homeserver. This obsoletes the \--content-addr parameter and confusion over accessing content directly from remote homeservers.
-   Implement exponential backoff when retrying federation requests when sending to remote homeservers which are offline.
-   Implement typing notifications.
-   Fix bugs where we sent events with invalid signatures due to bugs where we incorrectly persisted events.
-   Improve performance of database queries involving retrieving events.

Changes in synapse 0.5.4a (2014-12-13)
======================================

-   Fix bug while generating the error message when a file path specified in the config doesn\'t exist.

Changes in synapse 0.5.4 (2014-12-03)
=====================================

-   Fix presence bug where some rooms did not display presence updates for remote users.
-   Do not log SQL timing log lines when started with \"-v\"
-   Fix potential memory leak.

Changes in synapse 0.5.3c (2014-12-02)
======================================

-   Change the default value for the content\_addr option to use the HTTP listener, as by default the HTTPS listener will be using a self-signed certificate.

Changes in synapse 0.5.3 (2014-11-27)
=====================================

-   Fix bug that caused joining a remote room to fail if a single event was not signed correctly.
-   Fix bug which caused servers to continuously try and fetch events from other servers.

Changes in synapse 0.5.2 (2014-11-26)
=====================================

Fix major bug that caused rooms to disappear from peoples initial sync.

Changes in synapse 0.5.1 (2014-11-26)
=====================================

See UPGRADES.rst for specific instructions on how to upgrade.

> -   Fix bug where we served up an Event that did not match its signatures.
> -   Fix regression where we no longer correctly handled the case where a homeserver receives an event for a room it doesn\'t recognise (but is in.)

Changes in synapse 0.5.0 (2014-11-19)
=====================================

This release includes changes to the federation protocol and client-server API that is not backwards compatible.

This release also changes the internal database schemas and so requires servers to drop their current history. See UPGRADES.rst for details.

Homeserver:

:   -   Add authentication and authorization to the federation protocol. Events are now signed by their originating homeservers.
    -   Implement the new authorization model for rooms.
    -   Split out web client into a seperate repository: matrix-angular-sdk.
    -   Change the structure of PDUs.
    -   Fix bug where user could not join rooms via an alias containing 4-byte UTF-8 characters.
    -   Merge concept of PDUs and Events internally.
    -   Improve logging by adding request ids to log lines.
    -   Implement a very basic room initial sync API.
    -   Implement the new invite/join federation APIs.

Webclient:

:   -   The webclient has been moved to a seperate repository.

Changes in synapse 0.4.2 (2014-10-31)
=====================================

Homeserver:

:   -   Fix bugs where we did not notify users of correct presence updates.
    -   Fix bug where we did not handle sub second event stream timeouts.

Webclient:

:   -   Add ability to click on messages to see JSON.
    -   Add ability to redact messages.
    -   Add ability to view and edit all room state JSON.
    -   Handle incoming redactions.
    -   Improve feedback on errors.
    -   Fix bugs in mobile CSS.
    -   Fix bugs with desktop notifications.

Changes in synapse 0.4.1 (2014-10-17)
=====================================

Webclient:

:   -   Fix bug with display of timestamps.

Changes in synpase 0.4.0 (2014-10-17)
=====================================

This release includes changes to the federation protocol and client-server API that is not backwards compatible.

The Matrix specification has been moved to a separate git repository: <http://github.com/matrix-org/matrix-doc>

You will also need an updated syutil and config. See UPGRADES.rst.

Homeserver:

:   -   Sign federation transactions to assert strong identity over federation.
    -   Rename timestamp keys in PDUs and events from \'ts\' and \'hsob\_ts\' to \'origin\_server\_ts\'.

Changes in synapse 0.3.4 (2014-09-25)
=====================================

This version adds support for using a TURN server. See docs/turn-howto.rst on how to set one up.

Homeserver:

:   -   Add support for redaction of messages.
    -   Fix bug where inviting a user on a remote home server could take up to 20-30s.
    -   Implement a get current room state API.
    -   Add support specifying and retrieving turn server configuration.

Webclient:

:   -   Add button to send messages to users from the home page.
    -   Add support for using TURN for VoIP calls.
    -   Show display name change messages.
    -   Fix bug where the client didn\'t get the state of a newly joined room until after it has been refreshed.
    -   Fix bugs with tab complete.
    -   Fix bug where holding down the down arrow caused chrome to chew 100% CPU.
    -   Fix bug where desktop notifications occasionally used \"Undefined\" as the display name.
    -   Fix more places where we sometimes saw room IDs incorrectly.
    -   Fix bug which caused lag when entering text in the text box.

Changes in synapse 0.3.3 (2014-09-22)
=====================================

Homeserver:

:   -   Fix bug where you continued to get events for rooms you had left.

Webclient:

:   -   Add support for video calls with basic UI.
    -   Fix bug where one to one chats were named after your display name rather than the other person\'s.
    -   Fix bug which caused lag when typing in the textarea.
    -   Refuse to run on browsers we know won\'t work.
    -   Trigger pagination when joining new rooms.
    -   Fix bug where we sometimes didn\'t display invitations in recents.
    -   Automatically join room when accepting a VoIP call.
    -   Disable outgoing and reject incoming calls on browsers we don\'t support VoIP in.
    -   Don\'t display desktop notifications for messages in the room you are non-idle and speaking in.

Changes in synapse 0.3.2 (2014-09-18)
=====================================

Webclient:

:   -   Fix bug where an empty \"bing words\" list in old accounts didn\'t send notifications when it should have done.

Changes in synapse 0.3.1 (2014-09-18)
=====================================

This is a release to hotfix v0.3.0 to fix two regressions.

Webclient:

:   -   Fix a regression where we sometimes displayed duplicate events.
    -   Fix a regression where we didn\'t immediately remove rooms you were banned in from the recents list.

Changes in synapse 0.3.0 (2014-09-18)
=====================================

See UPGRADE for information about changes to the client server API, including breaking backwards compatibility with VoIP calls and registration API.

Homeserver:

:   -   When a user changes their displayname or avatar the server will now update all their join states to reflect this.
    -   The server now adds \"age\" key to events to indicate how old they are. This is clock independent, so at no point does any server or webclient have to assume their clock is in sync with everyone else.
    -   Fix bug where we didn\'t correctly pull in missing PDUs.
    -   Fix bug where prev\_content key wasn\'t always returned.
    -   Add support for password resets.

Webclient:

:   -   Improve page content loading.
    -   Join/parts now trigger desktop notifications.
    -   Always show room aliases in the UI if one is present.
    -   No longer show user-count in the recents side panel.
    -   Add up & down arrow support to the text box for message sending to step through your sent history.
    -   Don\'t display notifications for our own messages.
    -   Emotes are now formatted correctly in desktop notifications.
    -   The recents list now differentiates between public & private rooms.
    -   Fix bug where when switching between rooms the pagination flickered before the view jumped to the bottom of the screen.
    -   Add bing word support.

Registration API:

:   -   The registration API has been overhauled to function like the login API. In practice, this means registration requests must now include the following: \'type\':\'m.login.password\'. See UPGRADE for more information on this.
    -   The \'user\_id\' key has been renamed to \'user\' to better match the login API.
    -   There is an additional login type: \'m.login.email.identity\'.
    -   The command client and web client have been updated to reflect these changes.

Changes in synapse 0.2.3 (2014-09-12)
=====================================

Homeserver:

:   -   Fix bug where we stopped sending events to remote home servers if a user from that home server left, even if there were some still in the room.
    -   Fix bugs in the state conflict resolution where it was incorrectly rejecting events.

Webclient:

:   -   Display room names and topics.
    -   Allow setting/editing of room names and topics.
    -   Display information about rooms on the main page.
    -   Handle ban and kick events in real time.
    -   VoIP UI and reliability improvements.
    -   Add glare support for VoIP.
    -   Improvements to initial startup speed.
    -   Don\'t display duplicate join events.
    -   Local echo of messages.
    -   Differentiate sending and sent of local echo.
    -   Various minor bug fixes.

Changes in synapse 0.2.2 (2014-09-06)
=====================================

Homeserver:

:   -   When the server returns state events it now also includes the previous content.
    -   Add support for inviting people when creating a new room.
    -   Make the homeserver inform the room via m.room.aliases when a new alias is added for a room.
    -   Validate m.room.power\_level events.

Webclient:

:   -   Add support for captchas on registration.
    -   Handle m.room.aliases events.
    -   Asynchronously send messages and show a local echo.
    -   Inform the UI when a message failed to send.
    -   Only autoscroll on receiving a new message if the user was already at the bottom of the screen.
    -   Add support for ban/kick reasons.

Changes in synapse 0.2.1 (2014-09-03)
=====================================

Homeserver:

:   -   Added support for signing up with a third party id.
    -   Add synctl scripts.
    -   Added rate limiting.
    -   Add option to change the external address the content repo uses.
    -   Presence bug fixes.

Webclient:

:   -   Added support for signing up with a third party id.
    -   Added support for banning and kicking users.
    -   Added support for displaying and setting ops.
    -   Added support for room names.
    -   Fix bugs with room membership event display.

Changes in synapse 0.2.0 (2014-09-02)
=====================================

This update changes many configuration options, updates the database schema and mandates SSL for server-server connections.

Homeserver:

:   -   Require SSL for server-server connections.
    -   Add SSL listener for client-server connections.
    -   Add ability to use config files.
    -   Add support for kicking/banning and power levels.
    -   Allow setting of room names and topics on creation.
    -   Change presence to include last seen time of the user.
    -   Change url path prefix to /\_matrix/\...
    -   Bug fixes to presence.

Webclient:

:   -   Reskin the CSS for registration and login.
    -   Various improvements to rooms CSS.
    -   Support changes in client-server API.
    -   Bug fixes to VOIP UI.
    -   Various bug fixes to handling of changes to room member list.

Changes in synapse 0.1.2 (2014-08-29)
=====================================

Webclient:

:   -   Add basic call state UI for VoIP calls.

Changes in synapse 0.1.1 (2014-08-29)
=====================================

Homeserver:

:   -   Fix bug that caused the event stream to not notify some clients about changes.

Changes in synapse 0.1.0 (2014-08-29)
=====================================

Presence has been reenabled in this release.

Homeserver:

:   -

        Update client to server API, including:

        :   -   Use a more consistent url scheme.
            -   Provide more useful information in the initial sync api.

    -   Change the presence handling to be much more efficient.
    -   Change the presence server to server API to not require explicit polling of all users who share a room with a user.
    -   Fix races in the event streaming logic.

Webclient:

:   -   Update to use new client to server API.
    -   Add basic VOIP support.
    -   Add idle timers that change your status to away.
    -   Add recent rooms column when viewing a room.
    -   Various network efficiency improvements.
    -   Add basic mobile browser support.
    -   Add a settings page.

Changes in synapse 0.0.1 (2014-08-22)
=====================================

Presence has been disabled in this release due to a bug that caused the homeserver to spam other remote homeservers.

Homeserver:

:   -   Completely change the database schema to support generic event types.
    -   Improve presence reliability.
    -   Improve reliability of joining remote rooms.
    -   Fix bug where room join events were duplicated.
    -   Improve initial sync API to return more information to the client.
    -   Stop generating fake messages for room membership events.

Webclient:

:   -   Add tab completion of names.
    -   Add ability to upload and send images.
    -   Add profile pages.
    -   Improve CSS layout of room.
    -   Disambiguate identical display names.
    -   Don\'t get remote users display names and avatars individually.
    -   Use the new initial sync API to reduce number of round trips to the homeserver.
    -   Change url scheme to use room aliases instead of room ids where known.
    -   Increase longpoll timeout.

Changes in synapse 0.0.0 (2014-08-13)
=====================================

> -   Initial alpha release
