Synapse 0.99.5.2 (2019-05-30)
=============================

Bugfixes
--------

- Fix bug where we leaked extremities when we soft failed events, leading to performance degradation. ([\#5274](https://github.com/matrix-org/synapse/issues/5274), [\#5278](https://github.com/matrix-org/synapse/issues/5278), [\#5291](https://github.com/matrix-org/synapse/issues/5291))


Synapse 0.99.5.1 (2019-05-22)
=============================

0.99.5.1 supersedes 0.99.5 due to malformed debian changelog - no functional changes.

Synapse 0.99.5 (2019-05-22)
===========================

No significant changes.


Synapse 0.99.5rc1 (2019-05-21)
==============================

Features
--------

- Add ability to blacklist IP ranges for the federation client. ([\#5043](https://github.com/matrix-org/synapse/issues/5043))
- Ratelimiting configuration for clients sending messages and the federation server has been altered to match login ratelimiting. The old configuration names will continue working. Check the sample config for details of the new names. ([\#5181](https://github.com/matrix-org/synapse/issues/5181))
- Drop support for the undocumented /_matrix/client/v2_alpha API prefix. ([\#5190](https://github.com/matrix-org/synapse/issues/5190))
- Add an option to disable per-room profiles. ([\#5196](https://github.com/matrix-org/synapse/issues/5196))
- Stick an expiration date to any registered user missing one at startup if account validity is enabled. ([\#5204](https://github.com/matrix-org/synapse/issues/5204))
- Add experimental support for relations (aka reactions and edits). ([\#5209](https://github.com/matrix-org/synapse/issues/5209), [\#5211](https://github.com/matrix-org/synapse/issues/5211), [\#5203](https://github.com/matrix-org/synapse/issues/5203), [\#5212](https://github.com/matrix-org/synapse/issues/5212))
- Add a room version 4 which uses a new event ID format, as per [MSC2002](https://github.com/matrix-org/matrix-doc/pull/2002). ([\#5210](https://github.com/matrix-org/synapse/issues/5210), [\#5217](https://github.com/matrix-org/synapse/issues/5217))


Bugfixes
--------

- Fix image orientation when generating thumbnails (needs pillow>=4.3.0). Contributed by Pau Rodriguez-Estivill. ([\#5039](https://github.com/matrix-org/synapse/issues/5039))
- Exclude soft-failed events from forward-extremity candidates: fixes "No forward extremities left!" error. ([\#5146](https://github.com/matrix-org/synapse/issues/5146))
- Re-order stages in registration flows such that msisdn and email verification are done last. ([\#5174](https://github.com/matrix-org/synapse/issues/5174))
- Fix 3pid guest invites. ([\#5177](https://github.com/matrix-org/synapse/issues/5177))
- Fix a bug where the register endpoint would fail with M_THREEPID_IN_USE instead of returning an account previously registered in the same session. ([\#5187](https://github.com/matrix-org/synapse/issues/5187))
- Prevent registration for user ids that are too long to fit into a state key. Contributed by Reid Anderson. ([\#5198](https://github.com/matrix-org/synapse/issues/5198))
- Fix incompatibility between ACME support and Python 3.5.2. ([\#5218](https://github.com/matrix-org/synapse/issues/5218))
- Fix error handling for rooms whose versions are unknown. ([\#5219](https://github.com/matrix-org/synapse/issues/5219))


Internal Changes
----------------

- Make /sync attempt to return device updates for both joined and invited users. Note that this doesn't currently work correctly due to other bugs. ([\#3484](https://github.com/matrix-org/synapse/issues/3484))
- Update tests to consistently be configured via the same code that is used when loading from configuration files. ([\#5171](https://github.com/matrix-org/synapse/issues/5171), [\#5185](https://github.com/matrix-org/synapse/issues/5185))
- Allow client event serialization to be async. ([\#5183](https://github.com/matrix-org/synapse/issues/5183))
- Expose DataStore._get_events as get_events_as_list. ([\#5184](https://github.com/matrix-org/synapse/issues/5184))
- Make generating SQL bounds for pagination generic. ([\#5191](https://github.com/matrix-org/synapse/issues/5191))
- Stop telling people to install the optional dependencies by default. ([\#5197](https://github.com/matrix-org/synapse/issues/5197))


Synapse 0.99.4 (2019-05-15)
===========================

No significant changes.


Synapse 0.99.4rc1 (2019-05-13)
==============================

Features
--------

- Add systemd-python to the optional dependencies to enable logging to the systemd journal. Install with `pip install matrix-synapse[systemd]`. ([\#4339](https://github.com/matrix-org/synapse/issues/4339))
- Add a default .m.rule.tombstone push rule. ([\#4867](https://github.com/matrix-org/synapse/issues/4867))
- Add ability for password provider modules to bind email addresses to users upon registration. ([\#4947](https://github.com/matrix-org/synapse/issues/4947))
- Implementation of [MSC1711](https://github.com/matrix-org/matrix-doc/pull/1711) including config options for requiring valid TLS certificates for federation traffic, the ability to disable TLS validation for specific domains, and the ability to specify your own list of CA certificates. ([\#4967](https://github.com/matrix-org/synapse/issues/4967))
- Remove presence list support as per MSC 1819. ([\#4989](https://github.com/matrix-org/synapse/issues/4989))
- Reduce CPU usage starting pushers during start up. ([\#4991](https://github.com/matrix-org/synapse/issues/4991))
- Add a delete group admin API. ([\#5002](https://github.com/matrix-org/synapse/issues/5002))
- Add config option to block users from looking up 3PIDs. ([\#5010](https://github.com/matrix-org/synapse/issues/5010))
- Add context to phonehome stats. ([\#5020](https://github.com/matrix-org/synapse/issues/5020))
- Configure the example systemd units to have a log identifier of `matrix-synapse`
  instead of the executable name, `python`.
  Contributed by Christoph Müller. ([\#5023](https://github.com/matrix-org/synapse/issues/5023))
- Add time-based account expiration. ([\#5027](https://github.com/matrix-org/synapse/issues/5027), [\#5047](https://github.com/matrix-org/synapse/issues/5047), [\#5073](https://github.com/matrix-org/synapse/issues/5073), [\#5116](https://github.com/matrix-org/synapse/issues/5116))
- Add support for handling `/versions`, `/voip` and `/push_rules` client endpoints to client_reader worker. ([\#5063](https://github.com/matrix-org/synapse/issues/5063), [\#5065](https://github.com/matrix-org/synapse/issues/5065), [\#5070](https://github.com/matrix-org/synapse/issues/5070))
- Add a configuration option to require authentication on /publicRooms and /profile endpoints. ([\#5083](https://github.com/matrix-org/synapse/issues/5083))
- Move admin APIs to `/_synapse/admin/v1`. (The old paths are retained for backwards-compatibility, for now). ([\#5119](https://github.com/matrix-org/synapse/issues/5119))
- Implement an admin API for sending server notices. Many thanks to @krombel who provided a foundation for this work. ([\#5121](https://github.com/matrix-org/synapse/issues/5121), [\#5142](https://github.com/matrix-org/synapse/issues/5142))


Bugfixes
--------

- Avoid redundant URL encoding of redirect URL for SSO login in the fallback login page. Fixes a regression introduced in [#4220](https://github.com/matrix-org/synapse/pull/4220). Contributed by Marcel Fabian Krüger ("[zaugin](https://github.com/zauguin)"). ([\#4555](https://github.com/matrix-org/synapse/issues/4555))
- Fix bug where presence updates were sent to all servers in a room when a new server joined, rather than to just the new server. ([\#4942](https://github.com/matrix-org/synapse/issues/4942), [\#5103](https://github.com/matrix-org/synapse/issues/5103))
- Fix sync bug which made accepting invites unreliable in worker-mode synapses. ([\#4955](https://github.com/matrix-org/synapse/issues/4955), [\#4956](https://github.com/matrix-org/synapse/issues/4956))
- start.sh: Fix the --no-rate-limit option for messages and make it bypass rate limit on registration and login too. ([\#4981](https://github.com/matrix-org/synapse/issues/4981))
- Transfer related groups on room upgrade. ([\#4990](https://github.com/matrix-org/synapse/issues/4990))
- Prevent the ability to kick users from a room they aren't in. ([\#4999](https://github.com/matrix-org/synapse/issues/4999))
- Fix issue [\#4596](https://github.com/matrix-org/synapse/issues/4596) so synapse_port_db script works with --curses option on Python 3. Contributed by Anders Jensen-Waud <anders@jensenwaud.com>. ([\#5003](https://github.com/matrix-org/synapse/issues/5003))
- Clients timing out/disappearing while downloading from the media repository will now no longer log a spurious "Producer was not unregistered" message. ([\#5009](https://github.com/matrix-org/synapse/issues/5009))
- Fix "cannot import name execute_batch" error with postgres. ([\#5032](https://github.com/matrix-org/synapse/issues/5032))
- Fix disappearing exceptions in manhole. ([\#5035](https://github.com/matrix-org/synapse/issues/5035))
- Workaround bug in twisted where attempting too many concurrent DNS requests could cause it to hang due to running out of file descriptors. ([\#5037](https://github.com/matrix-org/synapse/issues/5037))
- Make sure we're not registering the same 3pid twice on registration. ([\#5071](https://github.com/matrix-org/synapse/issues/5071))
- Don't crash on lack of expiry templates. ([\#5077](https://github.com/matrix-org/synapse/issues/5077))
- Fix the ratelimiting on third party invites. ([\#5104](https://github.com/matrix-org/synapse/issues/5104))
- Add some missing limitations to room alias creation. ([\#5124](https://github.com/matrix-org/synapse/issues/5124), [\#5128](https://github.com/matrix-org/synapse/issues/5128))
- Limit the number of EDUs in transactions to 100 as expected by synapse. Thanks to @superboum for this work! ([\#5138](https://github.com/matrix-org/synapse/issues/5138))

Internal Changes
----------------

- Add test to verify threepid auth check added in [\#4435](https://github.com/matrix-org/synapse/issues/4435). ([\#4474](https://github.com/matrix-org/synapse/issues/4474))
- Fix/improve some docstrings in the replication code. ([\#4949](https://github.com/matrix-org/synapse/issues/4949))
- Split synapse.replication.tcp.streams into smaller files. ([\#4953](https://github.com/matrix-org/synapse/issues/4953))
- Refactor replication row generation/parsing. ([\#4954](https://github.com/matrix-org/synapse/issues/4954))
- Run `black` to clean up formatting on `synapse/storage/roommember.py` and `synapse/storage/events.py`. ([\#4959](https://github.com/matrix-org/synapse/issues/4959))
- Remove log line for password via the admin API. ([\#4965](https://github.com/matrix-org/synapse/issues/4965))
- Fix typo in TLS filenames in docker/README.md. Also add the '-p' commandline option to the 'docker run' example. Contributed by Jurrie Overgoor. ([\#4968](https://github.com/matrix-org/synapse/issues/4968))
- Refactor room version definitions. ([\#4969](https://github.com/matrix-org/synapse/issues/4969))
- Reduce log level of .well-known/matrix/client responses. ([\#4972](https://github.com/matrix-org/synapse/issues/4972))
- Add `config.signing_key_path` that can be read by `synapse.config` utility. ([\#4974](https://github.com/matrix-org/synapse/issues/4974))
- Track which identity server is used when binding a threepid and use that for unbinding, as per MSC1915. ([\#4982](https://github.com/matrix-org/synapse/issues/4982))
- Rewrite KeyringTestCase as a HomeserverTestCase. ([\#4985](https://github.com/matrix-org/synapse/issues/4985))
- README updates: Corrected the default POSTGRES_USER. Added port forwarding hint in TLS section. ([\#4987](https://github.com/matrix-org/synapse/issues/4987))
- Remove a number of unused tables from the database schema. ([\#4992](https://github.com/matrix-org/synapse/issues/4992), [\#5028](https://github.com/matrix-org/synapse/issues/5028), [\#5033](https://github.com/matrix-org/synapse/issues/5033))
- Run `black` on the remainder of `synapse/storage/`. ([\#4996](https://github.com/matrix-org/synapse/issues/4996))
- Fix grammar in get_current_users_in_room and give it a docstring. ([\#4998](https://github.com/matrix-org/synapse/issues/4998))
- Clean up some code in the server-key Keyring. ([\#5001](https://github.com/matrix-org/synapse/issues/5001))
- Convert SYNAPSE_NO_TLS Docker variable to boolean for user friendliness. Contributed by Gabriel Eckerson. ([\#5005](https://github.com/matrix-org/synapse/issues/5005))
- Refactor synapse.storage._base._simple_select_list_paginate. ([\#5007](https://github.com/matrix-org/synapse/issues/5007))
- Store the notary server name correctly in server_keys_json. ([\#5024](https://github.com/matrix-org/synapse/issues/5024))
- Rewrite Datastore.get_server_verify_keys to reduce the number of database transactions. ([\#5030](https://github.com/matrix-org/synapse/issues/5030))
- Remove extraneous period from copyright headers. ([\#5046](https://github.com/matrix-org/synapse/issues/5046))
- Update documentation for where to get Synapse packages. ([\#5067](https://github.com/matrix-org/synapse/issues/5067))
- Add workarounds for pep-517 install errors. ([\#5098](https://github.com/matrix-org/synapse/issues/5098))
- Improve logging when event-signature checks fail. ([\#5100](https://github.com/matrix-org/synapse/issues/5100))
- Factor out an "assert_requester_is_admin" function. ([\#5120](https://github.com/matrix-org/synapse/issues/5120))
- Remove the requirement to authenticate for /admin/server_version. ([\#5122](https://github.com/matrix-org/synapse/issues/5122))
- Prevent an exception from being raised in a IResolutionReceiver and use a more generic error message for blacklisted URL previews. ([\#5155](https://github.com/matrix-org/synapse/issues/5155))
- Run `black` on the tests directory. ([\#5170](https://github.com/matrix-org/synapse/issues/5170))
- Fix CI after new release of isort. ([\#5179](https://github.com/matrix-org/synapse/issues/5179))
- Fix bogus imports in unit tests. ([\#5154](https://github.com/matrix-org/synapse/issues/5154))


Synapse 0.99.3.2 (2019-05-03)
=============================

Internal Changes
----------------

- Ensure that we have `urllib3` <1.25, to resolve incompatibility with `requests`. ([\#5135](https://github.com/matrix-org/synapse/issues/5135))


Synapse 0.99.3.1 (2019-05-03)
=============================

Security update
---------------

This release includes two security fixes:

- Switch to using a cryptographically-secure random number generator for token strings, ensuring they cannot be predicted by an attacker. Thanks to @opnsec for identifying and responsibly disclosing this issue! ([\#5133](https://github.com/matrix-org/synapse/issues/5133))
- Blacklist 0.0.0.0 and :: by default for URL previews. Thanks to @opnsec for identifying and responsibly disclosing this issue too! ([\#5134](https://github.com/matrix-org/synapse/issues/5134))

Synapse 0.99.3 (2019-04-01)
===========================

No significant changes.


Synapse 0.99.3rc1 (2019-03-27)
==============================

Features
--------

- The user directory has been rewritten to make it faster, with less chance of falling behind on a large server. ([\#4537](https://github.com/matrix-org/synapse/issues/4537), [\#4846](https://github.com/matrix-org/synapse/issues/4846), [\#4864](https://github.com/matrix-org/synapse/issues/4864), [\#4887](https://github.com/matrix-org/synapse/issues/4887), [\#4900](https://github.com/matrix-org/synapse/issues/4900), [\#4944](https://github.com/matrix-org/synapse/issues/4944))
- Add configurable rate limiting to the /register endpoint. ([\#4735](https://github.com/matrix-org/synapse/issues/4735), [\#4804](https://github.com/matrix-org/synapse/issues/4804))
- Move server key queries to federation reader. ([\#4757](https://github.com/matrix-org/synapse/issues/4757))
- Add support for /account/3pid REST endpoint to client_reader worker. ([\#4759](https://github.com/matrix-org/synapse/issues/4759))
- Add an endpoint to the admin API for querying the server version. Contributed by Joseph Weston. ([\#4772](https://github.com/matrix-org/synapse/issues/4772))
- Include a default configuration file in the 'docs' directory. ([\#4791](https://github.com/matrix-org/synapse/issues/4791), [\#4801](https://github.com/matrix-org/synapse/issues/4801))
- Synapse is now permissive about trailing slashes on some of its federation endpoints, allowing zero or more to be present. ([\#4793](https://github.com/matrix-org/synapse/issues/4793))
- Add support for /keys/query and /keys/changes REST endpoints to client_reader worker. ([\#4796](https://github.com/matrix-org/synapse/issues/4796))
- Add checks to incoming events over federation for events evading auth (aka "soft fail"). ([\#4814](https://github.com/matrix-org/synapse/issues/4814))
- Add configurable rate limiting to the /login endpoint. ([\#4821](https://github.com/matrix-org/synapse/issues/4821), [\#4865](https://github.com/matrix-org/synapse/issues/4865))
- Remove trailing slashes from certain outbound federation requests. Retry if receiving a 404. Context: [\#3622](https://github.com/matrix-org/synapse/issues/3622). ([\#4840](https://github.com/matrix-org/synapse/issues/4840))
- Allow passing --daemonize flags to workers in the same way as with master. ([\#4853](https://github.com/matrix-org/synapse/issues/4853))
- Batch up outgoing read-receipts to reduce federation traffic. ([\#4890](https://github.com/matrix-org/synapse/issues/4890), [\#4927](https://github.com/matrix-org/synapse/issues/4927))
- Add option to disable searching the user directory. ([\#4895](https://github.com/matrix-org/synapse/issues/4895))
- Add option to disable searching of local and remote public room lists. ([\#4896](https://github.com/matrix-org/synapse/issues/4896))
- Add ability for password providers to login/register a user via 3PID (email, phone). ([\#4931](https://github.com/matrix-org/synapse/issues/4931))


Bugfixes
--------

- Fix a bug where media with spaces in the name would get a corrupted name. ([\#2090](https://github.com/matrix-org/synapse/issues/2090))
- Fix attempting to paginate in rooms where server cannot see any events, to avoid unnecessarily pulling in lots of redacted events. ([\#4699](https://github.com/matrix-org/synapse/issues/4699))
- 'event_id' is now a required parameter in federated state requests, as per the matrix spec. ([\#4740](https://github.com/matrix-org/synapse/issues/4740))
- Fix tightloop over connecting to replication server. ([\#4749](https://github.com/matrix-org/synapse/issues/4749))
- Fix parsing of Content-Disposition headers on remote media requests and URL previews. ([\#4763](https://github.com/matrix-org/synapse/issues/4763))
- Fix incorrect log about not persisting duplicate state event. ([\#4776](https://github.com/matrix-org/synapse/issues/4776))
- Fix v4v6 option in HAProxy example config. Contributed by Flakebi. ([\#4790](https://github.com/matrix-org/synapse/issues/4790))
- Handle batch updates in worker replication protocol. ([\#4792](https://github.com/matrix-org/synapse/issues/4792))
- Fix bug where we didn't correctly throttle sending of USER_IP commands over replication. ([\#4818](https://github.com/matrix-org/synapse/issues/4818))
- Fix potential race in handling missing updates in device list updates. ([\#4829](https://github.com/matrix-org/synapse/issues/4829))
- Fix bug where synapse expected an un-specced `prev_state` field on state events. ([\#4837](https://github.com/matrix-org/synapse/issues/4837))
- Transfer a user's notification settings (push rules) on room upgrade. ([\#4838](https://github.com/matrix-org/synapse/issues/4838))
- fix test_auto_create_auto_join_where_no_consent. ([\#4886](https://github.com/matrix-org/synapse/issues/4886))
- Fix a bug where hs_disabled_message was sometimes not correctly enforced. ([\#4888](https://github.com/matrix-org/synapse/issues/4888))
- Fix bug in shutdown room admin API where it would fail if a user in the room hadn't consented to the privacy policy. ([\#4904](https://github.com/matrix-org/synapse/issues/4904))
- Fix bug where blocked world-readable rooms were still peekable. ([\#4908](https://github.com/matrix-org/synapse/issues/4908))


Internal Changes
----------------

- Add a systemd setup that supports synapse workers. Contributed by Luca Corbatto. ([\#4662](https://github.com/matrix-org/synapse/issues/4662))
- Change from TravisCI to Buildkite for CI. ([\#4752](https://github.com/matrix-org/synapse/issues/4752))
- When presence is disabled don't send over replication. ([\#4757](https://github.com/matrix-org/synapse/issues/4757))
- Minor docstring fixes for MatrixFederationAgent. ([\#4765](https://github.com/matrix-org/synapse/issues/4765))
- Optimise EDU transmission for the federation_sender worker. ([\#4770](https://github.com/matrix-org/synapse/issues/4770))
- Update test_typing to use HomeserverTestCase. ([\#4771](https://github.com/matrix-org/synapse/issues/4771))
- Update URLs for riot.im icons and logos in the default notification templates. ([\#4779](https://github.com/matrix-org/synapse/issues/4779))
- Removed unnecessary $ from some federation endpoint path regexes. ([\#4794](https://github.com/matrix-org/synapse/issues/4794))
- Remove link to deleted title in README. ([\#4795](https://github.com/matrix-org/synapse/issues/4795))
- Clean up read-receipt handling. ([\#4797](https://github.com/matrix-org/synapse/issues/4797))
- Add some debug about processing read receipts. ([\#4798](https://github.com/matrix-org/synapse/issues/4798))
- Clean up some replication code. ([\#4799](https://github.com/matrix-org/synapse/issues/4799))
- Add some docstrings. ([\#4815](https://github.com/matrix-org/synapse/issues/4815))
- Add debug logger to try and track down [\#4422](https://github.com/matrix-org/synapse/issues/4422). ([\#4816](https://github.com/matrix-org/synapse/issues/4816))
- Make shutdown API send explanation message to room after users have been forced joined. ([\#4817](https://github.com/matrix-org/synapse/issues/4817))
- Update example_log_config.yaml. ([\#4820](https://github.com/matrix-org/synapse/issues/4820))
- Document the `generate` option for the docker image. ([\#4824](https://github.com/matrix-org/synapse/issues/4824))
- Fix check-newsfragment for debian-only changes. ([\#4825](https://github.com/matrix-org/synapse/issues/4825))
- Add some debug logging for device list updates to help with [\#4828](https://github.com/matrix-org/synapse/issues/4828). ([\#4828](https://github.com/matrix-org/synapse/issues/4828))
- Improve federation documentation, specifically .well-known support. Many thanks to @vaab. ([\#4832](https://github.com/matrix-org/synapse/issues/4832))
- Disable captcha registration by default in unit tests. ([\#4839](https://github.com/matrix-org/synapse/issues/4839))
- Add stuff back to the .gitignore. ([\#4843](https://github.com/matrix-org/synapse/issues/4843))
- Clarify what registration_shared_secret allows for. ([\#4844](https://github.com/matrix-org/synapse/issues/4844))
- Correctly log expected errors when fetching server keys. ([\#4847](https://github.com/matrix-org/synapse/issues/4847))
- Update install docs to explicitly state a full-chain (not just the top-level) TLS certificate must be provided to Synapse. This caused some people's Synapse ports to appear correct in a browser but still (rightfully so) upset the federation tester. ([\#4849](https://github.com/matrix-org/synapse/issues/4849))
- Move client read-receipt processing to federation sender worker. ([\#4852](https://github.com/matrix-org/synapse/issues/4852))
- Refactor federation TransactionQueue. ([\#4855](https://github.com/matrix-org/synapse/issues/4855))
- Comment out most options in the generated config. ([\#4863](https://github.com/matrix-org/synapse/issues/4863))
- Fix yaml library warnings by using safe_load. ([\#4869](https://github.com/matrix-org/synapse/issues/4869))
- Update Apache setup to remove location syntax. Thanks to @cwmke! ([\#4870](https://github.com/matrix-org/synapse/issues/4870))
- Reinstate test case that runs unit tests against oldest supported dependencies. ([\#4879](https://github.com/matrix-org/synapse/issues/4879))
- Update link to federation docs. ([\#4881](https://github.com/matrix-org/synapse/issues/4881))
- fix test_auto_create_auto_join_where_no_consent. ([\#4886](https://github.com/matrix-org/synapse/issues/4886))
- Use a regular HomeServerConfig object for unit tests rater than a Mock. ([\#4889](https://github.com/matrix-org/synapse/issues/4889))
- Add some notes about tuning postgres for larger deployments. ([\#4895](https://github.com/matrix-org/synapse/issues/4895))
- Add a config option for torture-testing worker replication. ([\#4902](https://github.com/matrix-org/synapse/issues/4902))
- Log requests which are simulated by the unit tests. ([\#4905](https://github.com/matrix-org/synapse/issues/4905))
- Allow newsfragments to end with exclamation marks. Exciting! ([\#4912](https://github.com/matrix-org/synapse/issues/4912))
- Refactor some more tests to use HomeserverTestCase. ([\#4913](https://github.com/matrix-org/synapse/issues/4913))
- Refactor out the state deltas portion of the user directory store and handler. ([\#4917](https://github.com/matrix-org/synapse/issues/4917))
- Fix nginx example in ACME doc. ([\#4923](https://github.com/matrix-org/synapse/issues/4923))
- Use an explicit dbname for postgres connections in the tests. ([\#4928](https://github.com/matrix-org/synapse/issues/4928))
- Fix `ClientReplicationStreamProtocol.__str__()`. ([\#4929](https://github.com/matrix-org/synapse/issues/4929))


Synapse 0.99.2 (2019-03-01)
===========================

Features
--------

- Added an HAProxy example in the reverse proxy documentation. Contributed by Benoît S. (“Benpro”). ([\#4541](https://github.com/matrix-org/synapse/issues/4541))
- Add basic optional sentry integration. ([\#4632](https://github.com/matrix-org/synapse/issues/4632), [\#4694](https://github.com/matrix-org/synapse/issues/4694))
- Transfer bans on room upgrade. ([\#4642](https://github.com/matrix-org/synapse/issues/4642))
- Add configurable room list publishing rules. ([\#4647](https://github.com/matrix-org/synapse/issues/4647))
- Support .well-known delegation when issuing certificates through ACME. ([\#4652](https://github.com/matrix-org/synapse/issues/4652))
- Allow registration and login to be handled by a worker instance. ([\#4666](https://github.com/matrix-org/synapse/issues/4666), [\#4670](https://github.com/matrix-org/synapse/issues/4670), [\#4682](https://github.com/matrix-org/synapse/issues/4682))
- Reduce the overhead of creating outbound federation connections over TLS by caching the TLS client options. ([\#4674](https://github.com/matrix-org/synapse/issues/4674))
- Add prometheus metrics for number of outgoing EDUs, by type. ([\#4695](https://github.com/matrix-org/synapse/issues/4695))
- Return correct error code when inviting a remote user to a room whose homeserver does not support the room version. ([\#4721](https://github.com/matrix-org/synapse/issues/4721))
- Prevent showing rooms to other servers that were set to not federate. ([\#4746](https://github.com/matrix-org/synapse/issues/4746))


Bugfixes
--------

- Fix possible exception when paginating. ([\#4263](https://github.com/matrix-org/synapse/issues/4263))
- The dependency checker now correctly reports a version mismatch for optional
  dependencies, instead of reporting the dependency missing. ([\#4450](https://github.com/matrix-org/synapse/issues/4450))
- Set CORS headers on .well-known requests. ([\#4651](https://github.com/matrix-org/synapse/issues/4651))
- Fix kicking guest users on guest access revocation in worker mode. ([\#4667](https://github.com/matrix-org/synapse/issues/4667))
- Fix an issue in the database migration script where the
  `e2e_room_keys.is_verified` column wasn't considered as
  a boolean. ([\#4680](https://github.com/matrix-org/synapse/issues/4680))
- Fix TaskStopped exceptions in logs when outbound requests time out. ([\#4690](https://github.com/matrix-org/synapse/issues/4690))
- Fix ACME config for python 2. ([\#4717](https://github.com/matrix-org/synapse/issues/4717))
- Fix paginating over federation persisting incorrect state. ([\#4718](https://github.com/matrix-org/synapse/issues/4718))


Internal Changes
----------------

- Run `black` to reformat user directory code. ([\#4635](https://github.com/matrix-org/synapse/issues/4635))
- Reduce number of exceptions we log. ([\#4643](https://github.com/matrix-org/synapse/issues/4643), [\#4668](https://github.com/matrix-org/synapse/issues/4668))
- Introduce upsert batching functionality in the database layer. ([\#4644](https://github.com/matrix-org/synapse/issues/4644))
- Fix various spelling mistakes. ([\#4657](https://github.com/matrix-org/synapse/issues/4657))
- Cleanup request exception logging. ([\#4669](https://github.com/matrix-org/synapse/issues/4669), [\#4737](https://github.com/matrix-org/synapse/issues/4737), [\#4738](https://github.com/matrix-org/synapse/issues/4738))
- Improve replication performance by reducing cache invalidation traffic. ([\#4671](https://github.com/matrix-org/synapse/issues/4671), [\#4715](https://github.com/matrix-org/synapse/issues/4715), [\#4748](https://github.com/matrix-org/synapse/issues/4748))
- Test against Postgres 9.5 as well as 9.4. ([\#4676](https://github.com/matrix-org/synapse/issues/4676))
- Run unit tests against python 3.7. ([\#4677](https://github.com/matrix-org/synapse/issues/4677))
- Attempt to clarify installation instructions/config. ([\#4681](https://github.com/matrix-org/synapse/issues/4681))
- Clean up gitignores. ([\#4688](https://github.com/matrix-org/synapse/issues/4688))
- Minor tweaks to acme docs. ([\#4689](https://github.com/matrix-org/synapse/issues/4689))
- Improve the logging in the pusher process. ([\#4691](https://github.com/matrix-org/synapse/issues/4691))
- Better checks on newsfragments. ([\#4698](https://github.com/matrix-org/synapse/issues/4698), [\#4750](https://github.com/matrix-org/synapse/issues/4750))
- Avoid some redundant work when processing read receipts. ([\#4706](https://github.com/matrix-org/synapse/issues/4706))
- Run `push_receipts_to_remotes` as background job. ([\#4707](https://github.com/matrix-org/synapse/issues/4707))
- Add prometheus metrics for number of badge update pushes. ([\#4709](https://github.com/matrix-org/synapse/issues/4709))
- Reduce pusher logging on startup ([\#4716](https://github.com/matrix-org/synapse/issues/4716))
- Don't log exceptions when failing to fetch remote server keys. ([\#4722](https://github.com/matrix-org/synapse/issues/4722))
- Correctly proxy exception in frontend_proxy worker. ([\#4723](https://github.com/matrix-org/synapse/issues/4723))
- Add database version to phonehome stats. ([\#4753](https://github.com/matrix-org/synapse/issues/4753))


Synapse 0.99.1.1 (2019-02-14)
=============================

Bugfixes
--------

- Fix "TypeError: '>' not supported" when starting without an existing certificate.
  Fix a bug where an existing certificate would be reprovisoned every day. ([\#4648](https://github.com/matrix-org/synapse/issues/4648))


Synapse 0.99.1 (2019-02-14)
===========================

Features
--------

- Include m.room.encryption on invites by default ([\#3902](https://github.com/matrix-org/synapse/issues/3902))
- Federation OpenID listener resource can now be activated even if federation is disabled ([\#4420](https://github.com/matrix-org/synapse/issues/4420))
- Synapse's ACME support will now correctly reprovision a certificate that approaches its expiry while Synapse is running. ([\#4522](https://github.com/matrix-org/synapse/issues/4522))
- Add ability to update backup versions ([\#4580](https://github.com/matrix-org/synapse/issues/4580))
- Allow the "unavailable" presence status for /sync.
  This change makes Synapse compliant with r0.4.0 of the Client-Server specification. ([\#4592](https://github.com/matrix-org/synapse/issues/4592))
- There is no longer any need to specify `no_tls`: it is inferred from the absence of TLS listeners ([\#4613](https://github.com/matrix-org/synapse/issues/4613), [\#4615](https://github.com/matrix-org/synapse/issues/4615), [\#4617](https://github.com/matrix-org/synapse/issues/4617), [\#4636](https://github.com/matrix-org/synapse/issues/4636))
- The default configuration no longer requires TLS certificates. ([\#4614](https://github.com/matrix-org/synapse/issues/4614))


Bugfixes
--------

- Copy over room federation ability on room upgrade. ([\#4530](https://github.com/matrix-org/synapse/issues/4530))
- Fix noisy "twisted.internet.task.TaskStopped" errors in logs ([\#4546](https://github.com/matrix-org/synapse/issues/4546))
- Synapse is now tolerant of the `tls_fingerprints` option being None or not specified. ([\#4589](https://github.com/matrix-org/synapse/issues/4589))
- Fix 'no unique or exclusion constraint' error ([\#4591](https://github.com/matrix-org/synapse/issues/4591))
- Transfer Server ACLs on room upgrade. ([\#4608](https://github.com/matrix-org/synapse/issues/4608))
- Fix failure to start when not TLS certificate was given even if TLS was disabled. ([\#4618](https://github.com/matrix-org/synapse/issues/4618))
- Fix self-signed cert notice from generate-config. ([\#4625](https://github.com/matrix-org/synapse/issues/4625))
- Fix performance of `user_ips` table deduplication background update ([\#4626](https://github.com/matrix-org/synapse/issues/4626), [\#4627](https://github.com/matrix-org/synapse/issues/4627))


Internal Changes
----------------

- Change the user directory state query to use a filtered call to the db instead of a generic one. ([\#4462](https://github.com/matrix-org/synapse/issues/4462))
- Reject federation transactions if they include more than 50 PDUs or 100 EDUs. ([\#4513](https://github.com/matrix-org/synapse/issues/4513))
- Reduce duplication of ``synapse.app`` code. ([\#4567](https://github.com/matrix-org/synapse/issues/4567))
- Fix docker upload job to push -py2 images. ([\#4576](https://github.com/matrix-org/synapse/issues/4576))
- Add port configuration information to ACME instructions. ([\#4578](https://github.com/matrix-org/synapse/issues/4578))
- Update MSC1711 FAQ to calrify .well-known usage ([\#4584](https://github.com/matrix-org/synapse/issues/4584))
- Clean up default listener configuration ([\#4586](https://github.com/matrix-org/synapse/issues/4586))
- Clarifications for reverse proxy docs ([\#4607](https://github.com/matrix-org/synapse/issues/4607))
- Move ClientTLSOptionsFactory init out of `refresh_certificates` ([\#4611](https://github.com/matrix-org/synapse/issues/4611))
- Fail cleanly if listener config lacks a 'port' ([\#4616](https://github.com/matrix-org/synapse/issues/4616))
- Remove redundant entries from docker config ([\#4619](https://github.com/matrix-org/synapse/issues/4619))
- README updates ([\#4621](https://github.com/matrix-org/synapse/issues/4621))


Synapse 0.99.0 (2019-02-05)
===========================

Synapse v0.99.x is a precursor to the upcoming Synapse v1.0 release. It contains foundational changes to room architecture and the federation security model necessary to support the upcoming r0 release of the Server to Server API.

Features
--------

- Synapse's cipher string has been updated to require ECDH key exchange. Configuring and generating dh_params is no longer required, and they will be ignored. ([\#4229](https://github.com/matrix-org/synapse/issues/4229))
- Synapse can now automatically provision TLS certificates via ACME (the protocol used by CAs like Let's Encrypt). ([\#4384](https://github.com/matrix-org/synapse/issues/4384), [\#4492](https://github.com/matrix-org/synapse/issues/4492), [\#4525](https://github.com/matrix-org/synapse/issues/4525), [\#4572](https://github.com/matrix-org/synapse/issues/4572), [\#4564](https://github.com/matrix-org/synapse/issues/4564), [\#4566](https://github.com/matrix-org/synapse/issues/4566), [\#4547](https://github.com/matrix-org/synapse/issues/4547), [\#4557](https://github.com/matrix-org/synapse/issues/4557))
- Implement MSC1708 (.well-known routing for server-server federation) ([\#4408](https://github.com/matrix-org/synapse/issues/4408), [\#4409](https://github.com/matrix-org/synapse/issues/4409), [\#4426](https://github.com/matrix-org/synapse/issues/4426), [\#4427](https://github.com/matrix-org/synapse/issues/4427), [\#4428](https://github.com/matrix-org/synapse/issues/4428), [\#4464](https://github.com/matrix-org/synapse/issues/4464), [\#4468](https://github.com/matrix-org/synapse/issues/4468), [\#4487](https://github.com/matrix-org/synapse/issues/4487), [\#4488](https://github.com/matrix-org/synapse/issues/4488), [\#4489](https://github.com/matrix-org/synapse/issues/4489), [\#4497](https://github.com/matrix-org/synapse/issues/4497), [\#4511](https://github.com/matrix-org/synapse/issues/4511), [\#4516](https://github.com/matrix-org/synapse/issues/4516), [\#4520](https://github.com/matrix-org/synapse/issues/4520), [\#4521](https://github.com/matrix-org/synapse/issues/4521), [\#4539](https://github.com/matrix-org/synapse/issues/4539), [\#4542](https://github.com/matrix-org/synapse/issues/4542), [\#4544](https://github.com/matrix-org/synapse/issues/4544))
- Search now includes results from predecessor rooms after a room upgrade. ([\#4415](https://github.com/matrix-org/synapse/issues/4415))
- Config option to disable requesting MSISDN on registration. ([\#4423](https://github.com/matrix-org/synapse/issues/4423))
- Add a metric for tracking event stream position of the user directory. ([\#4445](https://github.com/matrix-org/synapse/issues/4445))
- Support exposing server capabilities in CS API (MSC1753, MSC1804) ([\#4472](https://github.com/matrix-org/synapse/issues/4472), [81b7e7eed](https://github.com/matrix-org/synapse/commit/81b7e7eed323f55d6550e7a270a9dc2c4c7b0fe0)))
- Add support for room version 3 ([\#4483](https://github.com/matrix-org/synapse/issues/4483), [\#4499](https://github.com/matrix-org/synapse/issues/4499), [\#4515](https://github.com/matrix-org/synapse/issues/4515), [\#4523](https://github.com/matrix-org/synapse/issues/4523), [\#4535](https://github.com/matrix-org/synapse/issues/4535))
- Synapse will now reload TLS certificates from disk upon SIGHUP. ([\#4495](https://github.com/matrix-org/synapse/issues/4495), [\#4524](https://github.com/matrix-org/synapse/issues/4524))
- The matrixdotorg/synapse Docker images now use Python 3 by default. ([\#4558](https://github.com/matrix-org/synapse/issues/4558))

Bugfixes
--------

- Prevent users with access tokens predating the introduction of device IDs from creating spurious entries in the user_ips table. ([\#4369](https://github.com/matrix-org/synapse/issues/4369))
- Fix typo in ALL_USER_TYPES definition to ensure type is a tuple ([\#4392](https://github.com/matrix-org/synapse/issues/4392))
- Fix high CPU usage due to remote devicelist updates ([\#4397](https://github.com/matrix-org/synapse/issues/4397))
- Fix potential bug where creating or joining a room could fail ([\#4404](https://github.com/matrix-org/synapse/issues/4404))
- Fix bug when rejecting remote invites ([\#4405](https://github.com/matrix-org/synapse/issues/4405), [\#4527](https://github.com/matrix-org/synapse/issues/4527))
- Fix incorrect logcontexts after a Deferred was cancelled ([\#4407](https://github.com/matrix-org/synapse/issues/4407))
- Ensure encrypted room state is persisted across room upgrades. ([\#4411](https://github.com/matrix-org/synapse/issues/4411))
- Copy over whether a room is a direct message and any associated room tags on room upgrade. ([\#4412](https://github.com/matrix-org/synapse/issues/4412))
- Fix None guard in calling config.server.is_threepid_reserved ([\#4435](https://github.com/matrix-org/synapse/issues/4435))
- Don't send IP addresses as SNI ([\#4452](https://github.com/matrix-org/synapse/issues/4452))
- Fix UnboundLocalError in post_urlencoded_get_json ([\#4460](https://github.com/matrix-org/synapse/issues/4460))
- Add a timeout to filtered room directory queries. ([\#4461](https://github.com/matrix-org/synapse/issues/4461))
- Workaround for login error when using both LDAP and internal authentication. ([\#4486](https://github.com/matrix-org/synapse/issues/4486))
- Fix a bug where setting a relative consent directory path would cause a crash. ([\#4512](https://github.com/matrix-org/synapse/issues/4512))


Deprecations and Removals
-------------------------

- Synapse no longer generates self-signed TLS certificates when generating a configuration file. ([\#4509](https://github.com/matrix-org/synapse/issues/4509))


Improved Documentation
----------------------

- Update debian installation instructions ([\#4526](https://github.com/matrix-org/synapse/issues/4526))


Internal Changes
----------------

- Synapse will now take advantage of native UPSERT functionality in PostgreSQL 9.5+ and SQLite 3.24+. ([\#4306](https://github.com/matrix-org/synapse/issues/4306), [\#4459](https://github.com/matrix-org/synapse/issues/4459), [\#4466](https://github.com/matrix-org/synapse/issues/4466), [\#4471](https://github.com/matrix-org/synapse/issues/4471), [\#4477](https://github.com/matrix-org/synapse/issues/4477), [\#4505](https://github.com/matrix-org/synapse/issues/4505))
- Update README to use the new virtualenv everywhere ([\#4342](https://github.com/matrix-org/synapse/issues/4342))
- Add better logging for unexpected errors while sending transactions ([\#4368](https://github.com/matrix-org/synapse/issues/4368))
- Apply a unique index to the user_ips table, preventing duplicates. ([\#4370](https://github.com/matrix-org/synapse/issues/4370), [\#4432](https://github.com/matrix-org/synapse/issues/4432), [\#4434](https://github.com/matrix-org/synapse/issues/4434))
- Silence travis-ci build warnings by removing non-functional python3.6 ([\#4377](https://github.com/matrix-org/synapse/issues/4377))
- Fix a comment in the generated config file ([\#4387](https://github.com/matrix-org/synapse/issues/4387))
- Add ground work for implementing future federation API versions ([\#4390](https://github.com/matrix-org/synapse/issues/4390))
- Update dependencies on msgpack and pymacaroons to use the up-to-date packages. ([\#4399](https://github.com/matrix-org/synapse/issues/4399))
- Tweak codecov settings to make them less loud. ([\#4400](https://github.com/matrix-org/synapse/issues/4400))
- Implement server support for MSC1794 - Federation v2 Invite API ([\#4402](https://github.com/matrix-org/synapse/issues/4402))
- debian package: symlink to explicit python version ([\#4433](https://github.com/matrix-org/synapse/issues/4433))
- Add infrastructure to support different event formats ([\#4437](https://github.com/matrix-org/synapse/issues/4437), [\#4447](https://github.com/matrix-org/synapse/issues/4447), [\#4448](https://github.com/matrix-org/synapse/issues/4448), [\#4470](https://github.com/matrix-org/synapse/issues/4470), [\#4481](https://github.com/matrix-org/synapse/issues/4481), [\#4482](https://github.com/matrix-org/synapse/issues/4482), [\#4493](https://github.com/matrix-org/synapse/issues/4493), [\#4494](https://github.com/matrix-org/synapse/issues/4494), [\#4496](https://github.com/matrix-org/synapse/issues/4496), [\#4510](https://github.com/matrix-org/synapse/issues/4510), [\#4514](https://github.com/matrix-org/synapse/issues/4514))
- Generate the debian config during build ([\#4444](https://github.com/matrix-org/synapse/issues/4444))
- Clarify documentation for the `public_baseurl` config param ([\#4458](https://github.com/matrix-org/synapse/issues/4458), [\#4498](https://github.com/matrix-org/synapse/issues/4498))
- Fix quoting for allowed_local_3pids example config ([\#4476](https://github.com/matrix-org/synapse/issues/4476))
- Remove deprecated --process-dependency-links option from UPGRADE.rst ([\#4485](https://github.com/matrix-org/synapse/issues/4485))
- Make it possible to set the log level for tests via an environment variable ([\#4506](https://github.com/matrix-org/synapse/issues/4506))
- Reduce the log level of linearizer lock acquirement to DEBUG. ([\#4507](https://github.com/matrix-org/synapse/issues/4507))
- Fix code to comply with linting in PyFlakes 3.7.1. ([\#4519](https://github.com/matrix-org/synapse/issues/4519))
- Add some debug for membership syncing issues ([\#4538](https://github.com/matrix-org/synapse/issues/4538))
- Docker: only copy what we need to the build image ([\#4562](https://github.com/matrix-org/synapse/issues/4562))


Synapse 0.34.1.1 (2019-01-11)
=============================

This release fixes CVE-2019-5885 and is recommended for all users of Synapse 0.34.1.

This release is compatible with Python 2.7 and 3.5+. Python 3.7 is fully supported.

Bugfixes
--------

- Fix spontaneous logout on upgrade
  ([\#4374](https://github.com/matrix-org/synapse/issues/4374))


Synapse 0.34.1 (2019-01-09)
===========================

Internal Changes
----------------

- Add better logging for unexpected errors while sending transactions ([\#4361](https://github.com/matrix-org/synapse/issues/4361), [\#4362](https://github.com/matrix-org/synapse/issues/4362))


Synapse 0.34.1rc1 (2019-01-08)
==============================

Features
--------

- Special-case a support user for use in verifying behaviour of a given server. The support user does not appear in user directory or monthly active user counts. ([\#4141](https://github.com/matrix-org/synapse/issues/4141), [\#4344](https://github.com/matrix-org/synapse/issues/4344))
- Support for serving .well-known files ([\#4262](https://github.com/matrix-org/synapse/issues/4262))
- Rework SAML2 authentication ([\#4265](https://github.com/matrix-org/synapse/issues/4265), [\#4267](https://github.com/matrix-org/synapse/issues/4267))
- SAML2 authentication: Initialise user display name from SAML2 data ([\#4272](https://github.com/matrix-org/synapse/issues/4272))
- Synapse can now have its conditional/extra dependencies installed by pip. This functionality can be used by using `pip install matrix-synapse[feature]`, where feature is a comma separated list with the possible values `email.enable_notifs`, `matrix-synapse-ldap3`, `postgres`, `resources.consent`, `saml2`, `url_preview`, and `test`. If you want to install all optional dependencies, you can use "all" instead. ([\#4298](https://github.com/matrix-org/synapse/issues/4298), [\#4325](https://github.com/matrix-org/synapse/issues/4325), [\#4327](https://github.com/matrix-org/synapse/issues/4327))
- Add routes for reading account data. ([\#4303](https://github.com/matrix-org/synapse/issues/4303))
- Add opt-in support for v2 rooms ([\#4307](https://github.com/matrix-org/synapse/issues/4307))
- Add a script to generate a clean config file ([\#4315](https://github.com/matrix-org/synapse/issues/4315))
- Return server data in /login response ([\#4319](https://github.com/matrix-org/synapse/issues/4319))


Bugfixes
--------

- Fix contains_url check to be consistent with other instances in code-base and check that value is an instance of string. ([\#3405](https://github.com/matrix-org/synapse/issues/3405))
- Fix CAS login when username is not valid in an MXID ([\#4264](https://github.com/matrix-org/synapse/issues/4264))
- Send CORS headers for /media/config ([\#4279](https://github.com/matrix-org/synapse/issues/4279))
- Add 'sandbox' to CSP for media reprository ([\#4284](https://github.com/matrix-org/synapse/issues/4284))
- Make the new landing page prettier. ([\#4294](https://github.com/matrix-org/synapse/issues/4294))
- Fix deleting E2E room keys when using old SQLite versions. ([\#4295](https://github.com/matrix-org/synapse/issues/4295))
- The metric synapse_admin_mau:current previously did not update when config.mau_stats_only was set to True ([\#4305](https://github.com/matrix-org/synapse/issues/4305))
- Fixed per-room account data filters ([\#4309](https://github.com/matrix-org/synapse/issues/4309))
- Fix indentation in default config ([\#4313](https://github.com/matrix-org/synapse/issues/4313))
- Fix synapse:latest docker upload ([\#4316](https://github.com/matrix-org/synapse/issues/4316))
- Fix test_metric.py compatibility with prometheus_client 0.5. Contributed by Maarten de Vries <maarten@de-vri.es>. ([\#4317](https://github.com/matrix-org/synapse/issues/4317))
- Avoid packaging _trial_temp directory in -py3 debian packages ([\#4326](https://github.com/matrix-org/synapse/issues/4326))
- Check jinja version for consent resource ([\#4327](https://github.com/matrix-org/synapse/issues/4327))
- fix NPE in /messages by checking if all events were filtered out ([\#4330](https://github.com/matrix-org/synapse/issues/4330))
- Fix `python -m synapse.config` on Python 3. ([\#4356](https://github.com/matrix-org/synapse/issues/4356))


Deprecations and Removals
-------------------------

- Remove the deprecated v1/register API on Python 2. It was never ported to Python 3. ([\#4334](https://github.com/matrix-org/synapse/issues/4334))


Internal Changes
----------------

- Getting URL previews of IP addresses no longer fails on Python 3. ([\#4215](https://github.com/matrix-org/synapse/issues/4215))
- drop undocumented dependency on dateutil ([\#4266](https://github.com/matrix-org/synapse/issues/4266))
- Update the example systemd config to use a virtualenv ([\#4273](https://github.com/matrix-org/synapse/issues/4273))
- Update link to kernel DCO guide ([\#4274](https://github.com/matrix-org/synapse/issues/4274))
- Make isort tox check print diff when it fails ([\#4283](https://github.com/matrix-org/synapse/issues/4283))
- Log room_id in Unknown room errors ([\#4297](https://github.com/matrix-org/synapse/issues/4297))
- Documentation improvements for coturn setup. Contributed by Krithin Sitaram. ([\#4333](https://github.com/matrix-org/synapse/issues/4333))
- Update pull request template to use absolute links ([\#4341](https://github.com/matrix-org/synapse/issues/4341))
- Update README to not lie about required restart when updating TLS certificates ([\#4343](https://github.com/matrix-org/synapse/issues/4343))
- Update debian packaging for compatibility with transitional package ([\#4349](https://github.com/matrix-org/synapse/issues/4349))
- Fix command hint to generate a config file when trying to start without a config file ([\#4353](https://github.com/matrix-org/synapse/issues/4353))
- Add better logging for unexpected errors while sending transactions ([\#4358](https://github.com/matrix-org/synapse/issues/4358))


Synapse 0.34.0 (2018-12-20)
===========================

Synapse 0.34.0 is the first release to fully support Python 3. Synapse will now
run on Python versions 3.5 or 3.6 (as well as 2.7). Support for Python 3.7
remains experimental.

We recommend upgrading to Python 3, but make sure to read the [upgrade
notes](docs/upgrade.md#upgrading-to-v0340) when doing so.

Features
--------

- Add 'sandbox' to CSP for media reprository ([\#4284](https://github.com/matrix-org/synapse/issues/4284))
- Make the new landing page prettier. ([\#4294](https://github.com/matrix-org/synapse/issues/4294))
- Fix deleting E2E room keys when using old SQLite versions. ([\#4295](https://github.com/matrix-org/synapse/issues/4295))
- Add a welcome page for the client API port. Credit to @krombel! ([\#4289](https://github.com/matrix-org/synapse/issues/4289))
- Remove Matrix console from the default distribution ([\#4290](https://github.com/matrix-org/synapse/issues/4290))
- Add option to track MAU stats (but not limit people) ([\#3830](https://github.com/matrix-org/synapse/issues/3830))
- Add an option to enable recording IPs for appservice users ([\#3831](https://github.com/matrix-org/synapse/issues/3831))
- Rename login type `m.login.cas` to `m.login.sso` ([\#4220](https://github.com/matrix-org/synapse/issues/4220))
- Add an option to disable search for homeservers that may not be interested in it. ([\#4230](https://github.com/matrix-org/synapse/issues/4230))


Bugfixes
--------

- Pushrules can now again be made with non-ASCII rule IDs. ([\#4165](https://github.com/matrix-org/synapse/issues/4165))
- The media repository now no longer fails to decode UTF-8 filenames when downloading remote media. ([\#4176](https://github.com/matrix-org/synapse/issues/4176))
- URL previews now correctly decode non-UTF-8 text if the header contains a `<meta http-equiv="Content-Type"` header. ([\#4183](https://github.com/matrix-org/synapse/issues/4183))
- Fix an issue where public consent URLs had two slashes. ([\#4192](https://github.com/matrix-org/synapse/issues/4192))
- Fallback auth now accepts the session parameter on Python 3. ([\#4197](https://github.com/matrix-org/synapse/issues/4197))
- Remove riot.im from the list of trusted Identity Servers in the default configuration ([\#4207](https://github.com/matrix-org/synapse/issues/4207))
- fix start up failure when mau_limit_reserved_threepids set and db is postgres ([\#4211](https://github.com/matrix-org/synapse/issues/4211))
- Fix auto join failures for servers that require user consent ([\#4223](https://github.com/matrix-org/synapse/issues/4223))
- Fix exception caused by non-ascii event IDs ([\#4241](https://github.com/matrix-org/synapse/issues/4241))
- Pushers can now be unsubscribed from on Python 3. ([\#4250](https://github.com/matrix-org/synapse/issues/4250))
- Fix UnicodeDecodeError when postgres is configured to give non-English errors ([\#4253](https://github.com/matrix-org/synapse/issues/4253))


Internal Changes
----------------

- Debian packages utilising a virtualenv with bundled dependencies can now be built. ([\#4212](https://github.com/matrix-org/synapse/issues/4212))
- Disable pager when running git-show in CI ([\#4291](https://github.com/matrix-org/synapse/issues/4291))
- A coveragerc file has been added. ([\#4180](https://github.com/matrix-org/synapse/issues/4180))
- Add a GitHub pull request template and add multiple issue templates ([\#4182](https://github.com/matrix-org/synapse/issues/4182))
- Update README to reflect the fact that [\#1491](https://github.com/matrix-org/synapse/issues/1491) is fixed ([\#4188](https://github.com/matrix-org/synapse/issues/4188))
- Run the AS senders as background processes to fix warnings ([\#4189](https://github.com/matrix-org/synapse/issues/4189))
- Add some diagnostics to the tests to detect logcontext problems ([\#4190](https://github.com/matrix-org/synapse/issues/4190))
- Add missing `jpeg` package prerequisite for OpenBSD in README. ([\#4193](https://github.com/matrix-org/synapse/issues/4193))
- Add a note saying you need to manually reclaim disk space after using the Purge History API ([\#4200](https://github.com/matrix-org/synapse/issues/4200))
- More logcontext checking in unittests ([\#4205](https://github.com/matrix-org/synapse/issues/4205))
- Ignore `__pycache__` directories in the database schema folder ([\#4214](https://github.com/matrix-org/synapse/issues/4214))
- Add note to UPGRADE.rst about removing riot.im from list of trusted identity servers ([\#4224](https://github.com/matrix-org/synapse/issues/4224))
- Added automated coverage reporting to CI. ([\#4225](https://github.com/matrix-org/synapse/issues/4225))
- Garbage-collect after each unit test to fix logcontext leaks ([\#4227](https://github.com/matrix-org/synapse/issues/4227))
- add more detail to logging regarding "More than one row matched" error ([\#4234](https://github.com/matrix-org/synapse/issues/4234))
- Drop sent_transactions table ([\#4244](https://github.com/matrix-org/synapse/issues/4244))
- Add a basic .editorconfig ([\#4257](https://github.com/matrix-org/synapse/issues/4257))
- Update README.rst and UPGRADE.rst for Python 3. ([\#4260](https://github.com/matrix-org/synapse/issues/4260))
- Remove obsolete `verbose` and `log_file` settings from `homeserver.yaml` for Docker image. ([\#4261](https://github.com/matrix-org/synapse/issues/4261))


Synapse 0.33.9 (2018-11-19)
===========================

No significant changes.


Synapse 0.33.9rc1 (2018-11-14)
==============================

Features
--------

- Include flags to optionally add `m.login.terms` to the registration flow when consent tracking is enabled. ([\#4004](https://github.com/matrix-org/synapse/issues/4004), [\#4133](https://github.com/matrix-org/synapse/issues/4133), [\#4142](https://github.com/matrix-org/synapse/issues/4142), [\#4184](https://github.com/matrix-org/synapse/issues/4184))
- Support for replacing rooms with new ones ([\#4091](https://github.com/matrix-org/synapse/issues/4091), [\#4099](https://github.com/matrix-org/synapse/issues/4099), [\#4100](https://github.com/matrix-org/synapse/issues/4100), [\#4101](https://github.com/matrix-org/synapse/issues/4101))


Bugfixes
--------

- Fix exceptions when using the email mailer on Python 3. ([\#4095](https://github.com/matrix-org/synapse/issues/4095))
- Fix e2e key backup with more than 9 backup versions ([\#4113](https://github.com/matrix-org/synapse/issues/4113))
- Searches that request profile info now no longer fail with a 500. ([\#4122](https://github.com/matrix-org/synapse/issues/4122))
- fix return code of empty key backups ([\#4123](https://github.com/matrix-org/synapse/issues/4123))
- If the typing stream ID goes backwards (as on a worker when the master restarts), the worker's typing handler will no longer erroneously report rooms containing new typing events. ([\#4127](https://github.com/matrix-org/synapse/issues/4127))
- Fix table lock of device_lists_remote_cache which could freeze the application ([\#4132](https://github.com/matrix-org/synapse/issues/4132))
- Fix exception when using state res v2 algorithm ([\#4135](https://github.com/matrix-org/synapse/issues/4135))
- Generating the user consent URI no longer fails on Python 3. ([\#4140](https://github.com/matrix-org/synapse/issues/4140), [\#4163](https://github.com/matrix-org/synapse/issues/4163))
- Loading URL previews from the DB cache on Postgres will no longer cause Unicode type errors when responding to the request, and URL previews will no longer fail if the remote server returns a Content-Type header with the chartype in quotes. ([\#4157](https://github.com/matrix-org/synapse/issues/4157))
- The hash_password script now works on Python 3. ([\#4161](https://github.com/matrix-org/synapse/issues/4161))
- Fix noop checks when updating device keys, reducing spurious device list update notifications. ([\#4164](https://github.com/matrix-org/synapse/issues/4164))


Deprecations and Removals
-------------------------

- The disused and un-specced identicon generator has been removed. ([\#4106](https://github.com/matrix-org/synapse/issues/4106))
- The obsolete and non-functional /pull federation endpoint has been removed. ([\#4118](https://github.com/matrix-org/synapse/issues/4118))
- The deprecated v1 key exchange endpoints have been removed. ([\#4119](https://github.com/matrix-org/synapse/issues/4119))
- Synapse will no longer fetch keys using the fallback deprecated v1 key exchange method and will now always use v2. ([\#4120](https://github.com/matrix-org/synapse/issues/4120))


Internal Changes
----------------

- Fix build of Docker image with docker-compose ([\#3778](https://github.com/matrix-org/synapse/issues/3778))
- Delete unreferenced state groups during history purge ([\#4006](https://github.com/matrix-org/synapse/issues/4006))
- The "Received rdata" log messages on workers is now logged at DEBUG, not INFO. ([\#4108](https://github.com/matrix-org/synapse/issues/4108))
- Reduce replication traffic for device lists ([\#4109](https://github.com/matrix-org/synapse/issues/4109))
- Fix `synapse_replication_tcp_protocol_*_commands` metric label to be full command name, rather than just the first character ([\#4110](https://github.com/matrix-org/synapse/issues/4110))
- Log some bits about room creation ([\#4121](https://github.com/matrix-org/synapse/issues/4121))
- Fix `tox` failure on old systems ([\#4124](https://github.com/matrix-org/synapse/issues/4124))
- Add STATE_V2_TEST room version ([\#4128](https://github.com/matrix-org/synapse/issues/4128))
- Clean up event accesses and tests ([\#4137](https://github.com/matrix-org/synapse/issues/4137))
- The default logging config will now set an explicit log file encoding of UTF-8. ([\#4138](https://github.com/matrix-org/synapse/issues/4138))
- Add helpers functions for getting prev and auth events of an event ([\#4139](https://github.com/matrix-org/synapse/issues/4139))
- Add some tests for the HTTP pusher. ([\#4149](https://github.com/matrix-org/synapse/issues/4149))
- add purge_history.sh and purge_remote_media.sh scripts to contrib/ ([\#4155](https://github.com/matrix-org/synapse/issues/4155))
- HTTP tests have been refactored to contain less boilerplate. ([\#4156](https://github.com/matrix-org/synapse/issues/4156))
- Drop incoming events from federation for unknown rooms ([\#4165](https://github.com/matrix-org/synapse/issues/4165))


Synapse 0.33.8 (2018-11-01)
===========================

No significant changes.


Synapse 0.33.8rc2 (2018-10-31)
==============================

Bugfixes
--------

- Searches that request profile info now no longer fail with a 500. Fixes
  a regression in 0.33.8rc1. ([\#4122](https://github.com/matrix-org/synapse/issues/4122))


Synapse 0.33.8rc1 (2018-10-29)
==============================

Features
--------

- Servers with auto-join rooms will now automatically create those rooms when the first user registers ([\#3975](https://github.com/matrix-org/synapse/issues/3975))
- Add config option to control alias creation ([\#4051](https://github.com/matrix-org/synapse/issues/4051))
- The register_new_matrix_user script is now ported to Python 3. ([\#4085](https://github.com/matrix-org/synapse/issues/4085))
- Configure Docker image to listen on both ipv4 and ipv6. ([\#4089](https://github.com/matrix-org/synapse/issues/4089))


Bugfixes
--------

- Fix HTTP error response codes for federated group requests. ([\#3969](https://github.com/matrix-org/synapse/issues/3969))
- Fix issue where Python 3 users couldn't paginate /publicRooms ([\#4046](https://github.com/matrix-org/synapse/issues/4046))
- Fix URL previewing to work in Python 3.7 ([\#4050](https://github.com/matrix-org/synapse/issues/4050))
- synctl will use the right python executable to run worker processes ([\#4057](https://github.com/matrix-org/synapse/issues/4057))
- Manhole now works again on Python 3, instead of failing with a "couldn't match all kex parts" when connecting. ([\#4060](https://github.com/matrix-org/synapse/issues/4060), [\#4067](https://github.com/matrix-org/synapse/issues/4067))
- Fix some metrics being racy and causing exceptions when polled by Prometheus. ([\#4061](https://github.com/matrix-org/synapse/issues/4061))
- Fix bug which prevented email notifications from being sent unless an absolute path was given for `email_templates`. ([\#4068](https://github.com/matrix-org/synapse/issues/4068))
- Correctly account for cpu usage by background threads ([\#4074](https://github.com/matrix-org/synapse/issues/4074))
- Fix race condition where config defined reserved users were not being added to
  the monthly active user list prior to the homeserver reactor firing up ([\#4081](https://github.com/matrix-org/synapse/issues/4081))
- Fix bug which prevented backslashes being used in event field filters ([\#4083](https://github.com/matrix-org/synapse/issues/4083))


Internal Changes
----------------

- Add information about the [matrix-docker-ansible-deploy](https://github.com/spantaleev/matrix-docker-ansible-deploy) playbook ([\#3698](https://github.com/matrix-org/synapse/issues/3698))
- Add initial implementation of new state resolution algorithm ([\#3786](https://github.com/matrix-org/synapse/issues/3786))
- Reduce database load when fetching state groups ([\#4011](https://github.com/matrix-org/synapse/issues/4011))
- Various cleanups in the federation client code ([\#4031](https://github.com/matrix-org/synapse/issues/4031))
- Run the CircleCI builds in docker containers ([\#4041](https://github.com/matrix-org/synapse/issues/4041))
- Only colourise synctl output when attached to tty ([\#4049](https://github.com/matrix-org/synapse/issues/4049))
- Refactor room alias creation code ([\#4063](https://github.com/matrix-org/synapse/issues/4063))
- Make the Python scripts in the top-level scripts folders meet pep8 and pass flake8. ([\#4068](https://github.com/matrix-org/synapse/issues/4068))
- The README now contains example for the Caddy web server. Contributed by steamp0rt. ([\#4072](https://github.com/matrix-org/synapse/issues/4072))
- Add psutil as an explicit dependency ([\#4073](https://github.com/matrix-org/synapse/issues/4073))
- Clean up threading and logcontexts in pushers ([\#4075](https://github.com/matrix-org/synapse/issues/4075))
- Correctly manage logcontexts during startup to fix some "Unexpected logging context" warnings ([\#4076](https://github.com/matrix-org/synapse/issues/4076))
- Give some more things logcontexts ([\#4077](https://github.com/matrix-org/synapse/issues/4077))
- Clean up some bits of code which were flagged by the linter ([\#4082](https://github.com/matrix-org/synapse/issues/4082))


Synapse 0.33.7 (2018-10-18)
===========================

**Warning**: This release removes the example email notification templates from
`res/templates` (they are now internal to the python package). This should only
affect you if you (a) deploy your Synapse instance from a git checkout or a
github snapshot URL, and (b) have email notifications enabled.

If you have email notifications enabled, you should ensure that
`email.template_dir` is either configured to point at a directory where you
have installed customised templates, or leave it unset to use the default
templates.

Synapse 0.33.7rc2 (2018-10-17)
==============================

Features
--------

- Ship the example email templates as part of the package ([\#4052](https://github.com/matrix-org/synapse/issues/4052))

Bugfixes
--------

- Fix bug which made get_missing_events return too few events ([\#4045](https://github.com/matrix-org/synapse/issues/4045))


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
- Replaced all occurrences of e.message with str(e). Contributed by Schnuffle ([\#3970](https://github.com/matrix-org/synapse/issues/3970))
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
- Fix spurious exceptions when remote http client closes connection ([\#3925](https://github.com/matrix-org/synapse/issues/3925))
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
- fix VOIP crashes under Python 3 (issue [\#3821](https://github.com/matrix-org/synapse/issues/3821)). ([\#3835](https://github.com/matrix-org/synapse/issues/3835))
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
- Fix mau blocking calculation bug on login ([\#3689](https://github.com/matrix-org/synapse/issues/3689))
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
- Respond with M_NOT_FOUND when profiles are not found locally or over federation. Fixes [\#3585](https://github.com/matrix-org/synapse/issues/3585). ([\#3585](https://github.com/matrix-org/synapse/issues/3585))
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

-   Enforce the specified API for `report_event`. ([\#3316](https://github.com/matrix-org/synapse/issues/3316))
-   Include CPU time from database threads in request/block metrics. ([\#3496](https://github.com/matrix-org/synapse/issues/3496), [\#3501](https://github.com/matrix-org/synapse/issues/3501))
-   Add CPU metrics for `_fetch_event_list`. ([\#3497](https://github.com/matrix-org/synapse/issues/3497))
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
-   Add optional `ip_range_whitelist` param to AS registration files to lock AS IP access ([\#3465](https://github.com/matrix-org/synapse/issues/3465))
-   Reject invalid server names in federation requests ([\#3480](https://github.com/matrix-org/synapse/issues/3480))
-   Reject invalid server names in homeserver.yaml ([\#3483](https://github.com/matrix-org/synapse/issues/3483))

Bugfixes
--------

-   Strip `access_token` from outgoing requests ([\#3327](https://github.com/matrix-org/synapse/issues/3327))
-   Redact AS tokens in logs ([\#3349](https://github.com/matrix-org/synapse/issues/3349))
-   Fix federation backfill from SQLite servers ([\#3355](https://github.com/matrix-org/synapse/issues/3355))
-   Fix event-purge-by-ts admin API ([\#3363](https://github.com/matrix-org/synapse/issues/3363))
-   Fix event filtering in `get_missing_events` handler ([\#3371](https://github.com/matrix-org/synapse/issues/3371))
-   Synapse is now stricter regarding accepting events which it cannot retrieve the `prev_events` for. ([\#3456](https://github.com/matrix-org/synapse/issues/3456))
-   Fix bug where synapse would explode when receiving unicode in HTTP User-Agent header ([\#3470](https://github.com/matrix-org/synapse/issues/3470))
-   Invalidate cache on correct thread to avoid race ([\#3473](https://github.com/matrix-org/synapse/issues/3473))

Improved Documentation
----------------------

-   `doc/postgres.rst`: fix display of the last command block. Thanks to @ArchangeGabriel! ([\#3340](https://github.com/matrix-org/synapse/issues/3340))

Deprecations and Removals
-------------------------

-   Remove `was_forgotten_at` ([\#3324](https://github.com/matrix-org/synapse/issues/3324))

Misc
----

-   [\#3332](https://github.com/matrix-org/synapse/issues/3332), [\#3341](https://github.com/matrix-org/synapse/issues/3341), [\#3347](https://github.com/matrix-org/synapse/issues/3347), [\#3348](https://github.com/matrix-org/synapse/issues/3348), [\#3356](https://github.com/matrix-org/synapse/issues/3356), [\#3385](https://github.com/matrix-org/synapse/issues/3385), [\#3446](https://github.com/matrix-org/synapse/issues/3446), [\#3447](https://github.com/matrix-org/synapse/issues/3447), [\#3467](https://github.com/matrix-org/synapse/issues/3467), [\#3474](https://github.com/matrix-org/synapse/issues/3474)

Changes in synapse v0.31.2 (2018-06-14)
=======================================

SECURITY UPDATE: Prevent unauthorised users from setting state events in a room when there is no `m.room.power_levels` event in force in the room. ([\#3397](https://github.com/matrix-org/synapse/issues/3397))

Discussion around the Matrix Spec change proposal for this change can be followed at <https://github.com/matrix-org/matrix-doc/issues/1304>.

Changes in synapse v0.31.1 (2018-06-08)
=======================================

v0.31.1 fixes a security bug in the `get_missing_events` federation API where event visibility rules were not applied correctly.

We are not aware of it being actively exploited but please upgrade asap.

Bug Fixes:

-   Fix event filtering in `get_missing_events` handler. ([\#3371](https://github.com/matrix-org/synapse/issues/3371))

Changes in synapse v0.31.0 (2018-06-06)
=======================================

Most notable change from v0.30.0 is to switch to the python prometheus library to improve system stats reporting. WARNING: this changes a number of prometheus metrics in a backwards-incompatible manner. For more details, see [docs/metrics-howto.rst](docs/metrics-howto.rst#removal-of-deprecated-metrics--time-based-counters-becoming-histograms-in-0310).

Bug Fixes:

-   Fix metric documentation tables. ([\#3341](https://github.com/matrix-org/synapse/issues/3341))
-   Fix LaterGauge error handling (694968f)
-   Fix replication metrics (b7e7fd2)

Changes in synapse v0.31.0-rc1 (2018-06-04)
===========================================

Features:

-   Switch to the Python Prometheus library. ([\#3256](https://github.com/matrix-org/synapse/issues/3256), [\#3274](https://github.com/matrix-org/synapse/issues/3274))
-   Let users leave the server notice room after joining. ([\#3287](https://github.com/matrix-org/synapse/issues/3287))

Changes:

-   daily user type phone home stats. ([\#3264](https://github.com/matrix-org/synapse/issues/3264))
-   Use `iter*` methods for `_filter_events_for_server`. ([\#3267](https://github.com/matrix-org/synapse/issues/3267))
-   Docs on consent bits. ([\#3268](https://github.com/matrix-org/synapse/issues/3268))
-   Remove users from user directory on deactivate. ([\#3277](https://github.com/matrix-org/synapse/issues/3277))
-   Avoid sending consent notice to guest users. ([\#3288](https://github.com/matrix-org/synapse/issues/3288))
-   disable CPUMetrics if no /proc/self/stat. ([\#3299](https://github.com/matrix-org/synapse/issues/3299))
-   Consistently use six's iteritems and wrap lazy keys/values in list() if they're not meant to be lazy. ([\#3307](https://github.com/matrix-org/synapse/issues/3307))
-   Add private IPv6 addresses to example config for url preview blacklist. Thanks to @thegcat! ([\#3317](https://github.com/matrix-org/synapse/issues/3317))
-   Reduce stuck read-receipts: ignore depth when updating. ([\#3318](https://github.com/matrix-org/synapse/issues/3318))
-   Put python's logs into Trial when running unit tests. ([\#3319](https://github.com/matrix-org/synapse/issues/3319))

Changes, python 3 migration:

-   Replace some more comparisons with six. Thanks to @NotAFile! ([\#3243](https://github.com/matrix-org/synapse/issues/3243))
-   replace some iteritems with six. Thanks to @NotAFile! ([\#3244](https://github.com/matrix-org/synapse/issues/3244))
-   Add `batch_iter` to utils. Thanks to @NotAFile! ([\#3245](https://github.com/matrix-org/synapse/issues/3245))
-   use repr, not str. Thanks to @NotAFile! ([\#3246](https://github.com/matrix-org/synapse/issues/3246))
-   Misc Python3 fixes. Thanks to @NotAFile! ([\#3247](https://github.com/matrix-org/synapse/issues/3247))
-   Py3 `storage/_base.py`. Thanks to @NotAFile! ([\#3278](https://github.com/matrix-org/synapse/issues/3278))
-   more six iteritems. Thanks to @NotAFile! ([\#3279](https://github.com/matrix-org/synapse/issues/3279))
-   More Misc. py3 fixes. Thanks to @NotAFile! ([\#3280](https://github.com/matrix-org/synapse/issues/3280))
-   remaining isintance fixes. Thanks to @NotAFile! ([\#3281](https://github.com/matrix-org/synapse/issues/3281))
-   py3-ize state.py. Thanks to @NotAFile! ([\#3283](https://github.com/matrix-org/synapse/issues/3283))
-   extend tox testing for py3 to avoid regressions. Thanks to @krombel! ([\#3302](https://github.com/matrix-org/synapse/issues/3302))
-   use memoryview in py3. Thanks to @NotAFile! ([\#3303](https://github.com/matrix-org/synapse/issues/3303))

Bugs:

-   Fix federation backfill bugs. ([\#3261](https://github.com/matrix-org/synapse/issues/3261))
-   federation: fix LaterGauge usage. Thanks to @intelfx! ([\#3328](https://github.com/matrix-org/synapse/issues/3328))

Changes in synapse v0.30.0 (2018-05-24)
=======================================

"Server Notices" are a new feature introduced in Synapse 0.30. They provide a channel whereby server administrators can send messages to users on the server.

They are used as part of communication of the server policies (see `docs/consent_tracking.md`), however the intention is that they may also find a use for features such as "Message of the day".

This feature is specific to Synapse, but uses standard Matrix communication mechanisms, so should work with any Matrix client. For more details see `docs/server_notices.md`

Further Server Notices/Consent Tracking Support:

-   Allow overriding the `server_notices` user's avatar. ([\#3273](https://github.com/matrix-org/synapse/issues/3273))
-   Use the localpart in the consent uri. ([\#3272](https://github.com/matrix-org/synapse/issues/3272))
-   Support for putting `%(consent_uri)s` in messages. ([\#3271](https://github.com/matrix-org/synapse/issues/3271))
-   Block attempts to send server notices to remote users. ([\#3270](https://github.com/matrix-org/synapse/issues/3270))
-   Docs on consent bits. ([\#3268](https://github.com/matrix-org/synapse/issues/3268))

Changes in synapse v0.30.0-rc1 (2018-05-23)
===========================================

Server Notices/Consent Tracking Support:

-   ConsentResource to gather policy consent from users. ([\#3213](https://github.com/matrix-org/synapse/issues/3213))
-   Move RoomCreationHandler out of synapse.handlers.Handlers. ([\#3225](https://github.com/matrix-org/synapse/issues/3225))
-   Infrastructure for a server notices room. ([\#3232](https://github.com/matrix-org/synapse/issues/3232))
-   Send users a server notice about consent. ([\#3236](https://github.com/matrix-org/synapse/issues/3236))
-   Reject attempts to send event before privacy consent is given. ([\#3257](https://github.com/matrix-org/synapse/issues/3257))
-   Add a `has_consented` template var to consent forms. ([\#3262](https://github.com/matrix-org/synapse/issues/3262))
-   Fix dependency on jinja2. ([\#3263](https://github.com/matrix-org/synapse/issues/3263))

Features:

-   Cohort analytics. ([\#3163](https://github.com/matrix-org/synapse/issues/3163), [\#3241](https://github.com/matrix-org/synapse/issues/3241), [\#3251](https://github.com/matrix-org/synapse/issues/3251))
-   Add lxml to docker image for web previews. Thanks to @ptman! ([\#3239](https://github.com/matrix-org/synapse/issues/3239))
-   Add in flight request metrics. ([\#3252](https://github.com/matrix-org/synapse/issues/3252))

Changes:

-   Remove unused `update_external_syncs`. ([\#3233](https://github.com/matrix-org/synapse/issues/3233))
-   Use stream rather depth ordering for push actions. ([\#3212](https://github.com/matrix-org/synapse/issues/3212))
-   Make `purge_history` operate on tokens. ([\#3221](https://github.com/matrix-org/synapse/issues/3221))
-   Don't support limitless pagination. ([\#3265](https://github.com/matrix-org/synapse/issues/3265))

Bug Fixes:

-   Fix logcontext resource usage tracking. ([\#3258](https://github.com/matrix-org/synapse/issues/3258))
-   Fix error in handling receipts. ([\#3235](https://github.com/matrix-org/synapse/issues/3235))
-   Stop the transaction cache caching failures. ([\#3255](https://github.com/matrix-org/synapse/issues/3255))

Changes in synapse v0.29.1 (2018-05-17)
=======================================

Changes:

-   Update docker documentation. ([\#3222](https://github.com/matrix-org/synapse/issues/3222))

Changes in synapse v0.29.0 (2018-05-16)
=======================================

Not changes since v0.29.0-rc1

Changes in synapse v0.29.0-rc1 (2018-05-14)
===========================================

Notable changes, a docker file for running Synapse (Thanks to @kaiyou!) and a closed spec bug in the Client Server API. Additionally further prep for Python 3 migration.

Potentially breaking change:

-   Make Client-Server API return 401 for invalid token. ([\#3161](https://github.com/matrix-org/synapse/issues/3161))

    This changes the Client-server spec to return a 401 error code instead of 403 when the access token is unrecognised. This is the behaviour required by the specification, but some clients may be relying on the old, incorrect behaviour.

    Thanks to @NotAFile for fixing this.

Features:

-   Add a Dockerfile for synapse. Thanks to @kaiyou! ([\#2846](https://github.com/matrix-org/synapse/issues/2846))

Changes - General:

-   nuke-room-from-db.sh: added postgresql option and help. Thanks to @rubo77! ([\#2337](https://github.com/matrix-org/synapse/issues/2337))
-   Part user from rooms on account deactivate. ([\#3201](https://github.com/matrix-org/synapse/issues/3201))
-   Make "unexpected logging context" into warnings. ([\#3007](https://github.com/matrix-org/synapse/issues/3007))
-   Set Server header in SynapseRequest. ([\#3208](https://github.com/matrix-org/synapse/issues/3208))
-   remove duplicates from groups tables. ([\#3129](https://github.com/matrix-org/synapse/issues/3129))
-   Improve exception handling for background processes. ([\#3138](https://github.com/matrix-org/synapse/issues/3138))
-   Add missing consumeErrors to improve exception handling. ([\#3139](https://github.com/matrix-org/synapse/issues/3139))
-   reraise exceptions more carefully. ([\#3142](https://github.com/matrix-org/synapse/issues/3142))
-   Remove redundant call to `preserve_fn`. ([\#3143](https://github.com/matrix-org/synapse/issues/3143))
-   Trap exceptions thrown within `run_in_background`. ([\#3144](https://github.com/matrix-org/synapse/issues/3144))

Changes - Refactors:

-   Refactor /context to reuse pagination storage functions. ([\#3193](https://github.com/matrix-org/synapse/issues/3193))
-   Refactor recent events func to use pagination func. ([\#3195](https://github.com/matrix-org/synapse/issues/3195))
-   Refactor pagination DB API to return concrete type. ([\#3196](https://github.com/matrix-org/synapse/issues/3196))
-   Refactor `get_recent_events_for_room` return type. ([\#3198](https://github.com/matrix-org/synapse/issues/3198))
-   Refactor sync APIs to reuse pagination API. ([\#3199](https://github.com/matrix-org/synapse/issues/3199))
-   Remove unused code path from member change DB func. ([\#3200](https://github.com/matrix-org/synapse/issues/3200))
-   Refactor request handling wrappers. ([\#3203](https://github.com/matrix-org/synapse/issues/3203))
-   `transaction_id`, destination defined twice. Thanks to @damir-manapov! ([\#3209](https://github.com/matrix-org/synapse/issues/3209))
-   Refactor event storage to prepare for changes in state calculations. ([\#3141](https://github.com/matrix-org/synapse/issues/3141))
-   Set Server header in SynapseRequest. ([\#3208](https://github.com/matrix-org/synapse/issues/3208))
-   Use deferred.addTimeout instead of `time_bound_deferred`. ([\#3127](https://github.com/matrix-org/synapse/issues/3127), [\#3178](https://github.com/matrix-org/synapse/issues/3178))
-   Use `run_in_background` in preference to `preserve_fn`. ([\#3140](https://github.com/matrix-org/synapse/issues/3140))

Changes - Python 3 migration:

-   Construct HMAC as bytes on py3. Thanks to @NotAFile! ([\#3156](https://github.com/matrix-org/synapse/issues/3156))
-   run config tests on py3. Thanks to @NotAFile! ([\#3159](https://github.com/matrix-org/synapse/issues/3159))
-   Open certificate files as bytes. Thanks to @NotAFile! ([\#3084](https://github.com/matrix-org/synapse/issues/3084))
-   Open config file in non-bytes mode. Thanks to @NotAFile! ([\#3085](https://github.com/matrix-org/synapse/issues/3085))
-   Make event properties raise AttributeError instead. Thanks to @NotAFile! ([\#3102](https://github.com/matrix-org/synapse/issues/3102))
-   Use six.moves.urlparse. Thanks to @NotAFile! ([\#3108](https://github.com/matrix-org/synapse/issues/3108))
-   Add py3 tests to tox with folders that work. Thanks to @NotAFile! ([\#3145](https://github.com/matrix-org/synapse/issues/3145))
-   Don't yield in list comprehensions. Thanks to @NotAFile! ([\#3150](https://github.com/matrix-org/synapse/issues/3150))
-   Move more xrange to six. Thanks to @NotAFile! ([\#3151](https://github.com/matrix-org/synapse/issues/3151))
-   make imports local. Thanks to @NotAFile! ([\#3152](https://github.com/matrix-org/synapse/issues/3152))
-   move httplib import to six. Thanks to @NotAFile! ([\#3153](https://github.com/matrix-org/synapse/issues/3153))
-   Replace stringIO imports with six. Thanks to @NotAFile! ([\#3154](https://github.com/matrix-org/synapse/issues/3154), [\#3168](https://github.com/matrix-org/synapse/issues/3168))
-   more bytes strings. Thanks to @NotAFile! ([\#3155](https://github.com/matrix-org/synapse/issues/3155))

Bug Fixes:

-   synapse fails to start under Twisted >= 18.4. ([\#3157](https://github.com/matrix-org/synapse/issues/3157))
-   Fix a class of logcontext leaks. ([\#3170](https://github.com/matrix-org/synapse/issues/3170))
-   Fix a couple of logcontext leaks in unit tests. ([\#3172](https://github.com/matrix-org/synapse/issues/3172))
-   Fix logcontext leak in media repo. ([\#3174](https://github.com/matrix-org/synapse/issues/3174))
-   Escape label values in prometheus metrics. ([\#3175](https://github.com/matrix-org/synapse/issues/3175), [\#3186](https://github.com/matrix-org/synapse/issues/3186))
-   Fix "Unhandled Error" logs with Twisted 18.4. Thanks to @Half-Shot! ([\#3182](https://github.com/matrix-org/synapse/issues/3182))
-   Fix logcontext leaks in rate limiter. ([\#3183](https://github.com/matrix-org/synapse/issues/3183))
-   notifications: Convert `next_token` to string according to the spec. Thanks to @mujx! ([\#3190](https://github.com/matrix-org/synapse/issues/3190))
-   nuke-room-from-db.sh: fix deletion from search table. Thanks to @rubo77! ([\#3194](https://github.com/matrix-org/synapse/issues/3194))
-   add guard for None on `purge_history` api. Thanks to @krombel! ([\#3160](https://github.com/matrix-org/synapse/issues/3160))

Changes in synapse v0.28.1 (2018-05-01)
=======================================

SECURITY UPDATE

-   Clamp the allowed values of event depth received over federation to be `[0, 2^63 - 1]`. This mitigates an attack where malicious events injected with `depth = 2^63 - 1` render rooms unusable. Depth is used to determine the cosmetic ordering of events within a room, and so the ordering of events in such a room will default to using `stream_ordering` rather than `depth` (topological ordering).

    This is a temporary solution to mitigate abuse in the wild, whilst a long term solution is being implemented to improve how the depth parameter is used.

    Full details at <https://docs.google.com/document/d/1I3fi2S-XnpO45qrpCsowZv8P8dHcNZ4fsBsbOW7KABI>

-   Pin Twisted to <18.4 until we stop using the private `_OpenSSLECCurve` API.

Changes in synapse v0.28.0 (2018-04-26)
=======================================

Bug Fixes:

-   Fix quarantine media admin API and search reindex. ([\#3130](https://github.com/matrix-org/synapse/issues/3130))
-   Fix media admin APIs. ([\#3134](https://github.com/matrix-org/synapse/issues/3134))

Changes in synapse v0.28.0-rc1 (2018-04-24)
===========================================

Minor performance improvement to federation sending and bug fixes.

(Note: This release does not include the delta state resolution implementation discussed in matrix live)

Features:

-   Add metrics for event processing lag. ([\#3090](https://github.com/matrix-org/synapse/issues/3090))
-   Add metrics for ResponseCache. ([\#3092](https://github.com/matrix-org/synapse/issues/3092))

Changes:

-   Synapse on PyPy. Thanks to @Valodim! ([\#2760](https://github.com/matrix-org/synapse/issues/2760))
-   move handling of `auto_join_rooms` to RegisterHandler. Thanks to @krombel! ([\#2996](https://github.com/matrix-org/synapse/issues/2996))
-   Improve handling of SRV records for federation connections. Thanks to @silkeh! ([\#3016](https://github.com/matrix-org/synapse/issues/3016))
-   Document the behaviour of ResponseCache. ([\#3059](https://github.com/matrix-org/synapse/issues/3059))
-   Preparation for py3. Thanks to @NotAFile! ([\#3061](https://github.com/matrix-org/synapse/issues/3061), [\#3073](https://github.com/matrix-org/synapse/issues/3073), [\#3074](https://github.com/matrix-org/synapse/issues/3074), [\#3075](https://github.com/matrix-org/synapse/issues/3075), [\#3103](https://github.com/matrix-org/synapse/issues/3103), [\#3104](https://github.com/matrix-org/synapse/issues/3104), [\#3106](https://github.com/matrix-org/synapse/issues/3106), [\#3107](https://github.com/matrix-org/synapse/issues/3107), [\#3109](https://github.com/matrix-org/synapse/issues/3109), [\#3110](https://github.com/matrix-org/synapse/issues/3110))
-   update prometheus dashboard to use new metric names. Thanks to @krombel! ([\#3069](https://github.com/matrix-org/synapse/issues/3069))
-   use python3-compatible prints. Thanks to @NotAFile! ([\#3074](https://github.com/matrix-org/synapse/issues/3074))
-   Send federation events concurrently. ([\#3078](https://github.com/matrix-org/synapse/issues/3078))
-   Limit concurrent event sends for a room. ([\#3079](https://github.com/matrix-org/synapse/issues/3079))
-   Improve R30 stat definition. ([\#3086](https://github.com/matrix-org/synapse/issues/3086))
-   Send events to ASes concurrently. ([\#3088](https://github.com/matrix-org/synapse/issues/3088))
-   Refactor ResponseCache usage. ([\#3093](https://github.com/matrix-org/synapse/issues/3093))
-   Clarify that SRV may not point to a CNAME. Thanks to @silkeh! ([\#3100](https://github.com/matrix-org/synapse/issues/3100))
-   Use str(e) instead of e.message. Thanks to @NotAFile! ([\#3103](https://github.com/matrix-org/synapse/issues/3103))
-   Use six.itervalues in some places. Thanks to @NotAFile! ([\#3106](https://github.com/matrix-org/synapse/issues/3106))
-   Refactor `store.have_events`. ([\#3117](https://github.com/matrix-org/synapse/issues/3117))

Bug Fixes:

-   Return 401 for invalid `access_token` on logout. Thanks to @dklug! ([\#2938](https://github.com/matrix-org/synapse/issues/2938))
-   Return a 404 rather than a 500 on rejoining empty rooms. ([\#3080](https://github.com/matrix-org/synapse/issues/3080))
-   fix `federation_domain_whitelist`. ([\#3099](https://github.com/matrix-org/synapse/issues/3099))
-   Avoid creating events with huge numbers of `prev_events`. ([\#3113](https://github.com/matrix-org/synapse/issues/3113))
-   Reject events which have lots of `prev_events`. ([\#3118](https://github.com/matrix-org/synapse/issues/3118))

Changes in synapse v0.27.4 (2018-04-13)
=======================================

Changes:

-   Update canonicaljson dependency. ([\#3095](https://github.com/matrix-org/synapse/issues/3095))

Changes in synapse v0.27.3 (2018-04-11)
======================================

Bug fixes:

-   URL quote path segments over federation. ([\#3082](https://github.com/matrix-org/synapse/issues/3082))

Changes in synapse v0.27.3-rc2 (2018-04-09)
===========================================

v0.27.3-rc1 used a stale version of the develop branch so the changelog overstates the functionality. v0.27.3-rc2 is up to date, rc1 should be ignored.

Changes in synapse v0.27.3-rc1 (2018-04-09)
===========================================

Notable changes include API support for joinability of groups. Also new metrics and phone home stats. Phone home stats include better visibility of system usage so we can tweak synpase to work better for all users rather than our own experience with matrix.org. Also, recording "r30" stat which is the measure we use to track overall growth of the Matrix ecosystem. It is defined as:-

Counts the number of native 30 day retained users, defined as:

- Users who have created their accounts more than 30 days
- Where last seen at most 30 days ago
- Where account creation and `last_seen` are > 30 days

Features:

-   Add joinability for groups. ([\#3045](https://github.com/matrix-org/synapse/issues/3045))
-   Implement group join API. ([\#3046](https://github.com/matrix-org/synapse/issues/3046))
-   Add counter metrics for calculating state delta. ([\#3033](https://github.com/matrix-org/synapse/issues/3033))
-   R30 stats. ([\#3041](https://github.com/matrix-org/synapse/issues/3041))
-   Measure time it takes to calculate state group ID. ([\#3043](https://github.com/matrix-org/synapse/issues/3043))
-   Add basic performance statistics to phone home. ([\#3044](https://github.com/matrix-org/synapse/issues/3044))
-   Add response size metrics. ([\#3071](https://github.com/matrix-org/synapse/issues/3071))
-   phone home cache size configurations. ([\#3063](https://github.com/matrix-org/synapse/issues/3063))

Changes:

-   Add a blurb explaining the main synapse worker. Thanks to @turt2live! ([\#2886](https://github.com/matrix-org/synapse/issues/2886))
-   Replace old style error catching with `as` keyword. Thanks to @NotAFile! ([\#3000](https://github.com/matrix-org/synapse/issues/3000))
-   Use `.iter*` to avoid copies in StateHandler. ([\#3006](https://github.com/matrix-org/synapse/issues/3006))
-   Linearize calls to `_generate_user_id`. ([\#3029](https://github.com/matrix-org/synapse/issues/3029))
-   Remove last usage of ujson. ([\#3030](https://github.com/matrix-org/synapse/issues/3030))
-   Use simplejson throughout. ([\#3048](https://github.com/matrix-org/synapse/issues/3048))
-   Use static JSONEncoders. ([\#3049](https://github.com/matrix-org/synapse/issues/3049))
-   Remove uses of events.content. ([\#3060](https://github.com/matrix-org/synapse/issues/3060))
-   Improve database cache performance. ([\#3068](https://github.com/matrix-org/synapse/issues/3068))

Bug fixes:

-   Add `room_id` to the response of rooms/{roomId}/join. Thanks to @jplatte! ([\#2986](https://github.com/matrix-org/synapse/issues/2986))
-   Fix replication after switch to simplejson. ([\#3015](https://github.com/matrix-org/synapse/issues/3015))
-   404 correctly on missing paths via NoResource. ([\#3022](https://github.com/matrix-org/synapse/issues/3022))
-   Fix error when claiming e2e keys from offline servers. ([\#3034](https://github.com/matrix-org/synapse/issues/3034))
-   fix `tests/storage/test_user_directory.py`. ([\#3042](https://github.com/matrix-org/synapse/issues/3042))
-   use `PUT` instead of `POST` for federating `groups`/`m.join_policy`. Thanks to @krombel! ([\#3070](https://github.com/matrix-org/synapse/issues/3070))
-   postgres port script: fix `state_groups_pkey` error. ([\#3072](https://github.com/matrix-org/synapse/issues/3072))

Changes in synapse v0.27.2 (2018-03-26)
=======================================

Bug fixes:

-   Fix bug which broke TCP replication between workers. ([\#3015](https://github.com/matrix-org/synapse/issues/3015))

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

-   Fix bug introduced in v0.27.0-rc1 that causes much increased memory usage in state cache. ([\#3005](https://github.com/matrix-org/synapse/issues/3005))

Changes in synapse v0.26.1 (2018-03-15)
=======================================

Bug fixes:

-   Fix bug where an invalid event caused server to stop functioning correctly, due to parsing and serializing bugs in ujson library. ([\#3008](https://github.com/matrix-org/synapse/issues/3008))

Changes in synapse v0.27.0-rc1 (2018-03-14)
===========================================

The common case for running Synapse is not to run separate workers, but for those that do, be aware that synctl no longer starts the main synapse when using `-a` option with workers. A new worker file should be added with `worker_app: synapse.app.homeserver`.

This release also begins the process of renaming a number of the metrics reported to prometheus. See [docs/metrics-howto.rst](docs/metrics-howto.rst#block-and-response-metrics-renamed-for-0-27-0). Note that the v0.28.0 release will remove the deprecated metric names.

Features:

-   Add ability for ASes to override message send time. ([\#2754](https://github.com/matrix-org/synapse/issues/2754))
-   Add support for custom storage providers for media repository. ([\#2867](https://github.com/matrix-org/synapse/issues/2867), [\#2777](https://github.com/matrix-org/synapse/issues/2777), [\#2783](https://github.com/matrix-org/synapse/issues/2783), [\#2789](https://github.com/matrix-org/synapse/issues/2789), [\#2791](https://github.com/matrix-org/synapse/issues/2791), [\#2804](https://github.com/matrix-org/synapse/issues/2804), [\#2812](https://github.com/matrix-org/synapse/issues/2812), [\#2814](https://github.com/matrix-org/synapse/issues/2814), [\#2857](https://github.com/matrix-org/synapse/issues/2857), [\#2868](https://github.com/matrix-org/synapse/issues/2868), [\#2767](https://github.com/matrix-org/synapse/issues/2767))
-   Add purge API features, see [docs/admin_api/purge_history_api.rst](docs/admin_api/purge_history_api.rst) for full details. ([\#2858](https://github.com/matrix-org/synapse/issues/2858), [\#2867](https://github.com/matrix-org/synapse/issues/2867), [\#2882](https://github.com/matrix-org/synapse/issues/2882), [\#2946](https://github.com/matrix-org/synapse/issues/2946), [\#2962](https://github.com/matrix-org/synapse/issues/2962), [\#2943](https://github.com/matrix-org/synapse/issues/2943))
-   Add support for whitelisting 3PIDs that users can register. ([\#2813](https://github.com/matrix-org/synapse/issues/2813))
-   Add `/room/{id}/event/{id}` API. ([\#2766](https://github.com/matrix-org/synapse/issues/2766))
-   Add an admin API to get all the media in a room. Thanks to @turt2live! ([\#2818](https://github.com/matrix-org/synapse/issues/2818))
-   Add `federation_domain_whitelist` option. ([\#2820](https://github.com/matrix-org/synapse/issues/2820), [\#2821](https://github.com/matrix-org/synapse/issues/2821))

Changes:

-   Continue to factor out processing from main process and into worker processes. See updated [docs/workers.rst](docs/workers.rst) ([\#2892](https://github.com/matrix-org/synapse/issues/2892), [\#2893](https://github.com/matrix-org/synapse/issues/2893), [\#2894](https://github.com/matrix-org/synapse/issues/2894), [\#2896](https://github.com/matrix-org/synapse/issues/2896), [\#2897](https://github.com/matrix-org/synapse/issues/2897), [\#2898](https://github.com/matrix-org/synapse/issues/2898), [\#2899](https://github.com/matrix-org/synapse/issues/2899), [\#2900](https://github.com/matrix-org/synapse/issues/2900), [\#2901](https://github.com/matrix-org/synapse/issues/2901), [\#2902](https://github.com/matrix-org/synapse/issues/2902), [\#2903](https://github.com/matrix-org/synapse/issues/2903), [\#2904](https://github.com/matrix-org/synapse/issues/2904), [\#2913](https://github.com/matrix-org/synapse/issues/2913), [\#2920](https://github.com/matrix-org/synapse/issues/2920), [\#2921](https://github.com/matrix-org/synapse/issues/2921), [\#2922](https://github.com/matrix-org/synapse/issues/2922), [\#2923](https://github.com/matrix-org/synapse/issues/2923), [\#2924](https://github.com/matrix-org/synapse/issues/2924), [\#2925](https://github.com/matrix-org/synapse/issues/2925), [\#2926](https://github.com/matrix-org/synapse/issues/2926), [\#2947](https://github.com/matrix-org/synapse/issues/2947), [\#2847](https://github.com/matrix-org/synapse/issues/2847), [\#2854](https://github.com/matrix-org/synapse/issues/2854), [\#2872](https://github.com/matrix-org/synapse/issues/2872), [\#2873](https://github.com/matrix-org/synapse/issues/2873), [\#2874](https://github.com/matrix-org/synapse/issues/2874), [\#2928](https://github.com/matrix-org/synapse/issues/2928), [\#2929](https://github.com/matrix-org/synapse/issues/2929), [\#2934](https://github.com/matrix-org/synapse/issues/2934), [\#2856](https://github.com/matrix-org/synapse/issues/2856), [\#2976](https://github.com/matrix-org/synapse/issues/2976), [\#2977](https://github.com/matrix-org/synapse/issues/2977), [\#2978](https://github.com/matrix-org/synapse/issues/2978), [\#2979](https://github.com/matrix-org/synapse/issues/2979), [\#2980](https://github.com/matrix-org/synapse/issues/2980), [\#2981](https://github.com/matrix-org/synapse/issues/2981), [\#2982](https://github.com/matrix-org/synapse/issues/2982), [\#2983](https://github.com/matrix-org/synapse/issues/2983), [\#2984](https://github.com/matrix-org/synapse/issues/2984), [\#2987](https://github.com/matrix-org/synapse/issues/2987), [\#2988](https://github.com/matrix-org/synapse/issues/2988), [\#2989](https://github.com/matrix-org/synapse/issues/2989), [\#2991](https://github.com/matrix-org/synapse/issues/2991), [\#2992](https://github.com/matrix-org/synapse/issues/2992), [\#2993](https://github.com/matrix-org/synapse/issues/2993), [\#2995](https://github.com/matrix-org/synapse/issues/2995), [\#2784](https://github.com/matrix-org/synapse/issues/2784))
-   Ensure state cache is used when persisting events. ([\#2864](https://github.com/matrix-org/synapse/issues/2864), [\#2871](https://github.com/matrix-org/synapse/issues/2871), [\#2802](https://github.com/matrix-org/synapse/issues/2802), [\#2835](https://github.com/matrix-org/synapse/issues/2835), [\#2836](https://github.com/matrix-org/synapse/issues/2836), [\#2841](https://github.com/matrix-org/synapse/issues/2841), [\#2842](https://github.com/matrix-org/synapse/issues/2842), [\#2849](https://github.com/matrix-org/synapse/issues/2849))
-   Change the default config to bind on both IPv4 and IPv6 on all platforms. Thanks to @silkeh! ([\#2435](https://github.com/matrix-org/synapse/issues/2435))
-   No longer require a specific version of saml2. Thanks to @okurz! ([\#2695](https://github.com/matrix-org/synapse/issues/2695))
-   Remove `verbosity`/`log_file` from generated config. ([\#2755](https://github.com/matrix-org/synapse/issues/2755))
-   Add and improve metrics and logging. ([\#2770](https://github.com/matrix-org/synapse/issues/2770), [\#2778](https://github.com/matrix-org/synapse/issues/2778), [\#2785](https://github.com/matrix-org/synapse/issues/2785), [\#2786](https://github.com/matrix-org/synapse/issues/2786), [\#2787](https://github.com/matrix-org/synapse/issues/2787), [\#2793](https://github.com/matrix-org/synapse/issues/2793), [\#2794](https://github.com/matrix-org/synapse/issues/2794), [\#2795](https://github.com/matrix-org/synapse/issues/2795), [\#2809](https://github.com/matrix-org/synapse/issues/2809), [\#2810](https://github.com/matrix-org/synapse/issues/2810), [\#2833](https://github.com/matrix-org/synapse/issues/2833), [\#2834](https://github.com/matrix-org/synapse/issues/2834), [\#2844](https://github.com/matrix-org/synapse/issues/2844), [\#2965](https://github.com/matrix-org/synapse/issues/2965), [\#2927](https://github.com/matrix-org/synapse/issues/2927), [\#2975](https://github.com/matrix-org/synapse/issues/2975), [\#2790](https://github.com/matrix-org/synapse/issues/2790), [\#2796](https://github.com/matrix-org/synapse/issues/2796), [\#2838](https://github.com/matrix-org/synapse/issues/2838))
-   When using synctl with workers, Don't start the main synapse automatically. ([\#2774](https://github.com/matrix-org/synapse/issues/2774))
-   Minor performance improvements. ([\#2773](https://github.com/matrix-org/synapse/issues/2773), [\#2792](https://github.com/matrix-org/synapse/issues/2792))
-   Use a connection pool for non-federation outbound connections. ([\#2817](https://github.com/matrix-org/synapse/issues/2817))
-   Make it possible to run unit tests against postgres. ([\#2829](https://github.com/matrix-org/synapse/issues/2829))
-   Update pynacl dependency to 1.2.1 or higher. Thanks to @bachp! ([\#2888](https://github.com/matrix-org/synapse/issues/2888))
-   Remove ability for AS users to call /events and /sync. ([\#2948](https://github.com/matrix-org/synapse/issues/2948))
-   Use bcrypt.checkpw. Thanks to @krombel! ([\#2949](https://github.com/matrix-org/synapse/issues/2949))

Bug fixes:

-   Fix broken `ldap_config` config option. Thanks to @seckrv! ([\#2683](https://github.com/matrix-org/synapse/issues/2683))
-   Fix error message when user is not allowed to unban. Thanks to @turt2live! ([\#2761](https://github.com/matrix-org/synapse/issues/2761))
-   Fix publicised groups GET API (singular) over federation. ([\#2772](https://github.com/matrix-org/synapse/issues/2772))
-   Fix user directory when using `user_directory_search_all_users` config option. ([\#2803](https://github.com/matrix-org/synapse/issues/2803), [\#2831](https://github.com/matrix-org/synapse/issues/2831))
-   Fix error on `/publicRooms` when no rooms exist. ([\#2827](https://github.com/matrix-org/synapse/issues/2827))
-   Fix bug in `quarantine_media`. ([\#2837](https://github.com/matrix-org/synapse/issues/2837))
-   Fix `url_previews` when no `Content-Type` is returned from URL. ([\#2845](https://github.com/matrix-org/synapse/issues/2845))
-   Fix rare race in sync API when joining room. ([\#2944](https://github.com/matrix-org/synapse/issues/2944))
-   Fix slow event search, switch back from GIST to GIN indexes. ([\#2769](https://github.com/matrix-org/synapse/issues/2769), [\#2848](https://github.com/matrix-org/synapse/issues/2848))

Changes in synapse v0.26.0 (2018-01-05)
=======================================

No changes since v0.26.0-rc1

Changes in synapse v0.26.0-rc1 (2017-12-13)
===========================================

Features:

-   Add ability for ASes to publicise groups for their users. ([\#2686](https://github.com/matrix-org/synapse/issues/2686))
-   Add all local users to the `user_directory` and optionally search them. ([\#2723](https://github.com/matrix-org/synapse/issues/2723))
-   Add support for custom login types for validating users. ([\#2729](https://github.com/matrix-org/synapse/issues/2729))

Changes:

-   Update example Prometheus config to new format. Thanks to @krombel! ([\#2648](https://github.com/matrix-org/synapse/issues/2648))
-   Rename `redact_content` option to `include_content` in Push API. ([\#2650](https://github.com/matrix-org/synapse/issues/2650))
-   Declare support for r0.3.0. ([\#2677](https://github.com/matrix-org/synapse/issues/2677))
-   Improve upserts. ([\#2684](https://github.com/matrix-org/synapse/issues/2684), [\#2688](https://github.com/matrix-org/synapse/issues/2688), [\#2689](https://github.com/matrix-org/synapse/issues/2689), [\#2713](https://github.com/matrix-org/synapse/issues/2713))
-   Improve documentation of workers. ([\#2700](https://github.com/matrix-org/synapse/issues/2700))
-   Improve tracebacks on exceptions. ([\#2705](https://github.com/matrix-org/synapse/issues/2705))
-   Allow guest access to group APIs for reading. ([\#2715](https://github.com/matrix-org/synapse/issues/2715))
-   Support for posting content in `federation_client` script. ([\#2716](https://github.com/matrix-org/synapse/issues/2716))
-   Delete devices and pushers on logouts etc. ([\#2722](https://github.com/matrix-org/synapse/issues/2722))

Bug fixes:

-   Fix database port script. ([\#2673](https://github.com/matrix-org/synapse/issues/2673))
-   Fix internal server error on login with `ldap_auth_provider`. Thanks to @jkolo! ([\#2678](https://github.com/matrix-org/synapse/issues/2678))
-   Fix error on sqlite 3.7. ([\#2697](https://github.com/matrix-org/synapse/issues/2697))
-   Fix `OPTIONS` on `preview_url`. ([\#2707](https://github.com/matrix-org/synapse/issues/2707))
-   Fix error handling on dns lookup. ([\#2711](https://github.com/matrix-org/synapse/issues/2711))
-   Fix wrong avatars when inviting multiple users when creating room. ([\#2717](https://github.com/matrix-org/synapse/issues/2717))
-   Fix 500 when joining matrix-dev. ([\#2719](https://github.com/matrix-org/synapse/issues/2719))

Changes in synapse v0.25.1 (2017-11-17)
=======================================

Bug fixes:

-   Fix login with LDAP and other password provider modules. Thanks to @jkolo! ([\#2678](https://github.com/matrix-org/synapse/issues/2678))

Changes in synapse v0.25.0 (2017-11-15)
=======================================

Bug fixes:

-   Fix port script. ([\#2673](https://github.com/matrix-org/synapse/issues/2673))

Changes in synapse v0.25.0-rc1 (2017-11-14)
===========================================

Features:

-   Add `is_public` to groups table to allow for private groups. ([\#2582](https://github.com/matrix-org/synapse/issues/2582))
-   Add a route for determining who you are. Thanks to @turt2live! ([\#2668](https://github.com/matrix-org/synapse/issues/2668))
-   Add more features to the password providers ([\#2608](https://github.com/matrix-org/synapse/issues/2608), [\#2610](https://github.com/matrix-org/synapse/issues/2610), [\#2620](https://github.com/matrix-org/synapse/issues/2620), [\#2622](https://github.com/matrix-org/synapse/issues/2622), [\#2623](https://github.com/matrix-org/synapse/issues/2623), [\#2624](https://github.com/matrix-org/synapse/issues/2624), [\#2626](https://github.com/matrix-org/synapse/issues/2626), [\#2628](https://github.com/matrix-org/synapse/issues/2628), [\#2629](https://github.com/matrix-org/synapse/issues/2629))
-   Add a hook for custom rest endpoints. ([\#2627](https://github.com/matrix-org/synapse/issues/2627))
-   Add API to update group room visibility. ([\#2651](https://github.com/matrix-org/synapse/issues/2651))

Changes:

-   Ignore `<noscript\>` tags when generating URL preview descriptions. Thanks to @maximevaillancourt! ([\#2576](https://github.com/matrix-org/synapse/issues/2576))
-   Register some /unstable endpoints in /r0 as well. Thanks to @krombel! ([\#2579](https://github.com/matrix-org/synapse/issues/2579))
-   Support /keys/upload on /r0 as well as /unstable. ([\#2585](https://github.com/matrix-org/synapse/issues/2585))
-   Front-end proxy: pass through auth header. ([\#2586](https://github.com/matrix-org/synapse/issues/2586))
-   Allow ASes to deactivate their own users. ([\#2589](https://github.com/matrix-org/synapse/issues/2589))
-   Remove refresh tokens. ([\#2613](https://github.com/matrix-org/synapse/issues/2613))
-   Automatically set default displayname on register. ([\#2617](https://github.com/matrix-org/synapse/issues/2617))
-   Log login requests. ([\#2618](https://github.com/matrix-org/synapse/issues/2618))
-   Always return `is_public` in the `/groups/:group_id/rooms` API. ([\#2630](https://github.com/matrix-org/synapse/issues/2630))
-   Avoid no-op media deletes. Thanks to @spantaleev! ([\#2637](https://github.com/matrix-org/synapse/issues/2637))
-   Fix various embarrassing typos around `user_directory` and add some doc. ([\#2643](https://github.com/matrix-org/synapse/issues/2643))
-   Return whether a user is an admin within a group. ([\#2647](https://github.com/matrix-org/synapse/issues/2647))
-   Namespace visibility options for groups. ([\#2657](https://github.com/matrix-org/synapse/issues/2657))
-   Downcase UserIDs on registration. ([\#2662](https://github.com/matrix-org/synapse/issues/2662))
-   Cache failures when fetching URL previews. ([\#2669](https://github.com/matrix-org/synapse/issues/2669))

Bug fixes:

-   Fix port script. ([\#2577](https://github.com/matrix-org/synapse/issues/2577))
-   Fix error when running synapse with no logfile. ([\#2581](https://github.com/matrix-org/synapse/issues/2581))
-   Fix UI auth when deleting devices. ([\#2591](https://github.com/matrix-org/synapse/issues/2591))
-   Fix typo when checking if user is invited to group. ([\#2599](https://github.com/matrix-org/synapse/issues/2599))
-   Fix the port script to drop NUL values in all tables. ([\#2611](https://github.com/matrix-org/synapse/issues/2611))
-   Fix appservices being backlogged and not receiving new events due to a bug in `notify_interested_services`. Thanks to @xyzz! ([\#2631](https://github.com/matrix-org/synapse/issues/2631))
-   Fix updating rooms avatar/display name when modified by admin. Thanks to @farialima! ([\#2636](https://github.com/matrix-org/synapse/issues/2636))
-   Fix bug in state group storage. ([\#2649](https://github.com/matrix-org/synapse/issues/2649))
-   Fix 500 on invalid utf-8 in request. ([\#2663](https://github.com/matrix-org/synapse/issues/2663))

Changes in synapse v0.24.1 (2017-10-24)
=======================================

Bug fixes:

-   Fix updating group profiles over federation. ([\#2567](https://github.com/matrix-org/synapse/issues/2567))

Changes in synapse v0.24.0 (2017-10-23)
=======================================

No changes since v0.24.0-rc1

Changes in synapse v0.24.0-rc1 (2017-10-19)
===========================================

Features:

-   Add Group Server ([\#2352](https://github.com/matrix-org/synapse/issues/2352), [\#2363](https://github.com/matrix-org/synapse/issues/2363), [\#2374](https://github.com/matrix-org/synapse/issues/2374), [\#2377](https://github.com/matrix-org/synapse/issues/2377), [\#2378](https://github.com/matrix-org/synapse/issues/2378), [\#2382](https://github.com/matrix-org/synapse/issues/2382), [\#2410](https://github.com/matrix-org/synapse/issues/2410), [\#2426](https://github.com/matrix-org/synapse/issues/2426), [\#2430](https://github.com/matrix-org/synapse/issues/2430), [\#2454](https://github.com/matrix-org/synapse/issues/2454), [\#2471](https://github.com/matrix-org/synapse/issues/2471), [\#2472](https://github.com/matrix-org/synapse/issues/2472), [\#2544](https://github.com/matrix-org/synapse/issues/2544))
-   Add support for channel notifications. ([\#2501](https://github.com/matrix-org/synapse/issues/2501))
-   Add basic implementation of backup media store. ([\#2538](https://github.com/matrix-org/synapse/issues/2538))
-   Add config option to auto-join new users to rooms. ([\#2545](https://github.com/matrix-org/synapse/issues/2545))

Changes:

-   Make the spam checker a module. ([\#2474](https://github.com/matrix-org/synapse/issues/2474))
-   Delete expired url cache data. ([\#2478](https://github.com/matrix-org/synapse/issues/2478))
-   Ignore incoming events for rooms that we have left. ([\#2490](https://github.com/matrix-org/synapse/issues/2490))
-   Allow spam checker to reject invites too. ([\#2492](https://github.com/matrix-org/synapse/issues/2492))
-   Add room creation checks to spam checker. ([\#2495](https://github.com/matrix-org/synapse/issues/2495))
-   Spam checking: add the invitee to `user_may_invite`. ([\#2502](https://github.com/matrix-org/synapse/issues/2502))
-   Process events from federation for different rooms in parallel. ([\#2520](https://github.com/matrix-org/synapse/issues/2520))
-   Allow error strings from spam checker. ([\#2531](https://github.com/matrix-org/synapse/issues/2531))
-   Improve error handling for missing files in config. ([\#2551](https://github.com/matrix-org/synapse/issues/2551))

Bug fixes:

-   Fix handling SERVFAILs when doing AAAA lookups for federation. ([\#2477](https://github.com/matrix-org/synapse/issues/2477))
-   Fix incompatibility with newer versions of ujson. Thanks to @jeremycline! ([\#2483](https://github.com/matrix-org/synapse/issues/2483))
-   Fix notification keywords that start/end with non-word chars. ([\#2500](https://github.com/matrix-org/synapse/issues/2500))
-   Fix stack overflow and logcontexts from linearizer. ([\#2532](https://github.com/matrix-org/synapse/issues/2532))
-   Fix 500 error when fields missing from `power_levels` event. ([\#2552](https://github.com/matrix-org/synapse/issues/2552))
-   Fix 500 error when we get an error handling a PDU. ([\#2553](https://github.com/matrix-org/synapse/issues/2553))

Changes in synapse v0.23.1 (2017-10-02)
=======================================

Changes:

-   Make `affinity` package optional, as it is not supported on some platforms

Changes in synapse v0.23.0 (2017-10-02)
=======================================

No changes since v0.23.0-rc2

Changes in synapse v0.23.0-rc2 (2017-09-26)
===========================================

Bug fixes:

-   Fix regression in performance of syncs. ([\#2470](https://github.com/matrix-org/synapse/issues/2470))

Changes in synapse v0.23.0-rc1 (2017-09-25)
===========================================

Features:

-   Add a frontend proxy worker. ([\#2344](https://github.com/matrix-org/synapse/issues/2344))
-   Add support for `event_id_only` push format. ([\#2450](https://github.com/matrix-org/synapse/issues/2450))
-   Add a PoC for filtering spammy events. ([\#2456](https://github.com/matrix-org/synapse/issues/2456))
-   Add a config option to block all room invites. ([\#2457](https://github.com/matrix-org/synapse/issues/2457))

Changes:

-   Use bcrypt module instead of py-bcrypt. Thanks to @kyrias! ([\#2288](https://github.com/matrix-org/synapse/issues/2288))
-   Improve performance of generating push notifications. ([\#2343](https://github.com/matrix-org/synapse/issues/2343), [\#2357](https://github.com/matrix-org/synapse/issues/2357), [\#2365](https://github.com/matrix-org/synapse/issues/2365), [\#2366](https://github.com/matrix-org/synapse/issues/2366), [\#2371](https://github.com/matrix-org/synapse/issues/2371))
-   Improve DB performance for device list handling in sync. ([\#2362](https://github.com/matrix-org/synapse/issues/2362))
-   Include a sample prometheus config. ([\#2416](https://github.com/matrix-org/synapse/issues/2416))
-   Document known to work postgres version. Thanks to @ptman! ([\#2433](https://github.com/matrix-org/synapse/issues/2433))

Bug fixes:

-   Fix caching error in the push evaluator. ([\#2332](https://github.com/matrix-org/synapse/issues/2332))
-   Fix bug where pusherpool didn't start and broke some rooms. ([\#2342](https://github.com/matrix-org/synapse/issues/2342))
-   Fix port script for user directory tables. ([\#2375](https://github.com/matrix-org/synapse/issues/2375))
-   Fix device lists notifications when user rejoins a room. ([\#2443](https://github.com/matrix-org/synapse/issues/2443), [\#2449](https://github.com/matrix-org/synapse/issues/2449))
-   Fix sync to always send down current state events in timeline. ([\#2451](https://github.com/matrix-org/synapse/issues/2451))
-   Fix bug where guest users were incorrectly kicked. ([\#2453](https://github.com/matrix-org/synapse/issues/2453))
-   Fix bug talking to IPv6 only servers using SRV records. ([\#2462](https://github.com/matrix-org/synapse/issues/2462))

Changes in synapse v0.22.1 (2017-07-06)
=======================================

Bug fixes:

-   Fix bug where pusher pool didn't start and caused issues when interacting with some rooms. ([\#2342](https://github.com/matrix-org/synapse/issues/2342))

Changes in synapse v0.22.0 (2017-07-06)
=======================================

No changes since v0.22.0-rc2

Changes in synapse v0.22.0-rc2 (2017-07-04)
===========================================

Changes:

-   Improve performance of storing user IPs. ([\#2307](https://github.com/matrix-org/synapse/issues/2307), [\#2308](https://github.com/matrix-org/synapse/issues/2308))
-   Slightly improve performance of verifying access tokens. ([\#2320](https://github.com/matrix-org/synapse/issues/2320))
-   Slightly improve performance of event persistence. ([\#2321](https://github.com/matrix-org/synapse/issues/2321))
-   Increase default cache factor size from 0.1 to 0.5. ([\#2330](https://github.com/matrix-org/synapse/issues/2330))

Bug fixes:

-   Fix bug with storing registration sessions that caused frequent CPU churn. ([\#2319](https://github.com/matrix-org/synapse/issues/2319))

Changes in synapse v0.22.0-rc1 (2017-06-26)
===========================================

Features:

-   Add a user directory API ([\#2252](https://github.com/matrix-org/synapse/issues/2252), and many more)
-   Add shutdown room API to remove room from local server. ([\#2291](https://github.com/matrix-org/synapse/issues/2291))
-   Add API to quarantine media. ([\#2292](https://github.com/matrix-org/synapse/issues/2292))
-   Add new config option to not send event contents to push servers. Thanks to @cjdelisle! ([\#2301](https://github.com/matrix-org/synapse/issues/2301))

Changes:

-   Various performance fixes. ([\#2177](https://github.com/matrix-org/synapse/issues/2177), [\#2233](https://github.com/matrix-org/synapse/issues/2233), [\#2230](https://github.com/matrix-org/synapse/issues/2230), [\#2238](https://github.com/matrix-org/synapse/issues/2238), [\#2248](https://github.com/matrix-org/synapse/issues/2248), [\#2256](https://github.com/matrix-org/synapse/issues/2256), [\#2274](https://github.com/matrix-org/synapse/issues/2274))
-   Deduplicate sync filters. Thanks to @krombel! ([\#2219](https://github.com/matrix-org/synapse/issues/2219))
-   Correct a typo in UPGRADE.rst. Thanks to @aaronraimist! ([\#2231](https://github.com/matrix-org/synapse/issues/2231))
-   Add count of one time keys to sync stream. ([\#2237](https://github.com/matrix-org/synapse/issues/2237))
-   Only store `event_auth` for state events. ([\#2247](https://github.com/matrix-org/synapse/issues/2247))
-   Store URL cache preview downloads separately. ([\#2299](https://github.com/matrix-org/synapse/issues/2299))

Bug fixes:

-   Fix users not getting notifications when AS listened to that `user_id`. Thanks to @slipeer! ([\#2216](https://github.com/matrix-org/synapse/issues/2216))
-   Fix users without push set up not getting notifications after joining rooms. ([\#2236](https://github.com/matrix-org/synapse/issues/2236))
-   Fix preview url API to trim long descriptions. ([\#2243](https://github.com/matrix-org/synapse/issues/2243))
-   Fix bug where we used cached but unpersisted state group as prev group, resulting in broken state of restart. ([\#2263](https://github.com/matrix-org/synapse/issues/2263))
-   Fix removing of pushers when using workers. ([\#2267](https://github.com/matrix-org/synapse/issues/2267))
-   Fix CORS headers to allow Authorization header. Thanks to @krombel! ([\#2285](https://github.com/matrix-org/synapse/issues/2285))

Changes in synapse v0.21.1 (2017-06-15)
=======================================

Bug fixes:

-   Fix bug in anonymous usage statistic reporting. ([\#2281](https://github.com/matrix-org/synapse/issues/2281))

Changes in synapse v0.21.0 (2017-05-18)
=======================================

No changes since v0.21.0-rc3

Changes in synapse v0.21.0-rc3 (2017-05-17)
===========================================

Features:

-   Add per user rate-limiting overrides. ([\#2208](https://github.com/matrix-org/synapse/issues/2208))
-   Add config option to limit maximum number of events requested by `/sync` and `/messages`. Thanks to @psaavedra! ([\#2221](https://github.com/matrix-org/synapse/issues/2221))

Changes:

-   Various small performance fixes. ([\#2201](https://github.com/matrix-org/synapse/issues/2201), [\#2202](https://github.com/matrix-org/synapse/issues/2202), [\#2224](https://github.com/matrix-org/synapse/issues/2224), [\#2226](https://github.com/matrix-org/synapse/issues/2226), [\#2227](https://github.com/matrix-org/synapse/issues/2227), [\#2228](https://github.com/matrix-org/synapse/issues/2228), [\#2229](https://github.com/matrix-org/synapse/issues/2229))
-   Update username availability checker API. ([\#2209](https://github.com/matrix-org/synapse/issues/2209), [\#2213](https://github.com/matrix-org/synapse/issues/2213))
-   When purging, Don't de-delta state groups we're about to delete. ([\#2214](https://github.com/matrix-org/synapse/issues/2214))
-   Documentation to check synapse version. Thanks to @hamber-dick! ([\#2215](https://github.com/matrix-org/synapse/issues/2215))
-   Add an index to `event_search` to speed up purge history API. ([\#2218](https://github.com/matrix-org/synapse/issues/2218))

Bug fixes:

-   Fix API to allow clients to upload one-time-keys with new sigs. ([\#2206](https://github.com/matrix-org/synapse/issues/2206))

Changes in synapse v0.21.0-rc2 (2017-05-08)
===========================================

Changes:

-   Always mark remotes as up if we receive a signed request from them. ([\#2190](https://github.com/matrix-org/synapse/issues/2190))

Bug fixes:

-   Fix bug where users got pushed for rooms they had muted. ([\#2200](https://github.com/matrix-org/synapse/issues/2200))

Changes in synapse v0.21.0-rc1 (2017-05-08)
===========================================

Features:

-   Add username availability checker API. ([\#2183](https://github.com/matrix-org/synapse/issues/2183))
-   Add read marker API. ([\#2120](https://github.com/matrix-org/synapse/issues/2120))

Changes:

-   Enable guest access for the 3pl/3pid APIs. ([\#1986](https://github.com/matrix-org/synapse/issues/1986))
-   Add setting to support TURN for guests. ([\#2011](https://github.com/matrix-org/synapse/issues/2011))
-   Various performance improvements. ([\#2075](https://github.com/matrix-org/synapse/issues/2075), [\#2076](https://github.com/matrix-org/synapse/issues/2076), [\#2080](https://github.com/matrix-org/synapse/issues/2080), [\#2083](https://github.com/matrix-org/synapse/issues/2083), [\#2108](https://github.com/matrix-org/synapse/issues/2108), [\#2158](https://github.com/matrix-org/synapse/issues/2158), [\#2176](https://github.com/matrix-org/synapse/issues/2176), [\#2185](https://github.com/matrix-org/synapse/issues/2185))
-   Make synctl a bit more user friendly. ([\#2078](https://github.com/matrix-org/synapse/issues/2078), [\#2127](https://github.com/matrix-org/synapse/issues/2127)) Thanks @APwhitehat!
-   Replace HTTP replication with TCP replication. ([\#2082](https://github.com/matrix-org/synapse/issues/2082), [\#2097](https://github.com/matrix-org/synapse/issues/2097), [\#2098](https://github.com/matrix-org/synapse/issues/2098), [\#2099](https://github.com/matrix-org/synapse/issues/2099), [\#2103](https://github.com/matrix-org/synapse/issues/2103), [\#2014](https://github.com/matrix-org/synapse/issues/2014), [\#2016](https://github.com/matrix-org/synapse/issues/2016), [\#2115](https://github.com/matrix-org/synapse/issues/2115), [\#2116](https://github.com/matrix-org/synapse/issues/2116), [\#2117](https://github.com/matrix-org/synapse/issues/2117))
-   Support authenticated SMTP. Thanks @DanielDent! ([\#2102](https://github.com/matrix-org/synapse/issues/2102))
-   Add a counter metric for successfully-sent transactions. ([\#2121](https://github.com/matrix-org/synapse/issues/2121))
-   Propagate errors sensibly from proxied IS requests. ([\#2147](https://github.com/matrix-org/synapse/issues/2147))
-   Add more granular event send metrics. ([\#2178](https://github.com/matrix-org/synapse/issues/2178))

Bug fixes:

-   Fix nuke-room script to work with current schema. Thanks @zuckschwerdt! ([\#1927](https://github.com/matrix-org/synapse/issues/1927))
-   Fix db port script to not assume postgres tables are in the public schema. Thanks @jerrykan! ([\#2024](https://github.com/matrix-org/synapse/issues/2024))
-   Fix getting latest device IP for user with no devices. ([\#2118](https://github.com/matrix-org/synapse/issues/2118))
-   Fix rejection of invites to unreachable servers. ([\#2145](https://github.com/matrix-org/synapse/issues/2145))
-   Fix code for reporting old verify keys in synapse. ([\#2156](https://github.com/matrix-org/synapse/issues/2156))
-   Fix invite state to always include all events. ([\#2163](https://github.com/matrix-org/synapse/issues/2163))
-   Fix bug where synapse would always fetch state for any missing event. ([\#2170](https://github.com/matrix-org/synapse/issues/2170))
-   Fix a leak with timed out HTTP connections. ([\#2180](https://github.com/matrix-org/synapse/issues/2180))
-   Fix bug where we didn't time out HTTP requests to ASes. ([\#2192](https://github.com/matrix-org/synapse/issues/2192))

Docs:

-   Clarify doc for SQLite to PostgreSQL port. Thanks @benhylau! ([\#1961](https://github.com/matrix-org/synapse/issues/1961))
-   Fix typo in synctl help. Thanks @HarHarLinks! ([\#2107](https://github.com/matrix-org/synapse/issues/2107))
-   `web_client_location` documentation fix. Thanks @matthewjwolff! ([\#2131](https://github.com/matrix-org/synapse/issues/2131))
-   Update README.rst with FreeBSD changes. Thanks @feld! ([\#2132](https://github.com/matrix-org/synapse/issues/2132))
-   Clarify setting up metrics. Thanks @encks! ([\#2149](https://github.com/matrix-org/synapse/issues/2149))

Changes in synapse v0.20.0 (2017-04-11)
=======================================

Bug fixes:

-   Fix joining rooms over federation where not all servers in the room saw the new server had joined. ([\#2094](https://github.com/matrix-org/synapse/issues/2094))

Changes in synapse v0.20.0-rc1 (2017-03-30)
===========================================

Features:

-   Add `delete_devices` API. ([\#1993](https://github.com/matrix-org/synapse/issues/1993))
-   Add phone number registration/login support. ([\#1994](https://github.com/matrix-org/synapse/issues/1994), [\#2055](https://github.com/matrix-org/synapse/issues/2055))

Changes:

-   Use JSONSchema for validation of filters. Thanks @pik! ([\#1783](https://github.com/matrix-org/synapse/issues/1783))
-   Reread log config on SIGHUP. ([\#1982](https://github.com/matrix-org/synapse/issues/1982))
-   Speed up public room list. ([\#1989](https://github.com/matrix-org/synapse/issues/1989))
-   Add helpful texts to logger config options. ([\#1990](https://github.com/matrix-org/synapse/issues/1990))
-   Minor `/sync` performance improvements. ([\#2002](https://github.com/matrix-org/synapse/issues/2002), [\#2013](https://github.com/matrix-org/synapse/issues/2013), [\#2022](https://github.com/matrix-org/synapse/issues/2022))
-   Add some debug to help diagnose weird federation issue. ([\#2035](https://github.com/matrix-org/synapse/issues/2035))
-   Correctly limit retries for all federation requests. ([\#2050](https://github.com/matrix-org/synapse/issues/2050), [\#2061](https://github.com/matrix-org/synapse/issues/2061))
-   Don't lock table when persisting new one time keys. ([\#2053](https://github.com/matrix-org/synapse/issues/2053))
-   Reduce some CPU work on DB threads. ([\#2054](https://github.com/matrix-org/synapse/issues/2054))
-   Cache hosts in room. ([\#2060](https://github.com/matrix-org/synapse/issues/2060))
-   Batch sending of device list pokes. ([\#2063](https://github.com/matrix-org/synapse/issues/2063))
-   Speed up persist event path in certain edge cases. ([\#2070](https://github.com/matrix-org/synapse/issues/2070))

Bug fixes:

-   Fix bug where `current_state_events` renamed to `current_state_ids`. ([\#1849](https://github.com/matrix-org/synapse/issues/1849))
-   Fix routing loop when fetching remote media. ([\#1992](https://github.com/matrix-org/synapse/issues/1992))
-   Fix `current_state_events` table to not lie. ([\#1996](https://github.com/matrix-org/synapse/issues/1996))
-   Fix CAS login to handle PartialDownloadError. ([\#1997](https://github.com/matrix-org/synapse/issues/1997))
-   Fix assertion to stop transaction queue getting wedged. ([\#2010](https://github.com/matrix-org/synapse/issues/2010))
-   Fix presence to fallback to `last_active_ts` if it beats the last sync time. Thanks @Half-Shot! ([\#2014](https://github.com/matrix-org/synapse/issues/2014))
-   Fix bug when federation received a PDU while a room join is in progress. ([\#2016](https://github.com/matrix-org/synapse/issues/2016))
-   Fix resetting state on rejected events. ([\#2025](https://github.com/matrix-org/synapse/issues/2025))
-   Fix installation issues in readme. Thanks @ricco386. ([\#2037](https://github.com/matrix-org/synapse/issues/2037))
-   Fix caching of remote servers' signature keys. ([\#2042](https://github.com/matrix-org/synapse/issues/2042))
-   Fix some leaking log context. ([\#2048](https://github.com/matrix-org/synapse/issues/2048), [\#2049](https://github.com/matrix-org/synapse/issues/2049), [\#2057](https://github.com/matrix-org/synapse/issues/2057), [\#2058](https://github.com/matrix-org/synapse/issues/2058))
-   Fix rejection of invites not reaching sync. ([\#2056](https://github.com/matrix-org/synapse/issues/2056))

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

-   Add some administration functionalities. Thanks to morteza-araby! ([\#1784](https://github.com/matrix-org/synapse/issues/1784))

Changes:

-   Reduce database table sizes. ([\#1873](https://github.com/matrix-org/synapse/issues/1873), [\#1916](https://github.com/matrix-org/synapse/issues/1916), [\#1923](https://github.com/matrix-org/synapse/issues/1923), [\#1963](https://github.com/matrix-org/synapse/issues/1963))
-   Update contrib/ to not use syutil. Thanks to andrewshadura! ([\#1907](https://github.com/matrix-org/synapse/issues/1907))
-   Don't fetch current state when sending an event in common case. ([\#1955](https://github.com/matrix-org/synapse/issues/1955))

Bug fixes:

-   Fix synapse_port_db failure. Thanks to Pneumaticat! ([\#1904](https://github.com/matrix-org/synapse/issues/1904))
-   Fix caching to not cache error responses. ([\#1913](https://github.com/matrix-org/synapse/issues/1913))
-   Fix APIs to make kick & ban reasons work. ([\#1917](https://github.com/matrix-org/synapse/issues/1917))
-   Fix bugs in the /keys/changes api. ([\#1921](https://github.com/matrix-org/synapse/issues/1921))
-   Fix bug where users couldn't forget rooms they were banned from. ([\#1922](https://github.com/matrix-org/synapse/issues/1922))
-   Fix issue with long language values in pushers API. ([\#1925](https://github.com/matrix-org/synapse/issues/1925))
-   Fix a race in transaction queue. ([\#1930](https://github.com/matrix-org/synapse/issues/1930))
-   Fix dynamic thumbnailing to preserve aspect ratio. Thanks to jkolo! ([\#1945](https://github.com/matrix-org/synapse/issues/1945))
-   Fix device list update to not constantly resync. ([\#1964](https://github.com/matrix-org/synapse/issues/1964))
-   Fix potential for huge memory usage when getting device that have changed. ([\#1969](https://github.com/matrix-org/synapse/issues/1969))

Changes in synapse v0.19.2 (2017-02-20)
=======================================

-   Fix bug with event visibility check in /context/ API. Thanks to Tokodomo for pointing it out! ([\#1929](https://github.com/matrix-org/synapse/issues/1929))

Changes in synapse v0.19.1 (2017-02-09)
=======================================

-   Fix bug where state was incorrectly reset in a room when synapse received an event over federation that did not pass auth checks. ([\#1892](https://github.com/matrix-org/synapse/issues/1892))

Changes in synapse v0.19.0 (2017-02-04)
=======================================

No changes since RC 4.

Changes in synapse v0.19.0-rc4 (2017-02-02)
===========================================

-   Bump cache sizes for common membership queries. ([\#1879](https://github.com/matrix-org/synapse/issues/1879))

Changes in synapse v0.19.0-rc3 (2017-02-02)
===========================================

-   Fix email push in pusher worker. ([\#1875](https://github.com/matrix-org/synapse/issues/1875))
-   Make `presence.get_new_events` a bit faster. ([\#1876](https://github.com/matrix-org/synapse/issues/1876))
-   Make /keys/changes a bit more performant. ([\#1877](https://github.com/matrix-org/synapse/issues/1877))

Changes in synapse v0.19.0-rc2 (2017-02-02)
===========================================

-   Include newly joined users in /keys/changes API. ([\#1872](https://github.com/matrix-org/synapse/issues/1872))

Changes in synapse v0.19.0-rc1 (2017-02-02)
===========================================

Features:

-   Add support for specifying multiple bind addresses. Thanks to @kyrias! ([\#1709](https://github.com/matrix-org/synapse/issues/1709), [\#1712](https://github.com/matrix-org/synapse/issues/1712), [\#1795](https://github.com/matrix-org/synapse/issues/1795), [\#1835](https://github.com/matrix-org/synapse/issues/1835))
-   Add /account/3pid/delete endpoint. ([\#1714](https://github.com/matrix-org/synapse/issues/1714))
-   Add config option to configure the Riot URL used in notification emails. Thanks to @aperezdc! ([\#1811](https://github.com/matrix-org/synapse/issues/1811))
-   Add username and password config options for turn server. Thanks to @xsteadfastx! ([\#1832](https://github.com/matrix-org/synapse/issues/1832))
-   Implement device lists updates over federation. ([\#1857](https://github.com/matrix-org/synapse/issues/1857), [\#1861](https://github.com/matrix-org/synapse/issues/1861), [\#1864](https://github.com/matrix-org/synapse/issues/1864))
-   Implement /keys/changes. ([\#1869](https://github.com/matrix-org/synapse/issues/1869), [\#1872](https://github.com/matrix-org/synapse/issues/1872))

Changes:

-   Improve IPv6 support. Thanks to @kyrias and @glyph! ([\#1696](https://github.com/matrix-org/synapse/issues/1696))
-   Log which files we saved attachments to in the `media_repository`. ([\#1791](https://github.com/matrix-org/synapse/issues/1791))
-   Linearize updates to membership via PUT /state/ to better handle multiple joins. ([\#1787](https://github.com/matrix-org/synapse/issues/1787))
-   Limit number of entries to prefill from cache on startup. ([\#1792](https://github.com/matrix-org/synapse/issues/1792))
-   Remove `full_twisted_stacktraces` option. ([\#1802](https://github.com/matrix-org/synapse/issues/1802))
-   Measure size of some caches by sum of the size of cached values. ([\#1815](https://github.com/matrix-org/synapse/issues/1815))
-   Measure metrics of `string_cache`. ([\#1821](https://github.com/matrix-org/synapse/issues/1821))
-   Reduce logging verbosity. ([\#1822](https://github.com/matrix-org/synapse/issues/1822), [\#1823](https://github.com/matrix-org/synapse/issues/1823), [\#1824](https://github.com/matrix-org/synapse/issues/1824))
-   Don't clobber a displayname or `avatar_url` if provided by an m.room.member event. ([\#1852](https://github.com/matrix-org/synapse/issues/1852))
-   Better handle 401/404 response for federation /send/. ([\#1866](https://github.com/matrix-org/synapse/issues/1866), [\#1871](https://github.com/matrix-org/synapse/issues/1871))

Fixes:

-   Fix ability to change password to a non-ascii one. ([\#1711](https://github.com/matrix-org/synapse/issues/1711))
-   Fix push getting stuck due to looking at the wrong view of state. ([\#1820](https://github.com/matrix-org/synapse/issues/1820))
-   Fix email address comparison to be case insensitive. ([\#1827](https://github.com/matrix-org/synapse/issues/1827))
-   Fix occasional inconsistencies of room membership. ([\#1836](https://github.com/matrix-org/synapse/issues/1836), [\#1840](https://github.com/matrix-org/synapse/issues/1840))

Performance:

-   Don't block messages sending on bumping presence. ([\#1789](https://github.com/matrix-org/synapse/issues/1789))
-   Change `device_inbox` stream index to include user. ([\#1793](https://github.com/matrix-org/synapse/issues/1793))
-   Optimise state resolution. ([\#1818](https://github.com/matrix-org/synapse/issues/1818))
-   Use DB cache of joined users for presence. ([\#1862](https://github.com/matrix-org/synapse/issues/1862))
-   Add an index to make membership queries faster. ([\#1867](https://github.com/matrix-org/synapse/issues/1867))

Changes in synapse v0.18.7 (2017-01-09)
=======================================

No changes from v0.18.7-rc2

Changes in synapse v0.18.7-rc2 (2017-01-07)
===========================================

Bug fixes:

-   Fix error in rc1's discarding invalid inbound traffic logic that was incorrectly discarding missing events

Changes in synapse v0.18.7-rc1 (2017-01-06)
===========================================

Bug fixes:

-   Fix error in [\#1764](https://github.com/matrix-org/synapse/issues/1764) to actually fix the nightmare [\#1753](https://github.com/matrix-org/synapse/issues/1753) bug.
-   Improve deadlock logging further
-   Discard inbound federation traffic from invalid domains, to immunise against [\#1753](https://github.com/matrix-org/synapse/issues/1753).

Changes in synapse v0.18.6 (2017-01-06)
=======================================

Bug fixes:

-   Fix bug when checking if a guest user is allowed to join a room. Thanks to Patrik Oldsberg for diagnosing and the fix! ([\#1772](https://github.com/matrix-org/synapse/issues/1772))

Changes in synapse v0.18.6-rc3 (2017-01-05)
===========================================

Bug fixes:

-   Fix bug where we failed to send ban events to the banned server. ([\#1758](https://github.com/matrix-org/synapse/issues/1758))
-   Fix bug where we sent event that didn't originate on this server to other servers. ([\#1764](https://github.com/matrix-org/synapse/issues/1764))
-   Fix bug where processing an event from a remote server took a long time because we were making long HTTP requests. ([\#1765](https://github.com/matrix-org/synapse/issues/1765), [\#1744](https://github.com/matrix-org/synapse/issues/1744))

Changes:

-   Improve logging for debugging deadlocks. ([\#1766](https://github.com/matrix-org/synapse/issues/1766), [\#1767](https://github.com/matrix-org/synapse/issues/1767))

Changes in synapse v0.18.6-rc2 (2016-12-30)
===========================================

Bug fixes:

-   Fix memory leak in twisted by initialising logging correctly. ([\#1731](https://github.com/matrix-org/synapse/issues/1731))
-   Fix bug where fetching missing events took an unacceptable amount of time in large rooms. ([\#1734](https://github.com/matrix-org/synapse/issues/1734))

Changes in synapse v0.18.6-rc1 (2016-12-29)
===========================================

Bug fixes:

-   Make sure that outbound connections are closed. ([\#1725](https://github.com/matrix-org/synapse/issues/1725))

Changes in synapse v0.18.5 (2016-12-16)
=======================================

Bug fixes:

-   Fix federation /backfill returning events it shouldn't. ([\#1700](https://github.com/matrix-org/synapse/issues/1700))
-   Fix crash in url preview. ([\#1701](https://github.com/matrix-org/synapse/issues/1701))

Changes in synapse v0.18.5-rc3 (2016-12-13)
===========================================

Features:

-   Add support for E2E for guests. ([\#1653](https://github.com/matrix-org/synapse/issues/1653))
-   Add new API appservice specific public room list. ([\#1676](https://github.com/matrix-org/synapse/issues/1676))
-   Add new room membership APIs. ([\#1680](https://github.com/matrix-org/synapse/issues/1680))

Changes:

-   Enable guest access for private rooms by default. ([\#653](https://github.com/matrix-org/synapse/issues/653))
-   Limit the number of events that can be created on a given room concurrently. ([\#1620](https://github.com/matrix-org/synapse/issues/1620))
-   Log the args that we have on UI auth completion. ([\#1649](https://github.com/matrix-org/synapse/issues/1649))
-   Stop generating `refresh_tokens`. ([\#1654](https://github.com/matrix-org/synapse/issues/1654))
-   Stop putting a time caveat on access tokens. ([\#1656](https://github.com/matrix-org/synapse/issues/1656))
-   Remove unspecced GET endpoints for e2e keys. ([\#1694](https://github.com/matrix-org/synapse/issues/1694))

Bug fixes:

-   Fix handling of 500 and 429's over federation. ([\#1650](https://github.com/matrix-org/synapse/issues/1650))
-   Fix Content-Type header parsing. ([\#1660](https://github.com/matrix-org/synapse/issues/1660))
-   Fix error when previewing sites that include unicode, thanks to kyrias. ([\#1664](https://github.com/matrix-org/synapse/issues/1664))
-   Fix some cases where we drop read receipts. ([\#1678](https://github.com/matrix-org/synapse/issues/1678))
-   Fix bug where calls to `/sync` didn't correctly timeout. ([\#1683](https://github.com/matrix-org/synapse/issues/1683))
-   Fix bug where E2E key query would fail if a single remote host failed. ([\#1686](https://github.com/matrix-org/synapse/issues/1686))

Changes in synapse v0.18.5-rc2 (2016-11-24)
===========================================

Bug fixes:

-   Don't send old events over federation, fixes bug in -rc1.

Changes in synapse v0.18.5-rc1 (2016-11-24)
===========================================

Features:

-   Implement `event_fields` in filters. ([\#1638](https://github.com/matrix-org/synapse/issues/1638))

Changes:

-   Use external ldap auth package. ([\#1628](https://github.com/matrix-org/synapse/issues/1628))
-   Split out federation transaction sending to a worker. ([\#1635](https://github.com/matrix-org/synapse/issues/1635))
-   Fail with a coherent error message if /sync?filter= is invalid. ([\#1636](https://github.com/matrix-org/synapse/issues/1636))
-   More efficient notif count queries. ([\#1644](https://github.com/matrix-org/synapse/issues/1644))

Changes in synapse v0.18.4 (2016-11-22)
=======================================

Bug fixes:

-   Add workaround for buggy clients that the fail to register. ([\#1632](https://github.com/matrix-org/synapse/issues/1632))

Changes in synapse v0.18.4-rc1 (2016-11-14)
===========================================

Changes:

-   Various database efficiency improvements. ([\#1188](https://github.com/matrix-org/synapse/issues/1188), [\#1192](https://github.com/matrix-org/synapse/issues/1192))
-   Update default config to blacklist more internal IPs, thanks to Euan Kemp. ([\#1198](https://github.com/matrix-org/synapse/issues/1198))
-   Allow specifying duration in minutes in config, thanks to Daniel Dent. ([\#1625](https://github.com/matrix-org/synapse/issues/1625))

Bug fixes:

-   Fix media repo to set CORs headers on responses. ([\#1190](https://github.com/matrix-org/synapse/issues/1190))
-   Fix registration to not error on non-ascii passwords. ([\#1191](https://github.com/matrix-org/synapse/issues/1191))
-   Fix create event code to limit the number of `prev_events`. ([\#1615](https://github.com/matrix-org/synapse/issues/1615))
-   Fix bug in transaction ID deduplication. ([\#1624](https://github.com/matrix-org/synapse/issues/1624))

Changes in synapse v0.18.3 (2016-11-08)
=======================================

SECURITY UPDATE

Explicitly require authentication when using LDAP3. This is the default on versions of `ldap3` above 1.0, but some distributions will package an older version.

If you are using LDAP3 login and have a version of `ldap3` older than 1.0 it is **CRITICAL to upgrade**.

Changes in synapse v0.18.2 (2016-11-01)
=======================================

No changes since v0.18.2-rc5

Changes in synapse v0.18.2-rc5 (2016-10-28)
===========================================

Bug fixes:

-   Fix prometheus process metrics in worker processes. ([\#1184](https://github.com/matrix-org/synapse/issues/1184))

Changes in synapse v0.18.2-rc4 (2016-10-27)
===========================================

Bug fixes:

-   Fix `user_threepids` schema delta, which in some instances prevented startup after upgrade. ([\#1183](https://github.com/matrix-org/synapse/issues/1183))

Changes in synapse v0.18.2-rc3 (2016-10-27)
===========================================

Changes:

-   Allow clients to supply access tokens as headers. ([\#1098](https://github.com/matrix-org/synapse/issues/1098))
-   Clarify error codes for GET /filter/, thanks to Alexander Maznev. ([\#1164](https://github.com/matrix-org/synapse/issues/1164))
-   Make password reset email field case insensitive. ([\#1170](https://github.com/matrix-org/synapse/issues/1170))
-   Reduce redundant database work in email pusher. ([\#1174](https://github.com/matrix-org/synapse/issues/1174))
-   Allow configurable rate limiting per AS. ([\#1175](https://github.com/matrix-org/synapse/issues/1175))
-   Check whether to ratelimit sooner to avoid work. ([\#1176](https://github.com/matrix-org/synapse/issues/1176))
-   Standardise prometheus metrics. ([\#1177](https://github.com/matrix-org/synapse/issues/1177))

Bug fixes:

-   Fix incredibly slow back pagination query. ([\#1178](https://github.com/matrix-org/synapse/issues/1178))
-   Fix infinite typing bug. ([\#1179](https://github.com/matrix-org/synapse/issues/1179))

Changes in synapse v0.18.2-rc2 (2016-10-25)
===========================================

(This release did not include the changes advertised and was identical to RC1)

Changes in synapse v0.18.2-rc1 (2016-10-17)
===========================================

Changes:

-   Remove redundant `event_auth` index. ([\#1113](https://github.com/matrix-org/synapse/issues/1113))
-   Reduce DB hits for replication. ([\#1141](https://github.com/matrix-org/synapse/issues/1141))
-   Implement pluggable password auth. ([\#1155](https://github.com/matrix-org/synapse/issues/1155))
-   Remove rate limiting from app service senders and fix `get_or_create_user` requester, thanks to Patrik Oldsberg. ([\#1157](https://github.com/matrix-org/synapse/issues/1157))
-   window.postmessage for Interactive Auth fallback. ([\#1159](https://github.com/matrix-org/synapse/issues/1159))
-   Use sys.executable instead of hardcoded python, thanks to Pedro Larroy. ([\#1162](https://github.com/matrix-org/synapse/issues/1162))
-   Add config option for adding additional TLS fingerprints. ([\#1167](https://github.com/matrix-org/synapse/issues/1167))
-   User-interactive auth on delete device. ([\#1168](https://github.com/matrix-org/synapse/issues/1168))

Bug fixes:

-   Fix not being allowed to set your own `state_key`, thanks to Patrik Oldsberg. ([\#1150](https://github.com/matrix-org/synapse/issues/1150))
-   Fix interactive auth to return 401 from for incorrect password. ([\#1160](https://github.com/matrix-org/synapse/issues/1160), [\#1166](https://github.com/matrix-org/synapse/issues/1166))
-   Fix email push notifs being dropped. ([\#1169](https://github.com/matrix-org/synapse/issues/1169))

Changes in synapse v0.18.1 (2016-10-05)
=======================================

No changes since v0.18.1-rc1

Changes in synapse v0.18.1-rc1 (2016-09-30)
===========================================

Features:

-   Add `total_room_count_estimate` to `/publicRooms`. ([\#1133](https://github.com/matrix-org/synapse/issues/1133))

Changes:

-   Time out typing over federation. ([\#1140](https://github.com/matrix-org/synapse/issues/1140))
-   Restructure LDAP authentication. ([\#1153](https://github.com/matrix-org/synapse/issues/1153))

Bug fixes:

-   Fix 3pid invites when server is already in the room. ([\#1136](https://github.com/matrix-org/synapse/issues/1136))
-   Fix upgrading with SQLite taking lots of CPU for a few days after upgrade. ([\#1144](https://github.com/matrix-org/synapse/issues/1144))
-   Fix upgrading from very old database versions. ([\#1145](https://github.com/matrix-org/synapse/issues/1145))
-   Fix port script to work with recently added tables. ([\#1146](https://github.com/matrix-org/synapse/issues/1146))

Changes in synapse v0.18.0 (2016-09-19)
=======================================

The release includes major changes to the state storage database schemas, which significantly reduce database size. Synapse will attempt to upgrade the current data in the background. Servers with large SQLite database may experience degradation of performance while this upgrade is in progress, therefore you may want to consider migrating to using Postgres before upgrading very large SQLite databases

Changes:

-   Make public room search case insensitive. ([\#1127](https://github.com/matrix-org/synapse/issues/1127))

Bug fixes:

-   Fix and clean up publicRooms pagination. ([\#1129](https://github.com/matrix-org/synapse/issues/1129))

Changes in synapse v0.18.0-rc1 (2016-09-16)
===========================================

Features:

-   Add `only=highlight` on `/notifications`. ([\#1081](https://github.com/matrix-org/synapse/issues/1081))
-   Add server param to /publicRooms. ([\#1082](https://github.com/matrix-org/synapse/issues/1082))
-   Allow clients to ask for the whole of a single state event. ([\#1094](https://github.com/matrix-org/synapse/issues/1094))
-   Add `is_direct` param to /createRoom. ([\#1108](https://github.com/matrix-org/synapse/issues/1108))
-   Add pagination support to publicRooms. ([\#1121](https://github.com/matrix-org/synapse/issues/1121))
-   Add very basic filter API to /publicRooms. ([\#1126](https://github.com/matrix-org/synapse/issues/1126))
-   Add basic direct to device messaging support for E2E. ([\#1074](https://github.com/matrix-org/synapse/issues/1074), [\#1084](https://github.com/matrix-org/synapse/issues/1084), [\#1104](https://github.com/matrix-org/synapse/issues/1104), [\#1111](https://github.com/matrix-org/synapse/issues/1111))

Changes:

-   Move to storing `state_groups_state` as deltas, greatly reducing DB size. ([\#1065](https://github.com/matrix-org/synapse/issues/1065))
-   Reduce amount of state pulled out of the DB during common requests. ([\#1069](https://github.com/matrix-org/synapse/issues/1069))
-   Allow PDF to be rendered from media repo. ([\#1071](https://github.com/matrix-org/synapse/issues/1071))
-   Reindex `state_groups_state` after pruning. ([\#1085](https://github.com/matrix-org/synapse/issues/1085))
-   Clobber EDUs in send queue. ([\#1095](https://github.com/matrix-org/synapse/issues/1095))
-   Conform better to the CAS protocol specification. ([\#1100](https://github.com/matrix-org/synapse/issues/1100))
-   Limit how often we ask for keys from dead servers. ([\#1114](https://github.com/matrix-org/synapse/issues/1114))

Bug fixes:

-   Fix /notifications API when used with `from` param. ([\#1080](https://github.com/matrix-org/synapse/issues/1080))
-   Fix backfill when cannot find an event. ([\#1107](https://github.com/matrix-org/synapse/issues/1107))

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

-   Start adding store-and-forward direct-to-device messaging. ([\#1046](https://github.com/matrix-org/synapse/issues/1046), [\#1050](https://github.com/matrix-org/synapse/issues/1050), [\#1062](https://github.com/matrix-org/synapse/issues/1062), [\#1066](https://github.com/matrix-org/synapse/issues/1066))

Changes:

-   Avoid pulling the full state of a room out so often. ([\#1047](https://github.com/matrix-org/synapse/issues/1047), [\#1049](https://github.com/matrix-org/synapse/issues/1049), [\#1063](https://github.com/matrix-org/synapse/issues/1063), [\#1068](https://github.com/matrix-org/synapse/issues/1068))
-   Don't notify for online to online presence transitions. ([\#1054](https://github.com/matrix-org/synapse/issues/1054))
-   Occasionally persist unpersisted presence updates. ([\#1055](https://github.com/matrix-org/synapse/issues/1055))
-   Allow application services to have an optional `url`. ([\#1056](https://github.com/matrix-org/synapse/issues/1056))
-   Clean up old sent transactions from DB. ([\#1059](https://github.com/matrix-org/synapse/issues/1059))

Bug fixes:

-   Fix None check in backfill. ([\#1043](https://github.com/matrix-org/synapse/issues/1043))
-   Fix membership changes to be idempotent. ([\#1067](https://github.com/matrix-org/synapse/issues/1067))
-   Fix bug in `get_pdu` where it would sometimes return events with incorrect signature

Changes in synapse v0.17.1 (2016-08-24)
=======================================

Changes:

-   Delete old `received_transactions` rows. ([\#1038](https://github.com/matrix-org/synapse/issues/1038))
-   Pass through user-supplied content in `/join/$room_id`. ([\#1039](https://github.com/matrix-org/synapse/issues/1039))

Bug fixes:

-   Fix bug with backfill. ([\#1040](https://github.com/matrix-org/synapse/issues/1040))

Changes in synapse v0.17.1-rc1 (2016-08-22)
===========================================

Features:

-   Add notification API. ([\#1028](https://github.com/matrix-org/synapse/issues/1028))

Changes:

-   Don't print stack traces when failing to get remote keys. ([\#996](https://github.com/matrix-org/synapse/issues/996))
-   Various federation /event/ perf improvements. ([\#998](https://github.com/matrix-org/synapse/issues/998))
-   Only process one local membership event per room at a time. ([\#1005](https://github.com/matrix-org/synapse/issues/1005))
-   Move default display name push rule. ([\#1011](https://github.com/matrix-org/synapse/issues/1011), [\#1023](https://github.com/matrix-org/synapse/issues/1023))
-   Fix up preview URL API. Add tests. ([\#1015](https://github.com/matrix-org/synapse/issues/1015))
-   Set `Content-Security-Policy` on media repo. ([\#1021](https://github.com/matrix-org/synapse/issues/1021))
-   Make `notify_interested_services` faster. ([\#1022](https://github.com/matrix-org/synapse/issues/1022))
-   Add usage stats to prometheus monitoring. ([\#1037](https://github.com/matrix-org/synapse/issues/1037))

Bug fixes:

-   Fix token login. ([\#993](https://github.com/matrix-org/synapse/issues/993))
-   Fix CAS login. ([\#994](https://github.com/matrix-org/synapse/issues/994), [\#995](https://github.com/matrix-org/synapse/issues/995))
-   Fix /sync to not clobber `status_msg`. ([\#997](https://github.com/matrix-org/synapse/issues/997))
-   Fix redacted state events to include `prev_content`. ([\#1003](https://github.com/matrix-org/synapse/issues/1003))
-   Fix some bugs in the auth/ldap handler. ([\#1007](https://github.com/matrix-org/synapse/issues/1007))
-   Fix backfill request to limit URI length, so that remotes Don't reject the requests due to path length limits. ([\#1012](https://github.com/matrix-org/synapse/issues/1012))
-   Fix AS push code to not send duplicate events. ([\#1025](https://github.com/matrix-org/synapse/issues/1025))

Changes in synapse v0.17.0 (2016-08-08)
=======================================

This release contains significant security bug fixes regarding authenticating events received over federation. PLEASE UPGRADE.

This release changes the LDAP configuration format in a backwards incompatible way, see [\#843](https://github.com/matrix-org/synapse/issues/843) for details.

Changes:

-   Add federation /version API. ([\#990](https://github.com/matrix-org/synapse/issues/990))
-   Make psutil dependency optional. ([\#992](https://github.com/matrix-org/synapse/issues/992))

Bug fixes:

-   Fix URL preview API to exclude HTML comments in description. ([\#988](https://github.com/matrix-org/synapse/issues/988))
-   Fix error handling of remote joins. ([\#991](https://github.com/matrix-org/synapse/issues/991))

Changes in synapse v0.17.0-rc4 (2016-08-05)
===========================================

Changes:

-   Change the way we summarize URLs when previewing. ([\#973](https://github.com/matrix-org/synapse/issues/973))
-   Add new `/state_ids/` federation API. ([\#979](https://github.com/matrix-org/synapse/issues/979))
-   Speed up processing of `/state/` response. ([\#986](https://github.com/matrix-org/synapse/issues/986))

Bug fixes:

-   Fix event persistence when event has already been partially persisted. ([\#975](https://github.com/matrix-org/synapse/issues/975), [\#983](https://github.com/matrix-org/synapse/issues/983), [\#985](https://github.com/matrix-org/synapse/issues/985))
-   Fix port script to also copy across backfilled events. ([\#982](https://github.com/matrix-org/synapse/issues/982))

Changes in synapse v0.17.0-rc3 (2016-08-02)
===========================================

Changes:

-   Forbid non-ASes from registering users whose names begin with `_`. ([\#958](https://github.com/matrix-org/synapse/issues/958))
-   Add some basic admin API docs. ([\#963](https://github.com/matrix-org/synapse/issues/963))

Bug fixes:

-   Send the correct host header when fetching keys. ([\#941](https://github.com/matrix-org/synapse/issues/941))
-   Fix joining a room that has missing auth events. ([\#964](https://github.com/matrix-org/synapse/issues/964))
-   Fix various push bugs. ([\#966](https://github.com/matrix-org/synapse/issues/966), [\#970](https://github.com/matrix-org/synapse/issues/970))
-   Fix adding emails on registration. ([\#968](https://github.com/matrix-org/synapse/issues/968))

Changes in synapse v0.17.0-rc2 (2016-08-02)
===========================================

(This release did not include the changes advertised and was identical to RC1)

Changes in synapse v0.17.0-rc1 (2016-07-28)
===========================================

This release changes the LDAP configuration format in a backwards incompatible way, see [\#843](https://github.com/matrix-org/synapse/issues/843) for details.

Features:

-   Add `purge_media_cache` admin API. ([\#902](https://github.com/matrix-org/synapse/issues/902))
-   Add deactivate account admin API. ([\#903](https://github.com/matrix-org/synapse/issues/903))
-   Add optional pepper to password hashing by KentShikama. ([\#907](https://github.com/matrix-org/synapse/issues/907), [\#910](https://github.com/matrix-org/synapse/issues/910))
-   Add an admin option to shared secret registration (breaks backwards compat). ([\#909](https://github.com/matrix-org/synapse/issues/909))
-   Add purge local room history API. ([\#911](https://github.com/matrix-org/synapse/issues/911), [\#923](https://github.com/matrix-org/synapse/issues/923), [\#924](https://github.com/matrix-org/synapse/issues/924))
-   Add requestToken endpoints. ([\#915](https://github.com/matrix-org/synapse/issues/915))
-   Add an /account/deactivate endpoint. ([\#921](https://github.com/matrix-org/synapse/issues/921))
-   Add filter param to /messages. Add `contains_url` to filter. ([\#922](https://github.com/matrix-org/synapse/issues/922))
-   Add `device_id` support to /login. ([\#929](https://github.com/matrix-org/synapse/issues/929))
-   Add `device_id` support to /v2/register flow. ([\#937](https://github.com/matrix-org/synapse/issues/937), [\#942](https://github.com/matrix-org/synapse/issues/942))
-   Add GET /devices endpoint. ([\#939](https://github.com/matrix-org/synapse/issues/939), [\#944](https://github.com/matrix-org/synapse/issues/944))
-   Add GET /device/{deviceId}. ([\#943](https://github.com/matrix-org/synapse/issues/943))
-   Add update and delete APIs for devices. ([\#949](https://github.com/matrix-org/synapse/issues/949))

Changes:

-   Rewrite LDAP Authentication against ldap3. Contributed by mweinelt. ([\#843](https://github.com/matrix-org/synapse/issues/843))
-   Linearize some federation endpoints based on `(origin, room_id)`. ([\#879](https://github.com/matrix-org/synapse/issues/879))
-   Remove the legacy v0 content upload API. ([\#888](https://github.com/matrix-org/synapse/issues/888))
-   Use similar naming we use in email notifs for push. ([\#894](https://github.com/matrix-org/synapse/issues/894))
-   Optionally include password hash in createUser endpoint. Contributed by KentShikama. ([\#905](https://github.com/matrix-org/synapse/issues/905))
-   Use a query that postgresql optimises better for `get_events_around`. ([\#906](https://github.com/matrix-org/synapse/issues/906))
-   Fall back to '`username` if `user` is not given for appservice registration. Contributed by Half-Shot. ([\#927](https://github.com/matrix-org/synapse/issues/927))
-   Add metrics for psutil derived memory usage. ([\#936](https://github.com/matrix-org/synapse/issues/936))
-   Record `device_id` in `client_ips`. ([\#938](https://github.com/matrix-org/synapse/issues/938))
-   Send the correct host header when fetching keys. ([\#941](https://github.com/matrix-org/synapse/issues/941))
-   Log the hostname the reCAPTCHA was completed on. ([\#946](https://github.com/matrix-org/synapse/issues/946))
-   Make the device id on e2e key upload optional. ([\#956](https://github.com/matrix-org/synapse/issues/956))
-   Add r0.2.0 to the "supported versions" list. ([\#960](https://github.com/matrix-org/synapse/issues/960))
-   Don't include name of room for invites in push. ([\#961](https://github.com/matrix-org/synapse/issues/961))

Bug fixes:

-   Fix substitution failure in mail template. ([\#887](https://github.com/matrix-org/synapse/issues/887))
-   Put most recent 20 messages in email notif. ([\#892](https://github.com/matrix-org/synapse/issues/892))
-   Ensure that the guest user is in the database when upgrading accounts. ([\#914](https://github.com/matrix-org/synapse/issues/914))
-   Fix various edge cases in auth handling. ([\#919](https://github.com/matrix-org/synapse/issues/919))
-   Fix 500 ISE when sending alias event without a `state_key`. ([\#925](https://github.com/matrix-org/synapse/issues/925))
-   Fix bug where we stored rejections in the `state_group`, persist all rejections. ([\#948](https://github.com/matrix-org/synapse/issues/948))
-   Fix lack of check of if the user is banned when handling 3pid invites. ([\#952](https://github.com/matrix-org/synapse/issues/952))
-   Fix a couple of bugs in the transaction and keyring code. ([\#954](https://github.com/matrix-org/synapse/issues/954), [\#955](https://github.com/matrix-org/synapse/issues/955))

Changes in synapse v0.16.1-r1 (2016-07-08)
==========================================

THIS IS A CRITICAL SECURITY UPDATE.

This fixes a bug which allowed users' accounts to be accessed by unauthorised users.

Changes in synapse v0.16.1 (2016-06-20)
=======================================

Bug fixes:

-   Fix assorted bugs in `/preview_url`. ([\#872](https://github.com/matrix-org/synapse/issues/872))
-   Fix TypeError when setting unicode passwords. ([\#873](https://github.com/matrix-org/synapse/issues/873))

Performance improvements:

-   Turn `use_frozen_events` off by default. ([\#877](https://github.com/matrix-org/synapse/issues/877))
-   Disable responding with canonical json for federation. ([\#878](https://github.com/matrix-org/synapse/issues/878))

Changes in synapse v0.16.1-rc1 (2016-06-15)
===========================================

Features: None

Changes:

-   Log requester for `/publicRoom` endpoints when possible. ([\#856](https://github.com/matrix-org/synapse/issues/856))
-   502 on `/thumbnail` when can't connect to remote server. ([\#862](https://github.com/matrix-org/synapse/issues/862))
-   Linearize fetching of gaps on incoming events. ([\#871](https://github.com/matrix-org/synapse/issues/871))

Bugs fixes:

-   Fix bug where rooms where marked as published by default. ([\#857](https://github.com/matrix-org/synapse/issues/857))
-   Fix bug where joining room with an event with invalid sender. ([\#868](https://github.com/matrix-org/synapse/issues/868))
-   Fix bug where backfilled events were sent down sync streams. ([\#869](https://github.com/matrix-org/synapse/issues/869))
-   Fix bug where outgoing connections could wedge indefinitely, causing push notifications to be unreliable. ([\#870](https://github.com/matrix-org/synapse/issues/870))

Performance improvements:

-   Improve `/publicRooms` performance. ([\#859](https://github.com/matrix-org/synapse/issues/859))

Changes in synapse v0.16.0 (2016-06-09)
=======================================

NB: As of v0.14 all AS config files must have an ID field.

Bug fixes:

-   Don't make rooms published by default. ([\#857](https://github.com/matrix-org/synapse/issues/857))

Changes in synapse v0.16.0-rc2 (2016-06-08)
===========================================

Features:

-   Add configuration option for tuning GC via `gc.set_threshold`. ([\#849](https://github.com/matrix-org/synapse/issues/849))

Changes:

-   Record metrics about GC. ([\#771](https://github.com/matrix-org/synapse/issues/771), [\#847](https://github.com/matrix-org/synapse/issues/847), [\#852](https://github.com/matrix-org/synapse/issues/852))
-   Add metric counter for number of persisted events. ([\#841](https://github.com/matrix-org/synapse/issues/841))

Bug fixes:

-   Fix `From` header in email notifications. ([\#843](https://github.com/matrix-org/synapse/issues/843))
-   Fix presence where timeouts were not being fired for the first 8h after restarts. ([\#842](https://github.com/matrix-org/synapse/issues/842))
-   Fix bug where synapse sent malformed transactions to AS's when retrying transactions (Commits 310197b, 8437906)

Performance improvements:

-   Remove event fetching from DB threads. ([\#835](https://github.com/matrix-org/synapse/issues/835))
-   Change the way we cache events. ([\#836](https://github.com/matrix-org/synapse/issues/836))
-   Add events to cache when we persist them. ([\#840](https://github.com/matrix-org/synapse/issues/840))

Changes in synapse v0.16.0-rc1 (2016-06-03)
===========================================

Version 0.15 was not released. See v0.15.0-rc1 below for additional changes.

Features:

-   Add email notifications for missed messages. ([\#759](https://github.com/matrix-org/synapse/issues/759), [\#786](https://github.com/matrix-org/synapse/issues/786), [\#799](https://github.com/matrix-org/synapse/issues/799), [\#810](https://github.com/matrix-org/synapse/issues/810), [\#815](https://github.com/matrix-org/synapse/issues/815), [\#821](https://github.com/matrix-org/synapse/issues/821))
-   Add a `url_preview_ip_range_whitelist` config param. ([\#760](https://github.com/matrix-org/synapse/issues/760))
-   Add /report endpoint. ([\#762](https://github.com/matrix-org/synapse/issues/762))
-   Add basic ignore user API. ([\#763](https://github.com/matrix-org/synapse/issues/763))
-   Add an openidish mechanism for proving that you own a given `user_id`. ([\#765](https://github.com/matrix-org/synapse/issues/765))
-   Allow clients to specify a `server_name` to avoid "No known servers". ([\#794](https://github.com/matrix-org/synapse/issues/794))
-   Add `secondary_directory_servers` option to fetch room list from other servers. ([\#808](https://github.com/matrix-org/synapse/issues/808), [\#813](https://github.com/matrix-org/synapse/issues/813))

Changes:

-   Report per request metrics for all of the things using `request_handler`. ([\#756](https://github.com/matrix-org/synapse/issues/756))
-   Correctly handle `NULL` password hashes from the database. ([\#775](https://github.com/matrix-org/synapse/issues/775))
-   Allow receipts for events we haven't seen in the db. ([\#784](https://github.com/matrix-org/synapse/issues/784))
-   Make synctl read a cache factor from config file. ([\#785](https://github.com/matrix-org/synapse/issues/785))
-   Increment badge count per missed convo, not per msg. ([\#793](https://github.com/matrix-org/synapse/issues/793))
-   Special case `m.room.third_party_invite` event auth to match invites. ([\#814](https://github.com/matrix-org/synapse/issues/814))

Bug fixes:

-   Fix typo in `event_auth` servlet path. ([\#757](https://github.com/matrix-org/synapse/issues/757))
-   Fix password reset. ([\#758](https://github.com/matrix-org/synapse/issues/758))

Performance improvements:

-   Reduce database inserts when sending transactions. ([\#767](https://github.com/matrix-org/synapse/issues/767))
-   Queue events by room for persistence. ([\#768](https://github.com/matrix-org/synapse/issues/768))
-   Add cache to `get_user_by_id`. ([\#772](https://github.com/matrix-org/synapse/issues/772))
-   Add and use `get_domain_from_id`. ([\#773](https://github.com/matrix-org/synapse/issues/773))
-   Use tree cache for `get_linearized_receipts_for_room`. ([\#779](https://github.com/matrix-org/synapse/issues/779))
-   Remove unused indices. ([\#782](https://github.com/matrix-org/synapse/issues/782))
-   Add caches to `bulk_get_push_rules*`. ([\#804](https://github.com/matrix-org/synapse/issues/804))
-   Cache `get_event_reference_hashes`. ([\#806](https://github.com/matrix-org/synapse/issues/806))
-   Add `get_users_with_read_receipts_in_room` cache. ([\#809](https://github.com/matrix-org/synapse/issues/809))
-   Use state to calculate `get_users_in_room`. ([\#811](https://github.com/matrix-org/synapse/issues/811))
-   Load push rules in storage layer so that they get cached. ([\#825](https://github.com/matrix-org/synapse/issues/825))
-   Make `get_joined_hosts_for_room` use `get_users_in_room`. ([\#828](https://github.com/matrix-org/synapse/issues/828))
-   Poke notifier on next reactor tick. ([\#829](https://github.com/matrix-org/synapse/issues/829))
-   Change CacheMetrics to be quicker. ([\#830](https://github.com/matrix-org/synapse/issues/830))

Changes in synapse v0.15.0-rc1 (2016-04-26)
===========================================

Features:

-   Add login support for Javascript Web Tokens, thanks to Niklas Riekenbrauck. ([\#671](https://github.com/matrix-org/synapse/issues/671), [\#687](https://github.com/matrix-org/synapse/issues/687))
-   Add URL previewing support. ([\#688](https://github.com/matrix-org/synapse/issues/688))
-   Add login support for LDAP, thanks to Christoph Witzany. ([\#701](https://github.com/matrix-org/synapse/issues/701))
-   Add GET endpoint for pushers. ([\#716](https://github.com/matrix-org/synapse/issues/716))

Changes:

-   Never notify for member events. ([\#667](https://github.com/matrix-org/synapse/issues/667))
-   Deduplicate identical `/sync` requests. ([\#668](https://github.com/matrix-org/synapse/issues/668))
-   Require user to have left room to forget room. ([\#673](https://github.com/matrix-org/synapse/issues/673))
-   Use DNS cache if within TTL. ([\#677](https://github.com/matrix-org/synapse/issues/677))
-   Let users see their own leave events. ([\#699](https://github.com/matrix-org/synapse/issues/699))
-   Deduplicate membership changes. ([\#700](https://github.com/matrix-org/synapse/issues/700))
-   Increase performance of pusher code. ([\#705](https://github.com/matrix-org/synapse/issues/705))
-   Respond with error status 504 if failed to talk to remote server. ([\#731](https://github.com/matrix-org/synapse/issues/731))
-   Increase search performance on postgres. ([\#745](https://github.com/matrix-org/synapse/issues/745))

Bug fixes:

-   Fix bug where disabling all notifications still resulted in push. ([\#678](https://github.com/matrix-org/synapse/issues/678))
-   Fix bug where users couldn't reject remote invites if remote refused. ([\#691](https://github.com/matrix-org/synapse/issues/691))
-   Fix bug where synapse attempted to backfill from itself. ([\#693](https://github.com/matrix-org/synapse/issues/693))
-   Fix bug where profile information was not correctly added when joining remote rooms. ([\#703](https://github.com/matrix-org/synapse/issues/703))
-   Fix bug where register API required incorrect key name for AS registration. ([\#727](https://github.com/matrix-org/synapse/issues/727))

Changes in synapse v0.14.0 (2016-03-30)
=======================================

No changes from v0.14.0-rc2

Changes in synapse v0.14.0-rc2 (2016-03-23)
===========================================

Features:

-   Add published room list API. ([\#657](https://github.com/matrix-org/synapse/issues/657))

Changes:

-   Change various caches to consume less memory. ([\#656](https://github.com/matrix-org/synapse/issues/656), [\#658](https://github.com/matrix-org/synapse/issues/658), [\#660](https://github.com/matrix-org/synapse/issues/660), [\#662](https://github.com/matrix-org/synapse/issues/662), [\#663](https://github.com/matrix-org/synapse/issues/663), [\#665](https://github.com/matrix-org/synapse/issues/665))
-   Allow rooms to be published without requiring an alias. ([\#664](https://github.com/matrix-org/synapse/issues/664))
-   Intern common strings in caches to reduce memory footprint. ([\#666](https://github.com/matrix-org/synapse/issues/666))

Bug fixes:

-   Fix reject invites over federation. ([\#646](https://github.com/matrix-org/synapse/issues/646))
-   Fix bug where registration was not idempotent. ([\#649](https://github.com/matrix-org/synapse/issues/649))
-   Update aliases event after deleting aliases. ([\#652](https://github.com/matrix-org/synapse/issues/652))
-   Fix unread notification count, which was sometimes wrong. ([\#661](https://github.com/matrix-org/synapse/issues/661))

Changes in synapse v0.14.0-rc1 (2016-03-14)
===========================================

Features:

-   Add `event_id` to response to state event PUT. ([\#581](https://github.com/matrix-org/synapse/issues/581))
-   Allow guest users access to messages in rooms they have joined. ([\#587](https://github.com/matrix-org/synapse/issues/587))
-   Add config for what state is included in a room invite. ([\#598](https://github.com/matrix-org/synapse/issues/598))
-   Send the inviter's member event in room invite state. ([\#607](https://github.com/matrix-org/synapse/issues/607))
-   Add error codes for malformed/bad JSON in /login. ([\#608](https://github.com/matrix-org/synapse/issues/608))
-   Add support for changing the actions for default rules. ([\#609](https://github.com/matrix-org/synapse/issues/609))
-   Add environment variable `SYNAPSE_CACHE_FACTOR`, default it to 0.1. ([\#612](https://github.com/matrix-org/synapse/issues/612))
-   Add ability for alias creators to delete aliases. ([\#614](https://github.com/matrix-org/synapse/issues/614))
-   Add profile information to invites. ([\#624](https://github.com/matrix-org/synapse/issues/624))

Changes:

-   Enforce `user_id` exclusivity for AS registrations. ([\#572](https://github.com/matrix-org/synapse/issues/572))
-   Make adding push rules idempotent. ([\#587](https://github.com/matrix-org/synapse/issues/587))
-   Improve presence performance. ([\#582](https://github.com/matrix-org/synapse/issues/582), [\#586](https://github.com/matrix-org/synapse/issues/586))
-   Change presence semantics for `last_active_ago`. ([\#582](https://github.com/matrix-org/synapse/issues/582), [\#586](https://github.com/matrix-org/synapse/issues/586))
-   Don't allow `m.room.create` to be changed. ([\#596](https://github.com/matrix-org/synapse/issues/596))
-   Add 800x600 to default list of valid thumbnail sizes. ([\#616](https://github.com/matrix-org/synapse/issues/616))
-   Always include kicks and bans in full /sync. ([\#625](https://github.com/matrix-org/synapse/issues/625))
-   Send history visibility on boundary changes. ([\#626](https://github.com/matrix-org/synapse/issues/626))
-   Register endpoint now returns a `refresh_token`. ([\#637](https://github.com/matrix-org/synapse/issues/637))

Bug fixes:

-   Fix bug where we returned incorrect state in /sync. ([\#573](https://github.com/matrix-org/synapse/issues/573))
-   Always return a JSON object from push rule API. ([\#606](https://github.com/matrix-org/synapse/issues/606))
-   Fix bug where registering without a user id sometimes failed. ([\#610](https://github.com/matrix-org/synapse/issues/610))
-   Report size of ExpiringCache in cache size metrics. ([\#611](https://github.com/matrix-org/synapse/issues/611))
-   Fix rejection of invites to empty rooms. ([\#615](https://github.com/matrix-org/synapse/issues/615))
-   Fix usage of `bcrypt` to not use `checkpw`. ([\#619](https://github.com/matrix-org/synapse/issues/619))
-   Pin `pysaml2` dependency. ([\#634](https://github.com/matrix-org/synapse/issues/634))
-   Fix bug in `/sync` where timeline order was incorrect for backfilled events. ([\#635](https://github.com/matrix-org/synapse/issues/635))

Changes in synapse v0.13.3 (2016-02-11)
=======================================

-   Fix bug where `/sync` would occasionally return events in the wrong room.

Changes in synapse v0.13.2 (2016-02-11)
=======================================

-   Fix bug where `/events` would fail to skip some events if there had been more events than the limit specified since the last request. ([\#570](https://github.com/matrix-org/synapse/issues/570))

Changes in synapse v0.13.1 (2016-02-10)
=======================================

-   Bump matrix-angular-sdk (matrix web console) dependency to 0.6.8 to pull in the fix for SYWEB-361 so that the default client can display HTML messages again(!)

Changes in synapse v0.13.0 (2016-02-10)
=======================================

This version includes an upgrade of the schema, specifically adding an index to the `events` table. This may cause synapse to pause for several minutes the first time it is started after the upgrade.

Changes:

-   Improve general performance. ([\#540](https://github.com/matrix-org/synapse/issues/540), [\#543](https://github.com/matrix-org/synapse/issues/543). [\#544](https://github.com/matrix-org/synapse/issues/544), [\#54](https://github.com/matrix-org/synapse/issues/54), [\#549](https://github.com/matrix-org/synapse/issues/549), [\#567](https://github.com/matrix-org/synapse/issues/567))
-   Change guest user ids to be incrementing integers. ([\#550](https://github.com/matrix-org/synapse/issues/550))
-   Improve performance of public room list API. ([\#552](https://github.com/matrix-org/synapse/issues/552))
-   Change profile API to omit keys rather than return null. ([\#557](https://github.com/matrix-org/synapse/issues/557))
-   Add `/media/r0` endpoint prefix, which is equivalent to `/media/v1/`. ([\#595](https://github.com/matrix-org/synapse/issues/595))

Bug fixes:

-   Fix bug with upgrading guest accounts where it would fail if you opened the registration email on a different device. ([\#547](https://github.com/matrix-org/synapse/issues/547))
-   Fix bug where unread count could be wrong. ([\#568](https://github.com/matrix-org/synapse/issues/568))

Changes in synapse v0.12.1-rc1 (2016-01-29)
===========================================

Features:

-   Add unread notification counts in `/sync`. ([\#456](https://github.com/matrix-org/synapse/issues/456))
-   Add support for inviting 3pids in `/createRoom`. ([\#460](https://github.com/matrix-org/synapse/issues/460))
-   Add ability for guest accounts to upgrade. ([\#462](https://github.com/matrix-org/synapse/issues/462))
-   Add `/versions` API. ([\#468](https://github.com/matrix-org/synapse/issues/468))
-   Add `event` to `/context` API. ([\#492](https://github.com/matrix-org/synapse/issues/492))
-   Add specific error code for invalid user names in `/register`. ([\#499](https://github.com/matrix-org/synapse/issues/499))
-   Add support for push badge counts. ([\#507](https://github.com/matrix-org/synapse/issues/507))
-   Add support for non-guest users to peek in rooms using `/events`. ([\#510](https://github.com/matrix-org/synapse/issues/510))

Changes:

-   Change `/sync` so that guest users only get rooms they've joined. ([\#469](https://github.com/matrix-org/synapse/issues/469))
-   Change to require unbanning before other membership changes. ([\#501](https://github.com/matrix-org/synapse/issues/501))
-   Change default push rules to notify for all messages. ([\#486](https://github.com/matrix-org/synapse/issues/486))
-   Change default push rules to not notify on membership changes. ([\#514](https://github.com/matrix-org/synapse/issues/514))
-   Change default push rules in one to one rooms to only notify for events that are messages. ([\#529](https://github.com/matrix-org/synapse/issues/529))
-   Change `/sync` to reject requests with a `from` query param. ([\#512](https://github.com/matrix-org/synapse/issues/512))
-   Change server manhole to use SSH rather than telnet. ([\#473](https://github.com/matrix-org/synapse/issues/473))
-   Change server to require AS users to be registered before use. ([\#487](https://github.com/matrix-org/synapse/issues/487))
-   Change server not to start when ASes are invalidly configured. ([\#494](https://github.com/matrix-org/synapse/issues/494))
-   Change server to require ID and `as_token` to be unique for AS's. ([\#496](https://github.com/matrix-org/synapse/issues/496))
-   Change maximum pagination limit to 1000. ([\#497](https://github.com/matrix-org/synapse/issues/497))

Bug fixes:

-   Fix bug where `/sync` didn't return when something under the leave key changed. ([\#461](https://github.com/matrix-org/synapse/issues/461))
-   Fix bug where we returned smaller rather than larger than requested thumbnails when `method=crop`. ([\#464](https://github.com/matrix-org/synapse/issues/464))
-   Fix thumbnails API to only return cropped thumbnails when asking for a cropped thumbnail. ([\#475](https://github.com/matrix-org/synapse/issues/475))
-   Fix bug where we occasionally still logged access tokens. ([\#477](https://github.com/matrix-org/synapse/issues/477))
-   Fix bug where `/events` would always return immediately for guest users. ([\#480](https://github.com/matrix-org/synapse/issues/480))
-   Fix bug where `/sync` unexpectedly returned old left rooms. ([\#481](https://github.com/matrix-org/synapse/issues/481))
-   Fix enabling and disabling push rules. ([\#498](https://github.com/matrix-org/synapse/issues/498))
-   Fix bug where `/register` returned 500 when given unicode username. ([\#513](https://github.com/matrix-org/synapse/issues/513))

Changes in synapse v0.12.0 (2016-01-04)
=======================================

-   Expose `/login` under `r0`. ([\#459](https://github.com/matrix-org/synapse/issues/459))

Changes in synapse v0.12.0-rc3 (2015-12-23)
===========================================

-   Allow guest accounts access to `/sync`. ([\#455](https://github.com/matrix-org/synapse/issues/455))
-   Allow filters to include/exclude rooms at the room level rather than just from the components of the sync for each room. ([\#454](https://github.com/matrix-org/synapse/issues/454))
-   Include urls for room avatars in the response to `/publicRooms`. ([\#453](https://github.com/matrix-org/synapse/issues/453))
-   Don't set a identicon as the avatar for a user when they register. ([\#450](https://github.com/matrix-org/synapse/issues/450))
-   Add a `display_name` to third-party invites. ([\#449](https://github.com/matrix-org/synapse/issues/449))
-   Send more information to the identity server for third-party invites so that it can send richer messages to the invitee. ([\#446](https://github.com/matrix-org/synapse/issues/446))
-   Cache the responses to `/initialSync` for 5 minutes. If a client retries a request to `/initialSync` before the a response was computed to the first request then the same response is used for both requests. ([\#457](https://github.com/matrix-org/synapse/issues/457))
-   Fix a bug where synapse would always request the signing keys of remote servers even when the key was cached locally. ([\#452](https://github.com/matrix-org/synapse/issues/452))
-   Fix 500 when pagination search results. ([\#447](https://github.com/matrix-org/synapse/issues/447))
-   Fix a bug where synapse was leaking raw email address in third-party invites. ([\#448](https://github.com/matrix-org/synapse/issues/448))

Changes in synapse v0.12.0-rc2 (2015-12-14)
===========================================

-   Add caches for whether rooms have been forgotten by a user. ([\#434](https://github.com/matrix-org/synapse/issues/434))
-   Remove instructions to use `--process-dependency-link` since all of the dependencies of synapse are on PyPI. ([\#436](https://github.com/matrix-org/synapse/issues/436))
-   Parallelise the processing of `/sync` requests. ([\#437](https://github.com/matrix-org/synapse/issues/437))
-   Fix race updating presence in `/events`. ([\#444](https://github.com/matrix-org/synapse/issues/444))
-   Fix bug back-populating search results. ([\#441](https://github.com/matrix-org/synapse/issues/441))
-   Fix bug calculating state in `/sync` requests. ([\#442](https://github.com/matrix-org/synapse/issues/442))

Changes in synapse v0.12.0-rc1 (2015-12-10)
===========================================

-   Host the client APIs released as r0 by <https://matrix.org/docs/spec/r0.0.0/client_server.html> on paths prefixed by `/_matrix/client/r0`. ([\#430](https://github.com/matrix-org/synapse/issues/430), [\#415](https://github.com/matrix-org/synapse/issues/415), [\#400](https://github.com/matrix-org/synapse/issues/400))
-   Updates the client APIs to match r0 of the matrix specification.
    -   All APIs return events in the new event format, old APIs also include the fields needed to parse the event using the old format for compatibility. ([\#402](https://github.com/matrix-org/synapse/issues/402))
    -   Search results are now given as a JSON array rather than a JSON object. ([\#405](https://github.com/matrix-org/synapse/issues/405))
    -   Miscellaneous changes to search. ([\#403](https://github.com/matrix-org/synapse/issues/403), [\#406](https://github.com/matrix-org/synapse/issues/406), [\#412](https://github.com/matrix-org/synapse/issues/412))
    -   Filter JSON objects may now be passed as query parameters to `/sync`. ([\#431](https://github.com/matrix-org/synapse/issues/431))
    -   Fix implementation of `/admin/whois`. ([\#418](https://github.com/matrix-org/synapse/issues/418))
    -   Only include the rooms that user has left in `/sync` if the client requests them in the filter. ([\#423](https://github.com/matrix-org/synapse/issues/423))
    -   Don't push for `m.room.message` by default. ([\#411](https://github.com/matrix-org/synapse/issues/411))
    -   Add API for setting per account user data. ([\#392](https://github.com/matrix-org/synapse/issues/392))
    -   Allow users to forget rooms. ([\#385](https://github.com/matrix-org/synapse/issues/385))
-   Performance improvements and monitoring:
    -   Add per-request counters for CPU time spent on the main python thread. ([\#421](https://github.com/matrix-org/synapse/issues/421), [\#420](https://github.com/matrix-org/synapse/issues/420))
    -   Add per-request counters for time spent in the database. ([\#429](https://github.com/matrix-org/synapse/issues/429))
    -   Make state updates in the C+S API idempotent. ([\#416](https://github.com/matrix-org/synapse/issues/416))
    -   Only fire `user_joined_room` if the user has actually joined. ([\#410](https://github.com/matrix-org/synapse/issues/410))
    -   Reuse a single http client, rather than creating new ones. ([\#413](https://github.com/matrix-org/synapse/issues/413))
-   Fixed a bug upgrading from older versions of synapse on postgresql. ([\#417](https://github.com/matrix-org/synapse/issues/417))

Changes in synapse v0.11.1 (2015-11-20)
=======================================

-   Add extra options to search API. ([\#394](https://github.com/matrix-org/synapse/issues/394))
-   Fix bug where we did not correctly cap federation retry timers. This meant it could take several hours for servers to start talking to resurrected servers, even when they were receiving traffic from them. ([\#393](https://github.com/matrix-org/synapse/issues/393))
-   Don't advertise login token flow unless CAS is enabled. This caused issues where some clients would always use the fallback API if they did not recognize all login flows. ([\#391](https://github.com/matrix-org/synapse/issues/391))
-   Change /v2 sync API to rename `private_user_data` to `account_data`. ([\#386](https://github.com/matrix-org/synapse/issues/386))
-   Change /v2 sync API to remove the `event_map` and rename keys in `rooms` object. ([\#389](https://github.com/matrix-org/synapse/issues/389))

Changes in synapse v0.11.0-r2 (2015-11-19)
==========================================

-   Fix bug in database port script. ([\#387](https://github.com/matrix-org/synapse/issues/387))

Changes in synapse v0.11.0-r1 (2015-11-18)
==========================================

-   Retry and fail federation requests more aggressively for requests that block client side requests. ([\#384](https://github.com/matrix-org/synapse/issues/384))

Changes in synapse v0.11.0 (2015-11-17)
=======================================

-   Change CAS login API. ([\#349](https://github.com/matrix-org/synapse/issues/349))

Changes in synapse v0.11.0-rc2 (2015-11-13)
===========================================

-   Various changes to /sync API response format. ([\#373](https://github.com/matrix-org/synapse/issues/373))
-   Fix regression when setting display name in newly joined room over federation. ([\#368](https://github.com/matrix-org/synapse/issues/368))
-   Fix problem where /search was slow when using SQLite. ([\#366](https://github.com/matrix-org/synapse/issues/366))

Changes in synapse v0.11.0-rc1 (2015-11-11)
===========================================

-   Add Search API. ([\#307](https://github.com/matrix-org/synapse/issues/307), [\#324](https://github.com/matrix-org/synapse/issues/324), [\#327](https://github.com/matrix-org/synapse/issues/327), [\#336](https://github.com/matrix-org/synapse/issues/336), [\#350](https://github.com/matrix-org/synapse/issues/350), [\#359](https://github.com/matrix-org/synapse/issues/359))
-   Add `archived` state to v2 /sync API. ([\#316](https://github.com/matrix-org/synapse/issues/316))
-   Add ability to reject invites. ([\#317](https://github.com/matrix-org/synapse/issues/317))
-   Add config option to disable password login. ([\#322](https://github.com/matrix-org/synapse/issues/322))
-   Add the login fallback API. ([\#330](https://github.com/matrix-org/synapse/issues/330))
-   Add room context API. ([\#334](https://github.com/matrix-org/synapse/issues/334))
-   Add room tagging support. ([\#335](https://github.com/matrix-org/synapse/issues/335))
-   Update v2 /sync API to match spec. ([\#305](https://github.com/matrix-org/synapse/issues/305), [\#316](https://github.com/matrix-org/synapse/issues/316), [\#321](https://github.com/matrix-org/synapse/issues/321), [\#332](https://github.com/matrix-org/synapse/issues/332), [\#337](https://github.com/matrix-org/synapse/issues/337), [\#341](https://github.com/matrix-org/synapse/issues/341))
-   Change retry schedule for application services. ([\#320](https://github.com/matrix-org/synapse/issues/320))
-   Change retry schedule for remote servers. ([\#340](https://github.com/matrix-org/synapse/issues/340))
-   Fix bug where we hosted static content in the incorrect place. ([\#329](https://github.com/matrix-org/synapse/issues/329))
-   Fix bug where we didn't increment retry interval for remote servers. ([\#343](https://github.com/matrix-org/synapse/issues/343))

Changes in synapse v0.10.1-rc1 (2015-10-15)
===========================================

-   Add support for CAS, thanks to Steven Hammerton. ([\#295](https://github.com/matrix-org/synapse/issues/295), [\#296](https://github.com/matrix-org/synapse/issues/296))
-   Add support for using macaroons for `access_token`. ([\#256](https://github.com/matrix-org/synapse/issues/256), [\#229](https://github.com/matrix-org/synapse/issues/229))
-   Add support for `m.room.canonical_alias`. ([\#287](https://github.com/matrix-org/synapse/issues/287))
-   Add support for viewing the history of rooms that they have left. ([\#276](https://github.com/matrix-org/synapse/issues/276), [\#294](https://github.com/matrix-org/synapse/issues/294))
-   Add support for refresh tokens. ([\#240](https://github.com/matrix-org/synapse/issues/240))
-   Add flag on creation which disables federation of the room. ([\#279](https://github.com/matrix-org/synapse/issues/279))
-   Add some room state to invites. ([\#275](https://github.com/matrix-org/synapse/issues/275))
-   Atomically persist events when joining a room over federation. ([\#283](https://github.com/matrix-org/synapse/issues/283))
-   Change default history visibility for private rooms. ([\#271](https://github.com/matrix-org/synapse/issues/271))
-   Allow users to redact their own sent events. ([\#262](https://github.com/matrix-org/synapse/issues/262))
-   Use tox for tests. ([\#247](https://github.com/matrix-org/synapse/issues/247))
-   Split up syutil into separate libraries. ([\#243](https://github.com/matrix-org/synapse/issues/243))

Changes in synapse v0.10.0-r2 (2015-09-16)
==========================================

-   Fix bug where we always fetched remote server signing keys instead of using ones in our cache.
-   Fix adding threepids to an existing account.
-   Fix bug with invinting over federation where remote server was already in the room. ([\#281](https://github.com/matrix-org/synapse/issues/281), SYN-392)

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

-   Allow UTF-8 filenames for upload. ([\#259](https://github.com/matrix-org/synapse/issues/259))

Changes in synapse v0.10.0-rc3 (2015-08-25)
===========================================

-   Add `--keys-directory` config option to specify where files such as certs and signing keys should be stored in, when using `--generate-config` or `--generate-keys`. ([\#250](https://github.com/matrix-org/synapse/issues/250))
-   Allow `--config-path` to specify a directory, causing synapse to use all `*.yaml` files in the directory as config files. ([\#249](https://github.com/matrix-org/synapse/issues/249))
-   Add `web_client_location` config option to specify static files to be hosted by synapse under `/_matrix/client`. ([\#245](https://github.com/matrix-org/synapse/issues/245))
-   Add helper utility to synapse to read and parse the config files and extract the value of a given key. For example:

        $ python -m synapse.config read server_name -c homeserver.yaml
        localhost

   . ([\#246](https://github.com/matrix-org/synapse/issues/246))

Changes in synapse v0.10.0-rc2 (2015-08-24)
===========================================

-   Fix bug where we incorrectly populated the `event_forward_extremities` table, resulting in problems joining large remote rooms (e.g. `#matrix:matrix.org`)
-   Reduce the number of times we wake up pushers by not listening for presence or typing events, reducing the CPU cost of each pusher.

Changes in synapse v0.10.0-rc1 (2015-08-21)
===========================================

Also see v0.9.4-rc1 changelog, which has been amalgamated into this release.

General:

-   Upgrade to Twisted 15. ([\#173](https://github.com/matrix-org/synapse/issues/173))
-   Add support for serving and fetching encryption keys over federation. ([\#208](https://github.com/matrix-org/synapse/issues/208))
-   Add support for logging in with email address. ([\#234](https://github.com/matrix-org/synapse/issues/234))
-   Add support for new `m.room.canonical_alias` event. ([\#233](https://github.com/matrix-org/synapse/issues/233))
-   Change synapse to treat user IDs case insensitively during registration and login. (If two users already exist with case insensitive matching user ids, synapse will continue to require them to specify their user ids exactly.)
-   Error if a user tries to register with an email already in use. ([\#211](https://github.com/matrix-org/synapse/issues/211))
-   Add extra and improve existing caches. ([\#212](https://github.com/matrix-org/synapse/issues/212), [\#219](https://github.com/matrix-org/synapse/issues/219), [\#226](https://github.com/matrix-org/synapse/issues/226), [\#228](https://github.com/matrix-org/synapse/issues/228))
-   Batch various storage request. ([\#226](https://github.com/matrix-org/synapse/issues/226), [\#228](https://github.com/matrix-org/synapse/issues/228))
-   Fix bug where we didn't correctly log the entity that triggered the request if the request came in via an application service. ([\#230](https://github.com/matrix-org/synapse/issues/230))
-   Fix bug where we needlessly regenerated the full list of rooms an AS is interested in. ([\#232](https://github.com/matrix-org/synapse/issues/232))
-   Add support for AS's to use `v2_alpha` registration API. ([\#210](https://github.com/matrix-org/synapse/issues/210))

Configuration:

-   Add `--generate-keys` that will generate any missing cert and key files in the configuration files. This is equivalent to running `--generate-config` on an existing configuration file. ([\#220](https://github.com/matrix-org/synapse/issues/220))
-   `--generate-config` now no longer requires a `--server-name` parameter when used on existing configuration files. ([\#220](https://github.com/matrix-org/synapse/issues/220))
-   Add `--print-pidfile` flag that controls the printing of the pid to stdout of the demonised process. ([\#213](https://github.com/matrix-org/synapse/issues/213))

Media Repository:

-   Fix bug where we picked a lower resolution image than requested. ([\#205](https://github.com/matrix-org/synapse/issues/205))
-   Add support for specifying if a the media repository should dynamically thumbnail images or not. ([\#206](https://github.com/matrix-org/synapse/issues/206))

Metrics:

-   Add statistics from the reactor to the metrics API. ([\#224](https://github.com/matrix-org/synapse/issues/224), [\#225](https://github.com/matrix-org/synapse/issues/225))

Demo Homeservers:

-   Fix starting the demo homeservers without rate-limiting enabled. ([\#182](https://github.com/matrix-org/synapse/issues/182))
-   Fix enabling registration on demo homeservers. ([\#223](https://github.com/matrix-org/synapse/issues/223))

Changes in synapse v0.9.4-rc1 (2015-07-21)
==========================================

General:

-   Add basic implementation of receipts. (SPEC-99)
-   Add support for configuration presets in room creation API. ([\#203](https://github.com/matrix-org/synapse/issues/203))
-   Add auth event that limits the visibility of history for new users. (SPEC-134)
-   Add SAML2 login/registration support. Thanks Muthu Subramanian! ([\#201](https://github.com/matrix-org/synapse/issues/201))
-   Add client side key management APIs for end to end encryption. ([\#198](https://github.com/matrix-org/synapse/issues/198))
-   Change power level semantics so that you cannot kick, ban or change power levels of users that have equal or greater power level than you. (SYN-192)
-   Improve performance by bulk inserting events where possible. ([\#193](https://github.com/matrix-org/synapse/issues/193))
-   Improve performance by bulk verifying signatures where possible. ([\#194](https://github.com/matrix-org/synapse/issues/194))

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
-   Improve performance of backfill and joining remote rooms by removing unnecessary computations. This included handling events we'd previously handled as well as attempting to compute the current state for outliers.

Changes in synapse v0.9.1 (2015-05-26)
======================================

General:

-   Add support for backfilling when a client paginates. This allows servers to request history for a room from remote servers when a client tries to paginate history the server does not have - SYN-36
-   Fix bug where you couldn't disable non-default pushrules - SYN-378
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

-   Add key distribution mechanisms for fetching public keys of unavailable remote homeservers. See [Retrieving Server Keys](https://github.com/matrix-org/matrix-doc/blob/6f2698/specification/30_server_server_api.rst#retrieving-server-keys) in the spec.

Configuration:

-   Add support for multiple config files.
-   Add support for dictionaries in config files.
-   Remove support for specifying config options on the command line, except for:
    -   `--daemonize` - Daemonize the homeserver.
    -   `--manhole` - Turn on the twisted telnet manhole service on the given port.
    -   `--database-path` - The path to a sqlite database to use.
    -   `--verbose` - The verbosity level.
    -   `--log-file` - File to log to.
    -   `--log-config` - Python logging config file.
    -   `--enable-registration` - Enable registration for new users.

Application services:

-   Reliably retry sending of events from Synapse to application services, as per [Application Services](https://github.com/matrix-org/matrix-doc/blob/0c6bd9/specification/25_application_service_api.rst#home-server---application-service-api) spec.
-   Application services can no longer register via the `/register` API, instead their configuration should be saved to a file and listed in the synapse `app_service_config_files` config option. The AS configuration file has the same format as the old `/register` request. See [docs/application_services.rst](docs/application_services.rst) for more information.

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
    -   Notify for messages that Don't match any rule.
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
        > -   User's room membership, used for authorizing presence updates.

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
-   Replicate media uploads over multiple homeservers so media is always served to clients from their local homeserver. This obsoletes the `--content-addr` parameter and confusion over accessing content directly from remote homeservers.
-   Implement exponential backoff when retrying federation requests when sending to remote homeservers which are offline.
-   Implement typing notifications.
-   Fix bugs where we sent events with invalid signatures due to bugs where we incorrectly persisted events.
-   Improve performance of database queries involving retrieving events.

Changes in synapse 0.5.4a (2014-12-13)
======================================

-   Fix bug while generating the error message when a file path specified in the config doesn't exist.

Changes in synapse 0.5.4 (2014-12-03)
=====================================

-   Fix presence bug where some rooms did not display presence updates for remote users.
-   Do not log SQL timing log lines when started with `-v`
-   Fix potential memory leak.

Changes in synapse 0.5.3c (2014-12-02)
======================================

-   Change the default value for the `content_addr` option to use the HTTP listener, as by default the HTTPS listener will be using a self-signed certificate.

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

-   Fix bug where we served up an Event that did not match its signatures.
-   Fix regression where we no longer correctly handled the case where a homeserver receives an event for a room it doesn't recognise (but is in.)

Changes in synapse 0.5.0 (2014-11-19)
=====================================

This release includes changes to the federation protocol and client-server API that is not backwards compatible.

This release also changes the internal database schemas and so requires servers to drop their current history. See UPGRADES.rst for details.

Homeserver:

-   Add authentication and authorization to the federation protocol. Events are now signed by their originating homeservers.
-   Implement the new authorization model for rooms.
-   Split out web client into a separate repository: matrix-angular-sdk.
-   Change the structure of PDUs.
-   Fix bug where user could not join rooms via an alias containing 4-byte UTF-8 characters.
-   Merge concept of PDUs and Events internally.
-   Improve logging by adding request ids to log lines.
-   Implement a very basic room initial sync API.
-   Implement the new invite/join federation APIs.

Webclient:

-   The webclient has been moved to a separate repository.

Changes in synapse 0.4.2 (2014-10-31)
=====================================

Homeserver:

-   Fix bugs where we did not notify users of correct presence updates.
-   Fix bug where we did not handle sub second event stream timeouts.

Webclient:

-   Add ability to click on messages to see JSON.
-   Add ability to redact messages.
-   Add ability to view and edit all room state JSON.
-   Handle incoming redactions.
-   Improve feedback on errors.
-   Fix bugs in mobile CSS.
-   Fix bugs with desktop notifications.

Changes in synapse 0.4.1 (2014-10-17)
=====================================

Webclient:

-   Fix bug with display of timestamps.

Changes in synpase 0.4.0 (2014-10-17)
=====================================

This release includes changes to the federation protocol and client-server API that is not backwards compatible.

The Matrix specification has been moved to a separate git repository: <http://github.com/matrix-org/matrix-doc>

You will also need an updated syutil and config. See UPGRADES.rst.

Homeserver:

-   Sign federation transactions to assert strong identity over federation.
-   Rename timestamp keys in PDUs and events from `ts` and `hsob_ts` to `origin_server_ts`.

Changes in synapse 0.3.4 (2014-09-25)
=====================================

This version adds support for using a TURN server. See docs/turn-howto.rst on how to set one up.

Homeserver:

-   Add support for redaction of messages.
-   Fix bug where inviting a user on a remote homeserver could take up to 20-30s.
-   Implement a get current room state API.
-   Add support specifying and retrieving turn server configuration.

Webclient:

-   Add button to send messages to users from the home page.
-   Add support for using TURN for VoIP calls.
-   Show display name change messages.
-   Fix bug where the client didn't get the state of a newly joined room until after it has been refreshed.
-   Fix bugs with tab complete.
-   Fix bug where holding down the down arrow caused chrome to chew 100% CPU.
-   Fix bug where desktop notifications occasionally used "Undefined" as the display name.
-   Fix more places where we sometimes saw room IDs incorrectly.
-   Fix bug which caused lag when entering text in the text box.

Changes in synapse 0.3.3 (2014-09-22)
=====================================

Homeserver:

-   Fix bug where you continued to get events for rooms you had left.

Webclient:

-   Add support for video calls with basic UI.
-   Fix bug where one to one chats were named after your display name rather than the other person's.
-   Fix bug which caused lag when typing in the textarea.
-   Refuse to run on browsers we know won't work.
-   Trigger pagination when joining new rooms.
-   Fix bug where we sometimes didn't display invitations in recents.
-   Automatically join room when accepting a VoIP call.
-   Disable outgoing and reject incoming calls on browsers we Don't support VoIP in.
-   Don't display desktop notifications for messages in the room you are non-idle and speaking in.

Changes in synapse 0.3.2 (2014-09-18)
=====================================

Webclient:

-   Fix bug where an empty "bing words" list in old accounts didn't send notifications when it should have done.

Changes in synapse 0.3.1 (2014-09-18)
=====================================

This is a release to hotfix v0.3.0 to fix two regressions.

Webclient:

-   Fix a regression where we sometimes displayed duplicate events.
-   Fix a regression where we didn't immediately remove rooms you were banned in from the recents list.

Changes in synapse 0.3.0 (2014-09-18)
=====================================

See UPGRADE for information about changes to the client server API, including breaking backwards compatibility with VoIP calls and registration API.

Homeserver:

-   When a user changes their displayname or avatar the server will now update all their join states to reflect this.
-   The server now adds `age` key to events to indicate how old they are. This is clock independent, so at no point does any server or webclient have to assume their clock is in sync with everyone else.
-   Fix bug where we didn't correctly pull in missing PDUs.
-   Fix bug where `prev_content` key wasn't always returned.
-   Add support for password resets.

Webclient:

-   Improve page content loading.
-   Join/parts now trigger desktop notifications.
-   Always show room aliases in the UI if one is present.
-   No longer show user-count in the recents side panel.
-   Add up & down arrow support to the text box for message sending to step through your sent history.
-   Don't display notifications for our own messages.
-   Emotes are now formatted correctly in desktop notifications.
-   The recents list now differentiates between public & private rooms.
-   Fix bug where when switching between rooms the pagination flickered before the view jumped to the bottom of the screen.
-   Add bing word support.

Registration API:

-   The registration API has been overhauled to function like the login API. In practice, this means registration requests must now include the following: `type`:`m.login.password`. See UPGRADE for more information on this.
-   The `user_id` key has been renamed to `user` to better match the login API.
-   There is an additional login type: `m.login.email.identity`.
-   The command client and web client have been updated to reflect these changes.

Changes in synapse 0.2.3 (2014-09-12)
=====================================

Homeserver:

-   Fix bug where we stopped sending events to remote homeservers if a user from that homeserver left, even if there were some still in the room.
-   Fix bugs in the state conflict resolution where it was incorrectly rejecting events.

Webclient:

-   Display room names and topics.
-   Allow setting/editing of room names and topics.
-   Display information about rooms on the main page.
-   Handle ban and kick events in real time.
-   VoIP UI and reliability improvements.
-   Add glare support for VoIP.
-   Improvements to initial startup speed.
-   Don't display duplicate join events.
-   Local echo of messages.
-   Differentiate sending and sent of local echo.
-   Various minor bug fixes.

Changes in synapse 0.2.2 (2014-09-06)
=====================================

Homeserver:

-   When the server returns state events it now also includes the previous content.
-   Add support for inviting people when creating a new room.
-   Make the homeserver inform the room via m.room.aliases when a new alias is added for a room.
-   Validate `m.room.power_level` events.

Webclient:

-   Add support for captchas on registration.
-   Handle m.room.aliases events.
-   Asynchronously send messages and show a local echo.
-   Inform the UI when a message failed to send.
-   Only autoscroll on receiving a new message if the user was already at the bottom of the screen.
-   Add support for ban/kick reasons.

Changes in synapse 0.2.1 (2014-09-03)
=====================================

Homeserver:

-   Added support for signing up with a third party id.
-   Add synctl scripts.
-   Added rate limiting.
-   Add option to change the external address the content repo uses.
-   Presence bug fixes.

Webclient:

-   Added support for signing up with a third party id.
-   Added support for banning and kicking users.
-   Added support for displaying and setting ops.
-   Added support for room names.
-   Fix bugs with room membership event display.

Changes in synapse 0.2.0 (2014-09-02)
=====================================

This update changes many configuration options, updates the database schema and mandates SSL for server-server connections.

Homeserver:

-   Require SSL for server-server connections.
-   Add SSL listener for client-server connections.
-   Add ability to use config files.
-   Add support for kicking/banning and power levels.
-   Allow setting of room names and topics on creation.
-   Change presence to include last seen time of the user.
-   Change url path prefix to `/_matrix/...`
-   Bug fixes to presence.

Webclient:

-   Reskin the CSS for registration and login.
-   Various improvements to rooms CSS.
-   Support changes in client-server API.
-   Bug fixes to VOIP UI.
-   Various bug fixes to handling of changes to room member list.

Changes in synapse 0.1.2 (2014-08-29)
=====================================

Webclient:

-   Add basic call state UI for VoIP calls.

Changes in synapse 0.1.1 (2014-08-29)
=====================================

Homeserver:

-   Fix bug that caused the event stream to not notify some clients about changes.

Changes in synapse 0.1.0 (2014-08-29)
=====================================

Presence has been re-enabled in this release.

Homeserver:

-   Update client to server API, including:
    -   Use a more consistent url scheme.
    -   Provide more useful information in the initial sync api.
-   Change the presence handling to be much more efficient.
-   Change the presence server to server API to not require explicit polling of all users who share a room with a user.
-   Fix races in the event streaming logic.

Webclient:

-   Update to use new client to server API.
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

-   Completely change the database schema to support generic event types.
-   Improve presence reliability.
-   Improve reliability of joining remote rooms.
-   Fix bug where room join events were duplicated.
-   Improve initial sync API to return more information to the client.
-   Stop generating fake messages for room membership events.

Webclient:

-   Add tab completion of names.
-   Add ability to upload and send images.
-   Add profile pages.
-   Improve CSS layout of room.
-   Disambiguate identical display names.
-   Don't get remote users display names and avatars individually.
-   Use the new initial sync API to reduce number of round trips to the homeserver.
-   Change url scheme to use room aliases instead of room ids where known.
-   Increase longpoll timeout.

Changes in synapse 0.0.0 (2014-08-13)
=====================================

-   Initial alpha release
