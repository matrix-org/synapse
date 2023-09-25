Synapse 1.24.0 (2020-12-09)
===========================

Due to the two security issues highlighted below, server administrators are
encouraged to update Synapse. We are not aware of these vulnerabilities being
exploited in the wild.

Security advisory
-----------------

The following issues are fixed in v1.23.1 and v1.24.0.

- There is a denial of service attack
  ([CVE-2020-26257](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26257))
  against the federation APIs in which future events will not be correctly sent
  to other servers over federation. This affects all servers that participate in
  open federation. (Fixed in [#8776](https://github.com/matrix-org/synapse/pull/8776)).

- Synapse may be affected by OpenSSL
  [CVE-2020-1971](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971).
  Synapse administrators should ensure that they have the latest versions of
  the cryptography Python package installed.

To upgrade Synapse along with the cryptography package:

* Administrators using the [`matrix.org` Docker
  image](https://hub.docker.com/r/matrixdotorg/synapse/) or the [Debian/Ubuntu
  packages from
  `matrix.org`](https://matrix-org.github.io/synapse/latest/setup/installation.html#matrixorg-packages)
  should ensure that they have version 1.24.0 or 1.23.1 installed: these images include
  the updated packages.
* Administrators who have [installed Synapse from
  source](https://matrix-org.github.io/synapse/latest/setup/installation.html#installing-from-source)
  should upgrade the cryptography package within their virtualenv by running:
  ```sh
  <path_to_virtualenv>/bin/pip install 'cryptography>=3.3'
  ```
* Administrators who have installed Synapse from distribution packages should
  consult the information from their distributions.

Internal Changes
----------------

- Add a maximum version for pysaml2 on Python 3.5. ([\#8898](https://github.com/matrix-org/synapse/issues/8898))


Synapse 1.23.1 (2020-12-09)
===========================

Due to the two security issues highlighted below, server administrators are
encouraged to update Synapse. We are not aware of these vulnerabilities being
exploited in the wild.

Security advisory
-----------------

The following issues are fixed in v1.23.1 and v1.24.0.

- There is a denial of service attack
  ([CVE-2020-26257](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26257))
  against the federation APIs in which future events will not be correctly sent
  to other servers over federation. This affects all servers that participate in
  open federation. (Fixed in [#8776](https://github.com/matrix-org/synapse/pull/8776)).

- Synapse may be affected by OpenSSL
  [CVE-2020-1971](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1971).
  Synapse administrators should ensure that they have the latest versions of
  the cryptography Python package installed.

To upgrade Synapse along with the cryptography package:

* Administrators using the [`matrix.org` Docker
  image](https://hub.docker.com/r/matrixdotorg/synapse/) or the [Debian/Ubuntu
  packages from
  `matrix.org`](https://matrix-org.github.io/synapse/latest/setup/installation.html#matrixorg-packages)
  should ensure that they have version 1.24.0 or 1.23.1 installed: these images include
  the updated packages.
* Administrators who have [installed Synapse from
  source](https://matrix-org.github.io/synapse/latest/setup/installation.html#installing-from-source)
  should upgrade the cryptography package within their virtualenv by running:
  ```sh
  <path_to_virtualenv>/bin/pip install 'cryptography>=3.3'
  ```
* Administrators who have installed Synapse from distribution packages should
  consult the information from their distributions.

Bugfixes
--------

- Fix a bug in some federation APIs which could lead to unexpected behaviour if different parameters were set in the URI and the request body. ([\#8776](https://github.com/matrix-org/synapse/issues/8776))


Internal Changes
----------------

- Add a maximum version for pysaml2 on Python 3.5. ([\#8898](https://github.com/matrix-org/synapse/issues/8898))


Synapse 1.24.0rc2 (2020-12-04)
==============================

Bugfixes
--------

- Fix a regression in v1.24.0rc1 which failed to allow SAML mapping providers which were unable to redirect users to an additional page. ([\#8878](https://github.com/matrix-org/synapse/issues/8878))


Internal Changes
----------------

- Add support for the `prometheus_client` newer than 0.9.0. Contributed by Jordan Bancino. ([\#8875](https://github.com/matrix-org/synapse/issues/8875))


Synapse 1.24.0rc1 (2020-12-02)
==============================

Features
--------

- Add admin API for logging in as a user. ([\#8617](https://github.com/matrix-org/synapse/issues/8617))
- Allow specification of the SAML IdP if the metadata returns multiple IdPs. ([\#8630](https://github.com/matrix-org/synapse/issues/8630))
- Add support for re-trying generation of a localpart for OpenID Connect mapping providers. ([\#8801](https://github.com/matrix-org/synapse/issues/8801), [\#8855](https://github.com/matrix-org/synapse/issues/8855))
- Allow the `Date` header through CORS. Contributed by Nicolas Chamo. ([\#8804](https://github.com/matrix-org/synapse/issues/8804))
- Add a config option, `push.group_by_unread_count`, which controls whether unread message counts in push notifications are defined as "the number of rooms with unread messages" or "total unread messages". ([\#8820](https://github.com/matrix-org/synapse/issues/8820))
- Add `force_purge` option to delete-room admin api. ([\#8843](https://github.com/matrix-org/synapse/issues/8843))


Bugfixes
--------

- Fix a bug where appservices may be sent an excessive amount of read receipts and presence. Broke in v1.22.0. ([\#8744](https://github.com/matrix-org/synapse/issues/8744))
- Fix a bug in some federation APIs which could lead to unexpected behaviour if different parameters were set in the URI and the request body. ([\#8776](https://github.com/matrix-org/synapse/issues/8776))
- Fix a bug where synctl could spawn duplicate copies of a worker. Contributed by Waylon Cude. ([\#8798](https://github.com/matrix-org/synapse/issues/8798))
- Allow per-room profiles to be used for the server notice user. ([\#8799](https://github.com/matrix-org/synapse/issues/8799))
- Fix a bug where logging could break after a call to SIGHUP. ([\#8817](https://github.com/matrix-org/synapse/issues/8817))
- Fix `register_new_matrix_user` failing with "Bad Request" when trailing slash is included in server URL. Contributed by @angdraug. ([\#8823](https://github.com/matrix-org/synapse/issues/8823))
- Fix a minor long-standing bug in login, where we would offer the `password` login type if a custom auth provider supported it, even if password login was disabled. ([\#8835](https://github.com/matrix-org/synapse/issues/8835))
- Fix a long-standing bug which caused Synapse to require unspecified parameters during user-interactive authentication. ([\#8848](https://github.com/matrix-org/synapse/issues/8848))
- Fix a bug introduced in v1.20.0 where the user-agent and IP address reported during user registration for CAS, OpenID Connect, and SAML were of the wrong form. ([\#8784](https://github.com/matrix-org/synapse/issues/8784))


Improved Documentation
----------------------

- Clarify the usecase for a msisdn delegate. Contributed by Adrian Wannenmacher. ([\#8734](https://github.com/matrix-org/synapse/issues/8734))
- Remove extraneous comma from JSON example in User Admin API docs. ([\#8771](https://github.com/matrix-org/synapse/issues/8771))
- Update `turn-howto.md` with troubleshooting notes. ([\#8779](https://github.com/matrix-org/synapse/issues/8779))
- Fix the example on how to set the `Content-Type` header in nginx for the Client Well-Known URI. ([\#8793](https://github.com/matrix-org/synapse/issues/8793))
- Improve the documentation for the admin API to list all media in a room with respect to encrypted events. ([\#8795](https://github.com/matrix-org/synapse/issues/8795))
- Update the formatting of the `push` section of the homeserver config file to better align with the [code style guidelines](https://github.com/matrix-org/synapse/blob/develop/docs/code_style.md#configuration-file-format). ([\#8818](https://github.com/matrix-org/synapse/issues/8818))
- Improve documentation how to configure prometheus for workers. ([\#8822](https://github.com/matrix-org/synapse/issues/8822))
- Update example prometheus console. ([\#8824](https://github.com/matrix-org/synapse/issues/8824))


Deprecations and Removals
-------------------------

- Remove old `/_matrix/client/*/admin` endpoints which were deprecated since Synapse 1.20.0. ([\#8785](https://github.com/matrix-org/synapse/issues/8785))
- Disable pretty printing JSON responses for curl. Users who want pretty-printed output should use [jq](https://stedolan.github.io/jq/) in combination with curl. Contributed by @tulir. ([\#8833](https://github.com/matrix-org/synapse/issues/8833))


Internal Changes
----------------

- Simplify the way the `HomeServer` object caches its internal attributes. ([\#8565](https://github.com/matrix-org/synapse/issues/8565), [\#8851](https://github.com/matrix-org/synapse/issues/8851))
- Add an example and documentation for clock skew to the SAML2 sample configuration to allow for clock/time difference between the homserver and IdP. Contributed by @localguru. ([\#8731](https://github.com/matrix-org/synapse/issues/8731))
- Generalise `RoomMemberHandler._locally_reject_invite` to apply to more flows than just invite. ([\#8751](https://github.com/matrix-org/synapse/issues/8751))
- Generalise `RoomStore.maybe_store_room_on_invite` to handle other, non-invite membership events. ([\#8754](https://github.com/matrix-org/synapse/issues/8754))
- Refactor test utilities for injecting HTTP requests. ([\#8757](https://github.com/matrix-org/synapse/issues/8757), [\#8758](https://github.com/matrix-org/synapse/issues/8758), [\#8759](https://github.com/matrix-org/synapse/issues/8759), [\#8760](https://github.com/matrix-org/synapse/issues/8760), [\#8761](https://github.com/matrix-org/synapse/issues/8761), [\#8777](https://github.com/matrix-org/synapse/issues/8777))
- Consolidate logic between the OpenID Connect and SAML code. ([\#8765](https://github.com/matrix-org/synapse/issues/8765))
- Use `TYPE_CHECKING` instead of magic `MYPY` variable. ([\#8770](https://github.com/matrix-org/synapse/issues/8770))
- Add a commandline script to sign arbitrary json objects. ([\#8772](https://github.com/matrix-org/synapse/issues/8772))
- Minor log line improvements for the SSO mapping code used to generate Matrix IDs from SSO IDs. ([\#8773](https://github.com/matrix-org/synapse/issues/8773))
- Add additional error checking for OpenID Connect and SAML mapping providers. ([\#8774](https://github.com/matrix-org/synapse/issues/8774), [\#8800](https://github.com/matrix-org/synapse/issues/8800))
- Add type hints to HTTP abstractions. ([\#8806](https://github.com/matrix-org/synapse/issues/8806), [\#8812](https://github.com/matrix-org/synapse/issues/8812))
- Remove unnecessary function arguments and add typing to several membership replication classes. ([\#8809](https://github.com/matrix-org/synapse/issues/8809))
- Optimise the lookup for an invite from another homeserver when trying to reject it. ([\#8815](https://github.com/matrix-org/synapse/issues/8815))
- Add tests for `password_auth_provider`s. ([\#8819](https://github.com/matrix-org/synapse/issues/8819))
- Drop redundant database index on `event_json`. ([\#8845](https://github.com/matrix-org/synapse/issues/8845))
- Simplify `uk.half-shot.msc2778.login.application_service` login handler. ([\#8847](https://github.com/matrix-org/synapse/issues/8847))
- Refactor `password_auth_provider` support code. ([\#8849](https://github.com/matrix-org/synapse/issues/8849))
- Add missing `ordering` to background database updates. ([\#8850](https://github.com/matrix-org/synapse/issues/8850))
- Allow for specifying a room version when creating a room in unit tests via `RestHelper.create_room_as`. ([\#8854](https://github.com/matrix-org/synapse/issues/8854))


Synapse 1.23.0 (2020-11-18)
===========================

This release changes the way structured logging is configured. See the [upgrade notes](docs/upgrade.md#upgrading-to-v1230) for details.

**Note**: We are aware of a trivially exploitable denial of service vulnerability in versions of Synapse prior to 1.20.0. Complete details will be disclosed on Monday, November 23rd. If you have not upgraded recently, please do so.

Bugfixes
--------

- Fix a dependency versioning bug in the Dockerfile that prevented Synapse from starting. ([\#8767](https://github.com/matrix-org/synapse/issues/8767))


Synapse 1.23.0rc1 (2020-11-13)
==============================

Features
--------

- Add a push rule that highlights when a jitsi conference is created in a room. ([\#8286](https://github.com/matrix-org/synapse/issues/8286))
- Add an admin api to delete a single file or files that were not used for a defined time from server. Contributed by @dklimpel. ([\#8519](https://github.com/matrix-org/synapse/issues/8519))
- Split admin API for reported events (`GET /_synapse/admin/v1/event_reports`) into detail and list endpoints. This is a breaking change to #8217 which was introduced in Synapse v1.21.0. Those who already use this API should check their scripts. Contributed by @dklimpel. ([\#8539](https://github.com/matrix-org/synapse/issues/8539))
- Support generating structured logs via the standard logging configuration. ([\#8607](https://github.com/matrix-org/synapse/issues/8607), [\#8685](https://github.com/matrix-org/synapse/issues/8685))
- Add an admin API to allow server admins to list users' pushers. Contributed by @dklimpel. ([\#8610](https://github.com/matrix-org/synapse/issues/8610), [\#8689](https://github.com/matrix-org/synapse/issues/8689))
- Add an admin API `GET /_synapse/admin/v1/users/<user_id>/media` to get information about uploaded media. Contributed by @dklimpel. ([\#8647](https://github.com/matrix-org/synapse/issues/8647))
- Add an admin API for local user media statistics. Contributed by @dklimpel. ([\#8700](https://github.com/matrix-org/synapse/issues/8700))
- Add `displayname` to Shared-Secret Registration for admins. ([\#8722](https://github.com/matrix-org/synapse/issues/8722))


Bugfixes
--------

- Fix fetching of E2E cross signing keys over federation when only one of the master key and device signing key is cached already. ([\#8455](https://github.com/matrix-org/synapse/issues/8455))
- Fix a bug where Synapse would blindly forward bad responses from federation to clients when retrieving profile information. ([\#8580](https://github.com/matrix-org/synapse/issues/8580))
- Fix a bug where the account validity endpoint would silently fail if the user ID did not have an expiration time. It now returns a 400 error. ([\#8620](https://github.com/matrix-org/synapse/issues/8620))
- Fix email notifications for invites without local state. ([\#8627](https://github.com/matrix-org/synapse/issues/8627))
- Fix handling of invalid group IDs to return a 400 rather than log an exception and return a 500. ([\#8628](https://github.com/matrix-org/synapse/issues/8628))
- Fix handling of User-Agent headers that are invalid UTF-8, which caused user agents of users to not get correctly recorded. ([\#8632](https://github.com/matrix-org/synapse/issues/8632))
- Fix a bug in the `joined_rooms` admin API if the user has never joined any rooms. The bug was introduced, along with the API, in v1.21.0. ([\#8643](https://github.com/matrix-org/synapse/issues/8643))
- Fix exception during handling multiple concurrent requests for remote media when using multiple media repositories. ([\#8682](https://github.com/matrix-org/synapse/issues/8682))
- Fix bug that prevented Synapse from recovering after losing connection to the database. ([\#8726](https://github.com/matrix-org/synapse/issues/8726))
- Fix bug where the `/_synapse/admin/v1/send_server_notice` API could send notices to non-notice rooms. ([\#8728](https://github.com/matrix-org/synapse/issues/8728))
- Fix PostgreSQL port script fails when DB has no backfilled events. Broke in v1.21.0. ([\#8729](https://github.com/matrix-org/synapse/issues/8729))
- Fix PostgreSQL port script to correctly handle foreign key constraints. Broke in v1.21.0. ([\#8730](https://github.com/matrix-org/synapse/issues/8730))
- Fix PostgreSQL port script so that it can be run again after a failure. Broke in v1.21.0. ([\#8755](https://github.com/matrix-org/synapse/issues/8755))


Improved Documentation
----------------------

- Instructions for Azure AD in the OpenID Connect documentation. Contributed by peterk. ([\#8582](https://github.com/matrix-org/synapse/issues/8582))
- Improve the sample configuration for single sign-on providers. ([\#8635](https://github.com/matrix-org/synapse/issues/8635))
- Fix the filepath of Dex's example config and the link to Dex's Getting Started guide in the OpenID Connect docs. ([\#8657](https://github.com/matrix-org/synapse/issues/8657))
- Note support for Python 3.9. ([\#8665](https://github.com/matrix-org/synapse/issues/8665))
- Minor updates to docs on running tests. ([\#8666](https://github.com/matrix-org/synapse/issues/8666))
- Interlink prometheus/grafana documentation. ([\#8667](https://github.com/matrix-org/synapse/issues/8667))
- Notes on SSO logins and media_repository worker. ([\#8701](https://github.com/matrix-org/synapse/issues/8701))
- Document experimental support for running multiple event persisters. ([\#8706](https://github.com/matrix-org/synapse/issues/8706))
- Add information regarding the various sources of, and expected contributions to, Synapse's documentation to `CONTRIBUTING.md`. ([\#8714](https://github.com/matrix-org/synapse/issues/8714))
- Migrate documentation `docs/admin_api/event_reports` to markdown. ([\#8742](https://github.com/matrix-org/synapse/issues/8742))
- Add some helpful hints to the README for new Synapse developers. Contributed by @chagai95. ([\#8746](https://github.com/matrix-org/synapse/issues/8746))


Internal Changes
----------------

- Optimise `/createRoom` with multiple invited users. ([\#8559](https://github.com/matrix-org/synapse/issues/8559))
- Implement and use an `@lru_cache` decorator. ([\#8595](https://github.com/matrix-org/synapse/issues/8595))
- Don't instantiate Requester directly. ([\#8614](https://github.com/matrix-org/synapse/issues/8614))
- Type hints for `RegistrationStore`. ([\#8615](https://github.com/matrix-org/synapse/issues/8615))
- Change schema to support access tokens belonging to one user but granting access to another. ([\#8616](https://github.com/matrix-org/synapse/issues/8616))
- Remove unused OPTIONS handlers. ([\#8621](https://github.com/matrix-org/synapse/issues/8621))
- Run `mypy` as part of the lint.sh script. ([\#8633](https://github.com/matrix-org/synapse/issues/8633))
- Correct Synapse's PyPI package name in the OpenID Connect installation instructions. ([\#8634](https://github.com/matrix-org/synapse/issues/8634))
- Catch exceptions during initialization of `password_providers`. Contributed by Nicolai Søborg. ([\#8636](https://github.com/matrix-org/synapse/issues/8636))
- Fix typos and spelling errors in the code. ([\#8639](https://github.com/matrix-org/synapse/issues/8639))
- Reduce number of OpenTracing spans started. ([\#8640](https://github.com/matrix-org/synapse/issues/8640), [\#8668](https://github.com/matrix-org/synapse/issues/8668), [\#8670](https://github.com/matrix-org/synapse/issues/8670))
- Add field `total` to device list in admin API. ([\#8644](https://github.com/matrix-org/synapse/issues/8644))
- Add more type hints to the application services code. ([\#8655](https://github.com/matrix-org/synapse/issues/8655), [\#8693](https://github.com/matrix-org/synapse/issues/8693))
- Tell Black to format code for Python 3.5. ([\#8664](https://github.com/matrix-org/synapse/issues/8664))
- Don't pull event from DB when handling replication traffic. ([\#8669](https://github.com/matrix-org/synapse/issues/8669))
- Abstract some invite-related code in preparation for landing knocking. ([\#8671](https://github.com/matrix-org/synapse/issues/8671), [\#8688](https://github.com/matrix-org/synapse/issues/8688))
- Clarify representation of events in logfiles. ([\#8679](https://github.com/matrix-org/synapse/issues/8679))
- Don't require `hiredis` package to be installed to run unit tests. ([\#8680](https://github.com/matrix-org/synapse/issues/8680))
- Fix typing info on cache call signature to accept `on_invalidate`. ([\#8684](https://github.com/matrix-org/synapse/issues/8684))
- Fail tests if they do not await coroutines. ([\#8690](https://github.com/matrix-org/synapse/issues/8690))
- Improve start time by adding an index to `e2e_cross_signing_keys.stream_id`. ([\#8694](https://github.com/matrix-org/synapse/issues/8694))
- Re-organize the structured logging code to separate the TCP transport handling from the JSON formatting. ([\#8697](https://github.com/matrix-org/synapse/issues/8697))
- Use Python 3.8 in Docker images by default. ([\#8698](https://github.com/matrix-org/synapse/issues/8698))
- Remove the "draft" status of the Room Details Admin API. ([\#8702](https://github.com/matrix-org/synapse/issues/8702))
- Improve the error returned when a non-string displayname or avatar_url is used when updating a user's profile. ([\#8705](https://github.com/matrix-org/synapse/issues/8705))
- Block attempts by clients to send server ACLs, or redactions of server ACLs, that would result in the local server being blocked from the room. ([\#8708](https://github.com/matrix-org/synapse/issues/8708))
- Add metrics the allow the local sysadmin to track 3PID `/requestToken` requests. ([\#8712](https://github.com/matrix-org/synapse/issues/8712))
- Consolidate duplicated lists of purged tables that are checked in tests. ([\#8713](https://github.com/matrix-org/synapse/issues/8713))
- Add some `mdui:UIInfo` element examples for `saml2_config` in the homeserver config. ([\#8718](https://github.com/matrix-org/synapse/issues/8718))
- Improve the error message returned when a remote server incorrectly sets the `Content-Type` header in response to a JSON request. ([\#8719](https://github.com/matrix-org/synapse/issues/8719))
- Speed up repeated state resolutions on the same room by caching event ID to auth event ID lookups. ([\#8752](https://github.com/matrix-org/synapse/issues/8752))


Synapse 1.22.1 (2020-10-30)
===========================

Bugfixes
--------

- Fix a bug where an appservice may not be forwarded events for a room it was recently invited to. Broke in v1.22.0. ([\#8676](https://github.com/matrix-org/synapse/issues/8676))
- Fix `Object of type frozendict is not JSON serializable` exceptions when using third-party event rules. Broke in v1.22.0. ([\#8678](https://github.com/matrix-org/synapse/issues/8678))


Synapse 1.22.0 (2020-10-27)
===========================

No significant changes.


Synapse 1.22.0rc2 (2020-10-26)
==============================

Bugfixes
--------

- Fix bugs where ephemeral events were not sent to appservices. Broke in v1.22.0rc1. ([\#8648](https://github.com/matrix-org/synapse/issues/8648), [\#8656](https://github.com/matrix-org/synapse/issues/8656))
- Fix `user_daily_visits` table to not have duplicate rows per user/device due to multiple user agents. Broke in v1.22.0rc1. ([\#8654](https://github.com/matrix-org/synapse/issues/8654))

Synapse 1.22.0rc1 (2020-10-22)
==============================

Features
--------

- Add a configuration option for always using the "userinfo endpoint" for OpenID Connect. This fixes support for some identity providers, e.g. GitLab. Contributed by Benjamin Koch. ([\#7658](https://github.com/matrix-org/synapse/issues/7658))
- Add ability for `ThirdPartyEventRules` modules to query and manipulate whether a room is in the public rooms directory. ([\#8292](https://github.com/matrix-org/synapse/issues/8292), [\#8467](https://github.com/matrix-org/synapse/issues/8467))
- Add support for olm fallback keys ([MSC2732](https://github.com/matrix-org/matrix-doc/pull/2732)). ([\#8312](https://github.com/matrix-org/synapse/issues/8312), [\#8501](https://github.com/matrix-org/synapse/issues/8501))
- Add support for running background tasks in a separate worker process. ([\#8369](https://github.com/matrix-org/synapse/issues/8369), [\#8458](https://github.com/matrix-org/synapse/issues/8458), [\#8489](https://github.com/matrix-org/synapse/issues/8489), [\#8513](https://github.com/matrix-org/synapse/issues/8513), [\#8544](https://github.com/matrix-org/synapse/issues/8544), [\#8599](https://github.com/matrix-org/synapse/issues/8599))
- Add support for device dehydration ([MSC2697](https://github.com/matrix-org/matrix-doc/pull/2697)). ([\#8380](https://github.com/matrix-org/synapse/issues/8380))
- Add support for [MSC2409](https://github.com/matrix-org/matrix-doc/pull/2409), which allows sending typing, read receipts, and presence events to appservices. ([\#8437](https://github.com/matrix-org/synapse/issues/8437), [\#8590](https://github.com/matrix-org/synapse/issues/8590))
- Change default room version to "6", per [MSC2788](https://github.com/matrix-org/matrix-doc/pull/2788). ([\#8461](https://github.com/matrix-org/synapse/issues/8461))
- Add the ability to send non-membership events into a room via the `ModuleApi`. ([\#8479](https://github.com/matrix-org/synapse/issues/8479))
- Increase default upload size limit from 10M to 50M. Contributed by @Akkowicz. ([\#8502](https://github.com/matrix-org/synapse/issues/8502))
- Add support for modifying event content in `ThirdPartyRules` modules. ([\#8535](https://github.com/matrix-org/synapse/issues/8535), [\#8564](https://github.com/matrix-org/synapse/issues/8564))


Bugfixes
--------

- Fix a longstanding bug where invalid ignored users in account data could break clients. ([\#8454](https://github.com/matrix-org/synapse/issues/8454))
- Fix a bug where backfilling a room with an event that was missing the `redacts` field would break. ([\#8457](https://github.com/matrix-org/synapse/issues/8457))
- Don't attempt to respond to some requests if the client has already disconnected. ([\#8465](https://github.com/matrix-org/synapse/issues/8465))
- Fix message duplication if something goes wrong after persisting the event. ([\#8476](https://github.com/matrix-org/synapse/issues/8476))
- Fix incremental sync returning an incorrect `prev_batch` token in timeline section, which when used to paginate returned events that were included in the incremental sync. Broken since v0.16.0. ([\#8486](https://github.com/matrix-org/synapse/issues/8486))
- Expose the `uk.half-shot.msc2778.login.application_service` to clients from the login API. This feature was added in v1.21.0, but was not exposed as a potential login flow. ([\#8504](https://github.com/matrix-org/synapse/issues/8504))
- Fix error code for `/profile/{userId}/displayname` to be `M_BAD_JSON`. ([\#8517](https://github.com/matrix-org/synapse/issues/8517))
- Fix a bug introduced in v1.7.0 that could cause Synapse to insert values from non-state `m.room.retention` events into the `room_retention` database table. ([\#8527](https://github.com/matrix-org/synapse/issues/8527))
- Fix not sending events over federation when using sharded event writers. ([\#8536](https://github.com/matrix-org/synapse/issues/8536))
- Fix a long standing bug where email notifications for encrypted messages were blank. ([\#8545](https://github.com/matrix-org/synapse/issues/8545))
- Fix increase in the number of `There was no active span...` errors logged when using OpenTracing. ([\#8567](https://github.com/matrix-org/synapse/issues/8567))
- Fix a bug that prevented errors encountered during execution of the `synapse_port_db` from being correctly printed. ([\#8585](https://github.com/matrix-org/synapse/issues/8585))
- Fix appservice transactions to only include a maximum of 100 persistent and 100 ephemeral events. ([\#8606](https://github.com/matrix-org/synapse/issues/8606))


Updates to the Docker image
---------------------------

- Added multi-arch support (arm64,arm/v7) for the docker images. Contributed by @maquis196. ([\#7921](https://github.com/matrix-org/synapse/issues/7921))
- Add support for passing commandline args to the synapse process. Contributed by @samuel-p. ([\#8390](https://github.com/matrix-org/synapse/issues/8390))


Improved Documentation
----------------------

- Update the directions for using the manhole with coroutines. ([\#8462](https://github.com/matrix-org/synapse/issues/8462))
- Improve readme by adding new shield.io badges. ([\#8493](https://github.com/matrix-org/synapse/issues/8493))
- Added note about docker in manhole.md regarding which ip address to bind to. Contributed by @Maquis196. ([\#8526](https://github.com/matrix-org/synapse/issues/8526))
- Document the new behaviour of the `allowed_lifetime_min` and `allowed_lifetime_max` settings in the room retention configuration. ([\#8529](https://github.com/matrix-org/synapse/issues/8529))


Deprecations and Removals
-------------------------

- Drop unused `device_max_stream_id` table. ([\#8589](https://github.com/matrix-org/synapse/issues/8589))


Internal Changes
----------------

- Check for unreachable code with mypy. ([\#8432](https://github.com/matrix-org/synapse/issues/8432))
- Add unit test for event persister sharding. ([\#8433](https://github.com/matrix-org/synapse/issues/8433))
- Allow events to be sent to clients sooner when using sharded event persisters. ([\#8439](https://github.com/matrix-org/synapse/issues/8439), [\#8488](https://github.com/matrix-org/synapse/issues/8488), [\#8496](https://github.com/matrix-org/synapse/issues/8496), [\#8499](https://github.com/matrix-org/synapse/issues/8499))
- Configure `public_baseurl` when using demo scripts. ([\#8443](https://github.com/matrix-org/synapse/issues/8443))
- Add SQL logging on queries that happen during startup. ([\#8448](https://github.com/matrix-org/synapse/issues/8448))
- Speed up unit tests when using PostgreSQL. ([\#8450](https://github.com/matrix-org/synapse/issues/8450))
- Remove redundant database loads of stream_ordering for events we already have. ([\#8452](https://github.com/matrix-org/synapse/issues/8452))
- Reduce inconsistencies between codepaths for membership and non-membership events. ([\#8463](https://github.com/matrix-org/synapse/issues/8463))
- Combine `SpamCheckerApi` with the more generic `ModuleApi`. ([\#8464](https://github.com/matrix-org/synapse/issues/8464))
- Additional testing for `ThirdPartyEventRules`. ([\#8468](https://github.com/matrix-org/synapse/issues/8468))
- Add `-d` option to `./scripts-dev/lint.sh` to lint files that have changed since the last git commit. ([\#8472](https://github.com/matrix-org/synapse/issues/8472))
- Unblacklist some sytests. ([\#8474](https://github.com/matrix-org/synapse/issues/8474))
- Include the log level in the phone home stats. ([\#8477](https://github.com/matrix-org/synapse/issues/8477))
- Remove outdated sphinx documentation, scripts and configuration. ([\#8480](https://github.com/matrix-org/synapse/issues/8480))
- Clarify error message when plugin config parsers raise an error. ([\#8492](https://github.com/matrix-org/synapse/issues/8492))
- Remove the deprecated `Handlers` object. ([\#8494](https://github.com/matrix-org/synapse/issues/8494))
- Fix a threadsafety bug in unit tests. ([\#8497](https://github.com/matrix-org/synapse/issues/8497))
- Add user agent to user_daily_visits table. ([\#8503](https://github.com/matrix-org/synapse/issues/8503))
- Add type hints to various parts of the code base. ([\#8407](https://github.com/matrix-org/synapse/issues/8407), [\#8505](https://github.com/matrix-org/synapse/issues/8505), [\#8507](https://github.com/matrix-org/synapse/issues/8507), [\#8547](https://github.com/matrix-org/synapse/issues/8547), [\#8562](https://github.com/matrix-org/synapse/issues/8562), [\#8609](https://github.com/matrix-org/synapse/issues/8609))
- Remove unused code from the test framework. ([\#8514](https://github.com/matrix-org/synapse/issues/8514))
- Apply some internal fixes to the `HomeServer` class to make its code more idiomatic and statically-verifiable. ([\#8515](https://github.com/matrix-org/synapse/issues/8515))
- Factor out common code between `RoomMemberHandler._locally_reject_invite` and `EventCreationHandler.create_event`. ([\#8537](https://github.com/matrix-org/synapse/issues/8537))
- Improve database performance by executing more queries without starting transactions. ([\#8542](https://github.com/matrix-org/synapse/issues/8542))
- Rename `Cache` to `DeferredCache`, to better reflect its purpose. ([\#8548](https://github.com/matrix-org/synapse/issues/8548))
- Move metric registration code down into `LruCache`. ([\#8561](https://github.com/matrix-org/synapse/issues/8561), [\#8591](https://github.com/matrix-org/synapse/issues/8591))
- Replace `DeferredCache` with the lighter-weight `LruCache` where possible. ([\#8563](https://github.com/matrix-org/synapse/issues/8563))
- Add virtualenv-generated folders to `.gitignore`. ([\#8566](https://github.com/matrix-org/synapse/issues/8566))
- Add `get_immediate` method to `DeferredCache`. ([\#8568](https://github.com/matrix-org/synapse/issues/8568))
- Fix mypy not properly checking across the codebase, additionally, fix a typing assertion error in `handlers/auth.py`. ([\#8569](https://github.com/matrix-org/synapse/issues/8569))
- Fix `synmark` benchmark runner. ([\#8571](https://github.com/matrix-org/synapse/issues/8571))
- Modify `DeferredCache.get()` to return `Deferred`s instead of `ObservableDeferred`s. ([\#8572](https://github.com/matrix-org/synapse/issues/8572))
- Adjust a protocol-type definition to fit `sqlite3` assertions. ([\#8577](https://github.com/matrix-org/synapse/issues/8577))
- Support macOS on the `synmark` benchmark runner. ([\#8578](https://github.com/matrix-org/synapse/issues/8578))
- Update `mypy` static type checker to 0.790. ([\#8583](https://github.com/matrix-org/synapse/issues/8583), [\#8600](https://github.com/matrix-org/synapse/issues/8600))
- Re-organize the structured logging code to separate the TCP transport handling from the JSON formatting. ([\#8587](https://github.com/matrix-org/synapse/issues/8587))
- Remove extraneous unittest logging decorators from unit tests. ([\#8592](https://github.com/matrix-org/synapse/issues/8592))
- Minor optimisations in caching code. ([\#8593](https://github.com/matrix-org/synapse/issues/8593), [\#8594](https://github.com/matrix-org/synapse/issues/8594))


Synapse 1.21.2 (2020-10-15)
===========================

Debian packages and Docker images have been rebuilt using the latest versions of dependency libraries, including authlib 0.15.1. Please see bugfixes below.

Security advisory
-----------------

* HTML pages served via Synapse were vulnerable to cross-site scripting (XSS)
  attacks. All server administrators are encouraged to upgrade.
  ([\#8444](https://github.com/matrix-org/synapse/pull/8444))
  ([CVE-2020-26891](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26891))

  This fix was originally included in v1.21.0 but was missing a security advisory.

  This was reported by [Denis Kasak](https://github.com/dkasak).

Bugfixes
--------

- Fix rare bug where sending an event would fail due to a racey assertion. ([\#8530](https://github.com/matrix-org/synapse/issues/8530))
- An updated version of the authlib dependency is included in the Docker and Debian images to fix an issue using OpenID Connect. See [\#8534](https://github.com/matrix-org/synapse/issues/8534) for details.


Synapse 1.21.1 (2020-10-13)
===========================

This release fixes a regression in v1.21.0 that prevented debian packages from being built.
It is otherwise identical to v1.21.0.

Synapse 1.21.0 (2020-10-12)
===========================

No significant changes since v1.21.0rc3.

As [noted in
v1.20.0](https://github.com/matrix-org/synapse/blob/release-v1.21.0/CHANGES.md#synapse-1200-2020-09-22),
a future release will drop support for accessing Synapse's
[Admin API](https://github.com/matrix-org/synapse/tree/master/docs/admin_api) under the
`/_matrix/client/*` endpoint prefixes. At that point, the Admin API will only
be accessible under `/_synapse/admin`.


Synapse 1.21.0rc3 (2020-10-08)
==============================

Bugfixes
--------

- Fix duplication of events on high traffic servers, caused by PostgreSQL `could not serialize access due to concurrent update` errors. ([\#8456](https://github.com/matrix-org/synapse/issues/8456))


Internal Changes
----------------

- Add Groovy Gorilla to the list of distributions we build `.deb`s for. ([\#8475](https://github.com/matrix-org/synapse/issues/8475))


Synapse 1.21.0rc2 (2020-10-02)
==============================

Features
--------

- Convert additional templates from inline HTML to Jinja2 templates. ([\#8444](https://github.com/matrix-org/synapse/issues/8444))

Bugfixes
--------

- Fix a regression in v1.21.0rc1 which broke thumbnails of remote media. ([\#8438](https://github.com/matrix-org/synapse/issues/8438))
- Do not expose the experimental `uk.half-shot.msc2778.login.application_service` flow in the login API, which caused a compatibility problem with Element iOS. ([\#8440](https://github.com/matrix-org/synapse/issues/8440))
- Fix malformed log line in new federation "catch up" logic. ([\#8442](https://github.com/matrix-org/synapse/issues/8442))
- Fix DB query on startup for negative streams which caused long start up times. Introduced in [\#8374](https://github.com/matrix-org/synapse/issues/8374). ([\#8447](https://github.com/matrix-org/synapse/issues/8447))


Synapse 1.21.0rc1 (2020-10-01)
==============================

Features
--------

- Require the user to confirm that their password should be reset after clicking the email confirmation link. ([\#8004](https://github.com/matrix-org/synapse/issues/8004))
- Add an admin API `GET /_synapse/admin/v1/event_reports` to read entries of table `event_reports`. Contributed by @dklimpel. ([\#8217](https://github.com/matrix-org/synapse/issues/8217))
- Consolidate the SSO error template across all configuration. ([\#8248](https://github.com/matrix-org/synapse/issues/8248), [\#8405](https://github.com/matrix-org/synapse/issues/8405))
- Add a configuration option to specify a whitelist of domains that a user can be redirected to after validating their email or phone number. ([\#8275](https://github.com/matrix-org/synapse/issues/8275), [\#8417](https://github.com/matrix-org/synapse/issues/8417))
- Add experimental support for sharding event persister. ([\#8294](https://github.com/matrix-org/synapse/issues/8294), [\#8387](https://github.com/matrix-org/synapse/issues/8387), [\#8396](https://github.com/matrix-org/synapse/issues/8396), [\#8419](https://github.com/matrix-org/synapse/issues/8419))
- Add the room topic and avatar to the room details admin API. ([\#8305](https://github.com/matrix-org/synapse/issues/8305))
- Add an admin API for querying rooms where a user is a member. Contributed by @dklimpel. ([\#8306](https://github.com/matrix-org/synapse/issues/8306))
- Add `uk.half-shot.msc2778.login.application_service` login type to allow appservices to login. ([\#8320](https://github.com/matrix-org/synapse/issues/8320))
- Add a configuration option that allows existing users to log in with OpenID Connect. Contributed by @BBBSnowball and @OmmyZhang. ([\#8345](https://github.com/matrix-org/synapse/issues/8345))
- Add prometheus metrics for replication requests. ([\#8406](https://github.com/matrix-org/synapse/issues/8406))
- Support passing additional single sign-on parameters to the client. ([\#8413](https://github.com/matrix-org/synapse/issues/8413))
- Add experimental reporting of metrics on expensive rooms for state-resolution. ([\#8420](https://github.com/matrix-org/synapse/issues/8420))
- Add experimental prometheus metric to track numbers of "large" rooms for state resolutiom. ([\#8425](https://github.com/matrix-org/synapse/issues/8425))
- Add prometheus metrics to track federation delays. ([\#8430](https://github.com/matrix-org/synapse/issues/8430))


Bugfixes
--------

- Fix a bug in the media repository where remote thumbnails with the same size but different crop methods would overwrite each other. Contributed by @deepbluev7. ([\#7124](https://github.com/matrix-org/synapse/issues/7124))
- Fix inconsistent handling of non-existent push rules, and stop tracking the `enabled` state of removed push rules. ([\#7796](https://github.com/matrix-org/synapse/issues/7796))
- Fix a longstanding bug when storing a media file with an empty `upload_name`. ([\#7905](https://github.com/matrix-org/synapse/issues/7905))
- Fix messages not being sent over federation until an event is sent into the same room. ([\#8230](https://github.com/matrix-org/synapse/issues/8230), [\#8247](https://github.com/matrix-org/synapse/issues/8247), [\#8258](https://github.com/matrix-org/synapse/issues/8258), [\#8272](https://github.com/matrix-org/synapse/issues/8272), [\#8322](https://github.com/matrix-org/synapse/issues/8322))
- Fix a longstanding bug where files that could not be thumbnailed would result in an Internal Server Error. ([\#8236](https://github.com/matrix-org/synapse/issues/8236), [\#8435](https://github.com/matrix-org/synapse/issues/8435))
- Upgrade minimum version of `canonicaljson` to version 1.4.0, to fix an unicode encoding issue. ([\#8262](https://github.com/matrix-org/synapse/issues/8262))
- Fix longstanding bug which could lead to incomplete database upgrades on SQLite. ([\#8265](https://github.com/matrix-org/synapse/issues/8265))
- Fix stack overflow when stderr is redirected to the logging system, and the logging system encounters an error. ([\#8268](https://github.com/matrix-org/synapse/issues/8268))
- Fix a bug which cause the logging system to report errors, if `DEBUG` was enabled and no `context` filter was applied. ([\#8278](https://github.com/matrix-org/synapse/issues/8278))
- Fix edge case where push could get delayed for a user until a later event was pushed. ([\#8287](https://github.com/matrix-org/synapse/issues/8287))
- Fix fetching malformed events from remote servers. ([\#8324](https://github.com/matrix-org/synapse/issues/8324))
- Fix `UnboundLocalError` from occurring when appservices send a malformed register request. ([\#8329](https://github.com/matrix-org/synapse/issues/8329))
- Don't send push notifications to expired user accounts. ([\#8353](https://github.com/matrix-org/synapse/issues/8353))
- Fix a regression in v1.19.0 with reactivating users through the admin API. ([\#8362](https://github.com/matrix-org/synapse/issues/8362))
- Fix a bug where during device registration the length of the device name wasn't limited. ([\#8364](https://github.com/matrix-org/synapse/issues/8364))
- Include `guest_access` in the fields that are checked for null bytes when updating `room_stats_state`. Broke in v1.7.2. ([\#8373](https://github.com/matrix-org/synapse/issues/8373))
- Fix theoretical race condition where events are not sent down `/sync` if the synchrotron worker is restarted without restarting other workers. ([\#8374](https://github.com/matrix-org/synapse/issues/8374))
- Fix a bug which could cause errors in rooms with malformed membership events, on servers using sqlite. ([\#8385](https://github.com/matrix-org/synapse/issues/8385))
- Fix "Re-starting finished log context" warning when receiving an event we already had over federation. ([\#8398](https://github.com/matrix-org/synapse/issues/8398))
- Fix incorrect handling of timeouts on outgoing HTTP requests. ([\#8400](https://github.com/matrix-org/synapse/issues/8400))
- Fix a regression in v1.20.0 in the `synapse_port_db` script regarding the `ui_auth_sessions_ips` table. ([\#8410](https://github.com/matrix-org/synapse/issues/8410))
- Remove unnecessary 3PID registration check when resetting password via an email address. Bug introduced in v0.34.0rc2. ([\#8414](https://github.com/matrix-org/synapse/issues/8414))


Improved Documentation
----------------------

- Add `/_synapse/client` to the reverse proxy documentation. ([\#8227](https://github.com/matrix-org/synapse/issues/8227))
- Add note to the reverse proxy settings documentation about disabling Apache's mod_security2. Contributed by Julian Fietkau (@jfietkau). ([\#8375](https://github.com/matrix-org/synapse/issues/8375))
- Improve description of `server_name` config option in `homserver.yaml`. ([\#8415](https://github.com/matrix-org/synapse/issues/8415))


Deprecations and Removals
-------------------------

- Drop support for `prometheus_client` older than 0.4.0. ([\#8426](https://github.com/matrix-org/synapse/issues/8426))


Internal Changes
----------------

- Fix tests on distros which disable TLSv1.0. Contributed by @danc86. ([\#8208](https://github.com/matrix-org/synapse/issues/8208))
- Simplify the distributor code to avoid unnecessary work. ([\#8216](https://github.com/matrix-org/synapse/issues/8216))
- Remove the `populate_stats_process_rooms_2` background job and restore functionality to `populate_stats_process_rooms`. ([\#8243](https://github.com/matrix-org/synapse/issues/8243))
- Clean up type hints for `PaginationConfig`. ([\#8250](https://github.com/matrix-org/synapse/issues/8250), [\#8282](https://github.com/matrix-org/synapse/issues/8282))
- Track the latest event for every destination and room for catch-up after federation outage. ([\#8256](https://github.com/matrix-org/synapse/issues/8256))
- Fix non-user visible bug in implementation of `MultiWriterIdGenerator.get_current_token_for_writer`. ([\#8257](https://github.com/matrix-org/synapse/issues/8257))
- Switch to the JSON implementation from the standard library. ([\#8259](https://github.com/matrix-org/synapse/issues/8259))
- Add type hints to `synapse.util.async_helpers`. ([\#8260](https://github.com/matrix-org/synapse/issues/8260))
- Simplify tests that mock asynchronous functions. ([\#8261](https://github.com/matrix-org/synapse/issues/8261))
- Add type hints to `StreamToken` and `RoomStreamToken` classes. ([\#8279](https://github.com/matrix-org/synapse/issues/8279))
- Change `StreamToken.room_key` to be a `RoomStreamToken` instance. ([\#8281](https://github.com/matrix-org/synapse/issues/8281))
- Refactor notifier code to correctly use the max event stream position. ([\#8288](https://github.com/matrix-org/synapse/issues/8288))
- Use slotted classes where possible. ([\#8296](https://github.com/matrix-org/synapse/issues/8296))
- Support testing the local Synapse checkout against the [Complement homeserver test suite](https://github.com/matrix-org/complement/). ([\#8317](https://github.com/matrix-org/synapse/issues/8317))
- Update outdated usages of `metaclass` to python 3 syntax. ([\#8326](https://github.com/matrix-org/synapse/issues/8326))
- Move lint-related dependencies to package-extra field, update CONTRIBUTING.md to utilise this. ([\#8330](https://github.com/matrix-org/synapse/issues/8330), [\#8377](https://github.com/matrix-org/synapse/issues/8377))
- Use the `admin_patterns` helper in additional locations. ([\#8331](https://github.com/matrix-org/synapse/issues/8331))
- Fix test logging to allow braces in log output. ([\#8335](https://github.com/matrix-org/synapse/issues/8335))
- Remove `__future__` imports related to Python 2 compatibility. ([\#8337](https://github.com/matrix-org/synapse/issues/8337))
- Simplify `super()` calls to Python 3 syntax. ([\#8344](https://github.com/matrix-org/synapse/issues/8344))
- Fix bad merge from `release-v1.20.0` branch to `develop`. ([\#8354](https://github.com/matrix-org/synapse/issues/8354))
- Factor out a `_send_dummy_event_for_room` method. ([\#8370](https://github.com/matrix-org/synapse/issues/8370))
- Improve logging of state resolution. ([\#8371](https://github.com/matrix-org/synapse/issues/8371))
- Add type annotations to `SimpleHttpClient`. ([\#8372](https://github.com/matrix-org/synapse/issues/8372))
- Refactor ID generators to use `async with` syntax. ([\#8383](https://github.com/matrix-org/synapse/issues/8383))
- Add `EventStreamPosition` type. ([\#8388](https://github.com/matrix-org/synapse/issues/8388))
- Create a mechanism for marking tests "logcontext clean". ([\#8399](https://github.com/matrix-org/synapse/issues/8399))
- A pair of tiny cleanups in the federation request code. ([\#8401](https://github.com/matrix-org/synapse/issues/8401))
- Add checks on startup that PostgreSQL sequences are consistent with their associated tables. ([\#8402](https://github.com/matrix-org/synapse/issues/8402))
- Do not include appservice users when calculating the total MAU for a server. ([\#8404](https://github.com/matrix-org/synapse/issues/8404))
- Typing fixes for `synapse.handlers.federation`. ([\#8422](https://github.com/matrix-org/synapse/issues/8422))
- Various refactors to simplify stream token handling. ([\#8423](https://github.com/matrix-org/synapse/issues/8423))
- Make stream token serializing/deserializing async. ([\#8427](https://github.com/matrix-org/synapse/issues/8427))


Synapse 1.20.1 (2020-09-24)
===========================

Bugfixes
--------

- Fix a bug introduced in v1.20.0 which caused the `synapse_port_db` script to fail. ([\#8386](https://github.com/matrix-org/synapse/issues/8386))
- Fix a bug introduced in v1.20.0 which caused variables to be incorrectly escaped in Jinja2 templates. ([\#8394](https://github.com/matrix-org/synapse/issues/8394))


Synapse 1.20.0 (2020-09-22)
===========================

No significant changes since v1.20.0rc5.

Removal warning
---------------

Historically, the [Synapse Admin
API](https://github.com/matrix-org/synapse/tree/master/docs) has been
accessible under the `/_matrix/client/api/v1/admin`,
`/_matrix/client/unstable/admin`, `/_matrix/client/r0/admin` and
`/_synapse/admin` prefixes. In a future release, we will be dropping support
for accessing Synapse's Admin API using the `/_matrix/client/*` prefixes.

From that point, the Admin API will only be accessible under `/_synapse/admin`.
This makes it easier for homeserver admins to lock down external access to the
Admin API endpoints.

Synapse 1.20.0rc5 (2020-09-18)
==============================

In addition to the below, Synapse 1.20.0rc5 also includes the bug fix that was included in 1.19.3.

Features
--------

- Add flags to the `/versions` endpoint for whether new rooms default to using E2EE. ([\#8343](https://github.com/matrix-org/synapse/issues/8343))


Bugfixes
--------

- Fix rate limiting of federation `/send` requests. ([\#8342](https://github.com/matrix-org/synapse/issues/8342))
- Fix a longstanding bug where back pagination over federation could get stuck if it failed to handle a received event. ([\#8349](https://github.com/matrix-org/synapse/issues/8349))


Internal Changes
----------------

- Blacklist [MSC2753](https://github.com/matrix-org/matrix-doc/pull/2753) SyTests until it is implemented. ([\#8285](https://github.com/matrix-org/synapse/issues/8285))


Synapse 1.19.3 (2020-09-18)
===========================

Bugfixes
--------

- Partially mitigate bug where newly joined servers couldn't get past events in a room when there is a malformed event. ([\#8350](https://github.com/matrix-org/synapse/issues/8350))


Synapse 1.20.0rc4 (2020-09-16)
==============================

Synapse 1.20.0rc4 is identical to 1.20.0rc3, with the addition of the security fix that was included in 1.19.2.


Synapse 1.19.2 (2020-09-16)
===========================

Due to the issue below server admins are encouraged to upgrade as soon as possible.

Bugfixes
--------

- Fix joining rooms over federation that include malformed events. ([\#8324](https://github.com/matrix-org/synapse/issues/8324))


Synapse 1.20.0rc3 (2020-09-11)
==============================

Bugfixes
--------

- Fix a bug introduced in v1.20.0rc1 where the wrong exception was raised when invalid JSON data is encountered. ([\#8291](https://github.com/matrix-org/synapse/issues/8291))


Synapse 1.20.0rc2 (2020-09-09)
==============================

Bugfixes
--------

- Fix a bug introduced in v1.20.0rc1 causing some features related to notifications to misbehave following the implementation of unread counts. ([\#8280](https://github.com/matrix-org/synapse/issues/8280))


Synapse 1.20.0rc1 (2020-09-08)
==============================

Removal warning
---------------

Some older clients used a [disallowed character](https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-register-email-requesttoken) (`:`) in the `client_secret` parameter of various endpoints. The incorrect behaviour was allowed for backwards compatibility, but is now being removed from Synapse as most users have updated their client. Further context can be found at [\#6766](https://github.com/matrix-org/synapse/issues/6766).

Features
--------

- Add an endpoint to query your shared rooms with another user as an implementation of [MSC2666](https://github.com/matrix-org/matrix-doc/pull/2666). ([\#7785](https://github.com/matrix-org/synapse/issues/7785))
- Iteratively encode JSON to avoid blocking the reactor. ([\#8013](https://github.com/matrix-org/synapse/issues/8013), [\#8116](https://github.com/matrix-org/synapse/issues/8116))
- Add support for shadow-banning users (ignoring any message send requests). ([\#8034](https://github.com/matrix-org/synapse/issues/8034), [\#8092](https://github.com/matrix-org/synapse/issues/8092), [\#8095](https://github.com/matrix-org/synapse/issues/8095), [\#8142](https://github.com/matrix-org/synapse/issues/8142), [\#8152](https://github.com/matrix-org/synapse/issues/8152), [\#8157](https://github.com/matrix-org/synapse/issues/8157), [\#8158](https://github.com/matrix-org/synapse/issues/8158), [\#8176](https://github.com/matrix-org/synapse/issues/8176))
- Use the default template file when its equivalent is not found in a custom template directory. ([\#8037](https://github.com/matrix-org/synapse/issues/8037), [\#8107](https://github.com/matrix-org/synapse/issues/8107), [\#8252](https://github.com/matrix-org/synapse/issues/8252))
- Add unread messages count to sync responses, as specified in [MSC2654](https://github.com/matrix-org/matrix-doc/pull/2654). ([\#8059](https://github.com/matrix-org/synapse/issues/8059), [\#8254](https://github.com/matrix-org/synapse/issues/8254), [\#8270](https://github.com/matrix-org/synapse/issues/8270), [\#8274](https://github.com/matrix-org/synapse/issues/8274))
- Optimise `/federation/v1/user/devices/` API by only returning devices with encryption keys. ([\#8198](https://github.com/matrix-org/synapse/issues/8198))


Bugfixes
--------

- Fix a memory leak by limiting the length of time that messages will be queued for a remote server that has been unreachable. ([\#7864](https://github.com/matrix-org/synapse/issues/7864))
- Fix `Re-starting finished log context PUT-nnnn` warning when event persistence failed. ([\#8081](https://github.com/matrix-org/synapse/issues/8081))
- Synapse now correctly enforces the valid characters in the `client_secret` parameter used in various endpoints. ([\#8101](https://github.com/matrix-org/synapse/issues/8101))
- Fix a bug introduced in v1.7.2 impacting message retention policies that would allow federated homeservers to dictate a retention period that's lower than the configured minimum allowed duration in the configuration file. ([\#8104](https://github.com/matrix-org/synapse/issues/8104))
- Fix a long-standing bug where invalid JSON would be accepted by Synapse. ([\#8106](https://github.com/matrix-org/synapse/issues/8106))
- Fix a bug introduced in Synapse v1.12.0 which could cause `/sync` requests to fail with a 404 if you had a very old outstanding room invite. ([\#8110](https://github.com/matrix-org/synapse/issues/8110))
- Return a proper error code when the rooms of an invalid group are requested. ([\#8129](https://github.com/matrix-org/synapse/issues/8129))
- Fix a bug which could cause a leaked postgres connection if synapse was set to daemonize. ([\#8131](https://github.com/matrix-org/synapse/issues/8131))
- Clarify the error code if a user tries to register with a numeric ID. This bug was introduced in v1.15.0. ([\#8135](https://github.com/matrix-org/synapse/issues/8135))
- Fix a bug where appservices with ratelimiting disabled would still be ratelimited when joining rooms. This bug was introduced in v1.19.0. ([\#8139](https://github.com/matrix-org/synapse/issues/8139))
- Fix logging in via OpenID Connect with a provider that uses integer user IDs. ([\#8190](https://github.com/matrix-org/synapse/issues/8190))
- Fix a longstanding bug where user directory updates could break when unexpected profile data was included in events. ([\#8223](https://github.com/matrix-org/synapse/issues/8223))
- Fix a longstanding bug where stats updates could break when unexpected profile data was included in events. ([\#8226](https://github.com/matrix-org/synapse/issues/8226))
- Fix slow start times for large servers by removing a table scan of the `users` table from startup code. ([\#8271](https://github.com/matrix-org/synapse/issues/8271))


Updates to the Docker image
---------------------------

- Fix builds of the Docker image on non-x86 platforms. ([\#8144](https://github.com/matrix-org/synapse/issues/8144))
- Added curl for healthcheck support and readme updates for the change. Contributed by @maquis196. ([\#8147](https://github.com/matrix-org/synapse/issues/8147))


Improved Documentation
----------------------

- Link to matrix-synapse-rest-password-provider in the password provider documentation. ([\#8111](https://github.com/matrix-org/synapse/issues/8111))
- Updated documentation to note that Synapse does not follow `HTTP 308` redirects due to an upstream library not supporting them. Contributed by Ryan Cole. ([\#8120](https://github.com/matrix-org/synapse/issues/8120))
- Explain better what GDPR-erased means when deactivating a user. ([\#8189](https://github.com/matrix-org/synapse/issues/8189))


Internal Changes
----------------

- Add filter `name` to the `/users` admin API, which filters by user ID or displayname. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#7377](https://github.com/matrix-org/synapse/issues/7377), [\#8163](https://github.com/matrix-org/synapse/issues/8163))
- Reduce run times of some unit tests by advancing the reactor a fewer number of times. ([\#7757](https://github.com/matrix-org/synapse/issues/7757))
- Don't fail `/submit_token` requests on incorrect session ID if `request_token_inhibit_3pid_errors` is turned on. ([\#7991](https://github.com/matrix-org/synapse/issues/7991))
- Convert various parts of the codebase to async/await. ([\#8071](https://github.com/matrix-org/synapse/issues/8071), [\#8072](https://github.com/matrix-org/synapse/issues/8072), [\#8074](https://github.com/matrix-org/synapse/issues/8074), [\#8075](https://github.com/matrix-org/synapse/issues/8075), [\#8076](https://github.com/matrix-org/synapse/issues/8076), [\#8087](https://github.com/matrix-org/synapse/issues/8087), [\#8100](https://github.com/matrix-org/synapse/issues/8100), [\#8119](https://github.com/matrix-org/synapse/issues/8119), [\#8121](https://github.com/matrix-org/synapse/issues/8121), [\#8133](https://github.com/matrix-org/synapse/issues/8133), [\#8156](https://github.com/matrix-org/synapse/issues/8156), [\#8162](https://github.com/matrix-org/synapse/issues/8162), [\#8166](https://github.com/matrix-org/synapse/issues/8166), [\#8168](https://github.com/matrix-org/synapse/issues/8168), [\#8173](https://github.com/matrix-org/synapse/issues/8173), [\#8191](https://github.com/matrix-org/synapse/issues/8191), [\#8192](https://github.com/matrix-org/synapse/issues/8192), [\#8193](https://github.com/matrix-org/synapse/issues/8193), [\#8194](https://github.com/matrix-org/synapse/issues/8194), [\#8195](https://github.com/matrix-org/synapse/issues/8195), [\#8197](https://github.com/matrix-org/synapse/issues/8197), [\#8199](https://github.com/matrix-org/synapse/issues/8199), [\#8200](https://github.com/matrix-org/synapse/issues/8200), [\#8201](https://github.com/matrix-org/synapse/issues/8201), [\#8202](https://github.com/matrix-org/synapse/issues/8202), [\#8207](https://github.com/matrix-org/synapse/issues/8207), [\#8213](https://github.com/matrix-org/synapse/issues/8213), [\#8214](https://github.com/matrix-org/synapse/issues/8214))
- Remove some unused database functions. ([\#8085](https://github.com/matrix-org/synapse/issues/8085))
- Add type hints to various parts of the codebase. ([\#8090](https://github.com/matrix-org/synapse/issues/8090), [\#8127](https://github.com/matrix-org/synapse/issues/8127), [\#8187](https://github.com/matrix-org/synapse/issues/8187), [\#8241](https://github.com/matrix-org/synapse/issues/8241), [\#8140](https://github.com/matrix-org/synapse/issues/8140), [\#8183](https://github.com/matrix-org/synapse/issues/8183), [\#8232](https://github.com/matrix-org/synapse/issues/8232), [\#8235](https://github.com/matrix-org/synapse/issues/8235), [\#8237](https://github.com/matrix-org/synapse/issues/8237), [\#8244](https://github.com/matrix-org/synapse/issues/8244))
- Return the previous stream token if a non-member event is a duplicate. ([\#8093](https://github.com/matrix-org/synapse/issues/8093), [\#8112](https://github.com/matrix-org/synapse/issues/8112))
- Separate `get_current_token` into two since there are two different use cases for it. ([\#8113](https://github.com/matrix-org/synapse/issues/8113))
- Remove `ChainedIdGenerator`. ([\#8123](https://github.com/matrix-org/synapse/issues/8123))
- Reduce the amount of whitespace in JSON stored and sent in responses. ([\#8124](https://github.com/matrix-org/synapse/issues/8124))
- Update the test federation client to handle streaming responses. ([\#8130](https://github.com/matrix-org/synapse/issues/8130))
- Micro-optimisations to `get_auth_chain_ids`. ([\#8132](https://github.com/matrix-org/synapse/issues/8132))
- Refactor `StreamIdGenerator` and `MultiWriterIdGenerator` to have the same interface. ([\#8161](https://github.com/matrix-org/synapse/issues/8161))
- Add functions to `MultiWriterIdGen` used by events stream. ([\#8164](https://github.com/matrix-org/synapse/issues/8164), [\#8179](https://github.com/matrix-org/synapse/issues/8179))
- Fix tests that were broken due to the merge of 1.19.1. ([\#8167](https://github.com/matrix-org/synapse/issues/8167))
- Make `SlavedIdTracker.advance` have the same interface as `MultiWriterIDGenerator`. ([\#8171](https://github.com/matrix-org/synapse/issues/8171))
- Remove unused `is_guest` parameter from, and add safeguard to, `MessageHandler.get_room_data`. ([\#8174](https://github.com/matrix-org/synapse/issues/8174), [\#8181](https://github.com/matrix-org/synapse/issues/8181))
- Standardize the mypy configuration. ([\#8175](https://github.com/matrix-org/synapse/issues/8175))
- Refactor some of `LoginRestServlet`'s helper methods, and move them to `AuthHandler` for easier reuse. ([\#8182](https://github.com/matrix-org/synapse/issues/8182))
- Fix `wait_for_stream_position` to allow multiple waiters on same stream ID. ([\#8196](https://github.com/matrix-org/synapse/issues/8196))
- Make `MultiWriterIDGenerator` work for streams that use negative values. ([\#8203](https://github.com/matrix-org/synapse/issues/8203))
- Refactor queries for device keys and cross-signatures. ([\#8204](https://github.com/matrix-org/synapse/issues/8204), [\#8205](https://github.com/matrix-org/synapse/issues/8205), [\#8222](https://github.com/matrix-org/synapse/issues/8222), [\#8224](https://github.com/matrix-org/synapse/issues/8224), [\#8225](https://github.com/matrix-org/synapse/issues/8225), [\#8231](https://github.com/matrix-org/synapse/issues/8231), [\#8233](https://github.com/matrix-org/synapse/issues/8233), [\#8234](https://github.com/matrix-org/synapse/issues/8234))
- Fix type hints for functions decorated with `@cached`. ([\#8240](https://github.com/matrix-org/synapse/issues/8240))
- Remove obsolete `order` field from federation send queues. ([\#8245](https://github.com/matrix-org/synapse/issues/8245))
- Stop sub-classing from object. ([\#8249](https://github.com/matrix-org/synapse/issues/8249))
- Add more logging to debug slow startup. ([\#8264](https://github.com/matrix-org/synapse/issues/8264))
- Do not attempt to upgrade database schema on worker processes. ([\#8266](https://github.com/matrix-org/synapse/issues/8266), [\#8276](https://github.com/matrix-org/synapse/issues/8276))


Synapse 1.19.1 (2020-08-27)
===========================

No significant changes.


Synapse 1.19.1rc1 (2020-08-25)
==============================

Bugfixes
--------

- Fix a bug introduced in v1.19.0 where appservices with ratelimiting disabled would still be ratelimited when joining rooms. ([\#8139](https://github.com/matrix-org/synapse/issues/8139))
- Fix a bug introduced in v1.19.0 that would cause e.g. profile updates to fail due to incorrect application of rate limits on join requests. ([\#8153](https://github.com/matrix-org/synapse/issues/8153))


Synapse 1.19.0 (2020-08-17)
===========================

No significant changes since 1.19.0rc1.

Removal warning
---------------

As outlined in the [previous release](https://github.com/matrix-org/synapse/releases/tag/v1.18.0),
we are no longer publishing Docker images with the `-py3` tag suffix. On top of that, we have also removed the
`latest-py3` tag. Please see
[the announcement in the upgrade notes for 1.18.0](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1180).


Synapse 1.19.0rc1 (2020-08-13)
==============================

Features
--------

- Add option to allow server admins to join rooms which fail complexity checks. Contributed by @lugino-emeritus. ([\#7902](https://github.com/matrix-org/synapse/issues/7902))
- Add an option to purge room or not with delete room admin endpoint (`POST /_synapse/admin/v1/rooms/<room_id>/delete`). Contributed by @dklimpel. ([\#7964](https://github.com/matrix-org/synapse/issues/7964))
- Add rate limiting to users joining rooms. ([\#8008](https://github.com/matrix-org/synapse/issues/8008))
- Add a `/health` endpoint to every configured HTTP listener that can be used as a health check endpoint by load balancers. ([\#8048](https://github.com/matrix-org/synapse/issues/8048))
- Allow login to be blocked based on the values of SAML attributes. ([\#8052](https://github.com/matrix-org/synapse/issues/8052))
- Allow guest access to the `GET /_matrix/client/r0/rooms/{room_id}/members` endpoint, according to MSC2689. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#7314](https://github.com/matrix-org/synapse/issues/7314))


Bugfixes
--------

- Fix a bug introduced in Synapse v1.7.2 which caused inaccurate membership counts in the room directory. ([\#7977](https://github.com/matrix-org/synapse/issues/7977))
- Fix a long standing bug: 'Duplicate key value violates unique constraint "event_relations_id"' when message retention is configured. ([\#7978](https://github.com/matrix-org/synapse/issues/7978))
- Fix "no create event in auth events" when trying to reject invitation after inviter leaves. Bug introduced in Synapse v1.10.0. ([\#7980](https://github.com/matrix-org/synapse/issues/7980))
- Fix various comments and minor discrepancies in server notices code. ([\#7996](https://github.com/matrix-org/synapse/issues/7996))
- Fix a long standing bug where HTTP HEAD requests resulted in a 400 error. ([\#7999](https://github.com/matrix-org/synapse/issues/7999))
- Fix a long-standing bug which caused two copies of some log lines to be written when synctl was used along with a MemoryHandler logger. ([\#8011](https://github.com/matrix-org/synapse/issues/8011), [\#8012](https://github.com/matrix-org/synapse/issues/8012))


Updates to the Docker image
---------------------------

- We no longer publish Docker images with the `-py3` tag suffix, as [announced in the upgrade notes](https://github.com/matrix-org/synapse/blob/develop/docs/upgrade.md#upgrading-to-v1180). ([\#8056](https://github.com/matrix-org/synapse/issues/8056))


Improved Documentation
----------------------

- Document how to set up a client .well-known file and fix several pieces of outdated documentation. ([\#7899](https://github.com/matrix-org/synapse/issues/7899))
- Improve workers docs. ([\#7990](https://github.com/matrix-org/synapse/issues/7990), [\#8000](https://github.com/matrix-org/synapse/issues/8000))
- Fix typo in `docs/workers.md`. ([\#7992](https://github.com/matrix-org/synapse/issues/7992))
- Add documentation for how to undo a room shutdown. ([\#7998](https://github.com/matrix-org/synapse/issues/7998), [\#8010](https://github.com/matrix-org/synapse/issues/8010))


Internal Changes
----------------

- Reduce the amount of whitespace in JSON stored and sent in responses. Contributed by David Vo. ([\#7372](https://github.com/matrix-org/synapse/issues/7372))
- Switch to the JSON implementation from the standard library and bump the minimum version of the canonicaljson library to 1.2.0. ([\#7936](https://github.com/matrix-org/synapse/issues/7936), [\#7979](https://github.com/matrix-org/synapse/issues/7979))
- Convert various parts of the codebase to async/await. ([\#7947](https://github.com/matrix-org/synapse/issues/7947), [\#7948](https://github.com/matrix-org/synapse/issues/7948), [\#7949](https://github.com/matrix-org/synapse/issues/7949), [\#7951](https://github.com/matrix-org/synapse/issues/7951), [\#7963](https://github.com/matrix-org/synapse/issues/7963), [\#7973](https://github.com/matrix-org/synapse/issues/7973), [\#7975](https://github.com/matrix-org/synapse/issues/7975), [\#7976](https://github.com/matrix-org/synapse/issues/7976), [\#7981](https://github.com/matrix-org/synapse/issues/7981), [\#7987](https://github.com/matrix-org/synapse/issues/7987), [\#7989](https://github.com/matrix-org/synapse/issues/7989), [\#8003](https://github.com/matrix-org/synapse/issues/8003), [\#8014](https://github.com/matrix-org/synapse/issues/8014), [\#8016](https://github.com/matrix-org/synapse/issues/8016), [\#8027](https://github.com/matrix-org/synapse/issues/8027), [\#8031](https://github.com/matrix-org/synapse/issues/8031), [\#8032](https://github.com/matrix-org/synapse/issues/8032), [\#8035](https://github.com/matrix-org/synapse/issues/8035), [\#8042](https://github.com/matrix-org/synapse/issues/8042), [\#8044](https://github.com/matrix-org/synapse/issues/8044), [\#8045](https://github.com/matrix-org/synapse/issues/8045), [\#8061](https://github.com/matrix-org/synapse/issues/8061), [\#8062](https://github.com/matrix-org/synapse/issues/8062), [\#8063](https://github.com/matrix-org/synapse/issues/8063), [\#8066](https://github.com/matrix-org/synapse/issues/8066), [\#8069](https://github.com/matrix-org/synapse/issues/8069), [\#8070](https://github.com/matrix-org/synapse/issues/8070))
- Move some database-related log lines from the default logger to the database/transaction loggers. ([\#7952](https://github.com/matrix-org/synapse/issues/7952))
- Add a script to detect source code files using non-unix line terminators. ([\#7965](https://github.com/matrix-org/synapse/issues/7965), [\#7970](https://github.com/matrix-org/synapse/issues/7970))
- Log the SAML session ID during creation. ([\#7971](https://github.com/matrix-org/synapse/issues/7971))
- Implement new experimental push rules for some users. ([\#7997](https://github.com/matrix-org/synapse/issues/7997))
- Remove redundant and unreliable signature check for v1 Identity Service lookup responses. ([\#8001](https://github.com/matrix-org/synapse/issues/8001))
- Improve the performance of the register endpoint. ([\#8009](https://github.com/matrix-org/synapse/issues/8009))
- Reduce less useful output in the newsfragment CI step. Add a link to the changelog section of the contributing guide on error. ([\#8024](https://github.com/matrix-org/synapse/issues/8024))
- Rename storage layer objects to be more sensible. ([\#8033](https://github.com/matrix-org/synapse/issues/8033))
- Change the default log config to reduce disk I/O and storage for new servers. ([\#8040](https://github.com/matrix-org/synapse/issues/8040))
- Add an assertion on `prev_events` in `create_new_client_event`. ([\#8041](https://github.com/matrix-org/synapse/issues/8041))
- Add a comment to `ServerContextFactory` about the use of `SSLv23_METHOD`. ([\#8043](https://github.com/matrix-org/synapse/issues/8043))
- Log `OPTIONS` requests at `DEBUG` rather than `INFO` level to reduce amount logged at `INFO`. ([\#8049](https://github.com/matrix-org/synapse/issues/8049))
- Reduce amount of outbound request logging at `INFO` level. ([\#8050](https://github.com/matrix-org/synapse/issues/8050))
- It is no longer necessary to explicitly define `filters` in the logging configuration. (Continuing to do so is redundant but harmless.) ([\#8051](https://github.com/matrix-org/synapse/issues/8051))
- Add and improve type hints. ([\#8058](https://github.com/matrix-org/synapse/issues/8058), [\#8064](https://github.com/matrix-org/synapse/issues/8064), [\#8060](https://github.com/matrix-org/synapse/issues/8060), [\#8067](https://github.com/matrix-org/synapse/issues/8067))


Synapse 1.18.0 (2020-07-30)
===========================

Deprecation Warnings
--------------------

### Docker Tags with `-py3` Suffix

From 10th August 2020, we will no longer publish Docker images with the `-py3` tag suffix. The images tagged with the `-py3` suffix have been identical to the non-suffixed tags since release 0.99.0, and the suffix is obsolete.

On 10th August, we will remove the `latest-py3` tag. Existing per-release tags (such as `v1.18.0-py3`) will not be removed, but no new `-py3` tags will be added.

Scripts relying on the `-py3` suffix will need to be updated.


### TCP-based Replication

When setting up worker processes, we now recommend the use of a Redis server for replication. The old direct TCP connection method is deprecated and will be removed in a future release. See [docs/workers.md](https://github.com/matrix-org/synapse/blob/release-v1.18.0/docs/workers.md) for more details.


Improved Documentation
----------------------

- Update worker docs with latest enhancements. ([\#7969](https://github.com/matrix-org/synapse/issues/7969))


Synapse 1.18.0rc2 (2020-07-28)
==============================

Bugfixes
--------

- Fix an `AssertionError` exception introduced in v1.18.0rc1. ([\#7876](https://github.com/matrix-org/synapse/issues/7876))
- Fix experimental support for moving typing off master when worker is restarted, which is broken in v1.18.0rc1. ([\#7967](https://github.com/matrix-org/synapse/issues/7967))


Internal Changes
----------------

- Further optimise queueing of inbound replication commands. ([\#7876](https://github.com/matrix-org/synapse/issues/7876))


Synapse 1.18.0rc1 (2020-07-27)
==============================

Features
--------

- Include room states on invite events that are sent to application services. Contributed by @Sorunome. ([\#6455](https://github.com/matrix-org/synapse/issues/6455))
- Add delete room admin endpoint (`POST /_synapse/admin/v1/rooms/<room_id>/delete`). Contributed by @dklimpel. ([\#7613](https://github.com/matrix-org/synapse/issues/7613), [\#7953](https://github.com/matrix-org/synapse/issues/7953))
- Add experimental support for running multiple federation sender processes. ([\#7798](https://github.com/matrix-org/synapse/issues/7798))
- Add the option to validate the `iss` and `aud` claims for JWT logins. ([\#7827](https://github.com/matrix-org/synapse/issues/7827))
- Add support for handling registration requests across multiple client reader workers. ([\#7830](https://github.com/matrix-org/synapse/issues/7830))
- Add an admin API to list the users in a room. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#7842](https://github.com/matrix-org/synapse/issues/7842))
- Allow email subjects to be customised through Synapse's configuration. ([\#7846](https://github.com/matrix-org/synapse/issues/7846))
- Add the ability to re-activate an account from the admin API. ([\#7847](https://github.com/matrix-org/synapse/issues/7847), [\#7908](https://github.com/matrix-org/synapse/issues/7908))
- Add experimental support for running multiple pusher workers. ([\#7855](https://github.com/matrix-org/synapse/issues/7855))
- Add experimental support for moving typing off master. ([\#7869](https://github.com/matrix-org/synapse/issues/7869), [\#7959](https://github.com/matrix-org/synapse/issues/7959))
- Report CPU metrics to prometheus for time spent processing replication commands. ([\#7879](https://github.com/matrix-org/synapse/issues/7879))
- Support oEmbed for media previews. ([\#7920](https://github.com/matrix-org/synapse/issues/7920))
- Abort federation requests where the client disconnects before the ratelimiter expires. ([\#7930](https://github.com/matrix-org/synapse/issues/7930))
- Cache responses to `/_matrix/federation/v1/state_ids` to reduce duplicated work. ([\#7931](https://github.com/matrix-org/synapse/issues/7931))


Bugfixes
--------

- Fix detection of out of sync remote device lists when receiving events from remote users. ([\#7815](https://github.com/matrix-org/synapse/issues/7815))
- Fix bug where Synapse fails to process an incoming event over federation if the server is missing too much of the event's auth chain. ([\#7817](https://github.com/matrix-org/synapse/issues/7817))
- Fix a bug causing Synapse to misinterpret the value `off` for `encryption_enabled_by_default_for_room_type` in its configuration file(s) if that value isn't surrounded by quotes. This bug was introduced in v1.16.0. ([\#7822](https://github.com/matrix-org/synapse/issues/7822))
- Fix bug where we did not always pass in `app_name` or `server_name` to email templates, including e.g. for registration emails. ([\#7829](https://github.com/matrix-org/synapse/issues/7829))
- Errors which occur while using the non-standard JWT login now return the proper error: `403 Forbidden` with an error code of `M_FORBIDDEN`. ([\#7844](https://github.com/matrix-org/synapse/issues/7844))
- Fix "AttributeError: 'str' object has no attribute 'get'" error message when applying per-room message retention policies. The bug was introduced in Synapse 1.7.0. ([\#7850](https://github.com/matrix-org/synapse/issues/7850))
- Fix a bug introduced in Synapse 1.10.0 which could cause a "no create event in auth events" error during room creation. ([\#7854](https://github.com/matrix-org/synapse/issues/7854))
- Fix a bug which allowed empty rooms to be rejoined over federation. ([\#7859](https://github.com/matrix-org/synapse/issues/7859))
- Fix 'Unable to find a suitable guest user ID' error when using multiple client_reader workers. ([\#7866](https://github.com/matrix-org/synapse/issues/7866))
- Fix a long standing bug where the tracing of async functions with opentracing was broken. ([\#7872](https://github.com/matrix-org/synapse/issues/7872), [\#7961](https://github.com/matrix-org/synapse/issues/7961))
- Fix "TypeError in `synapse.notifier`" exceptions. ([\#7880](https://github.com/matrix-org/synapse/issues/7880))
- Fix deprecation warning due to invalid escape sequences. ([\#7895](https://github.com/matrix-org/synapse/issues/7895))


Updates to the Docker image
---------------------------

- Base docker image on Debian Buster rather than Alpine Linux. Contributed by @maquis196. ([\#7839](https://github.com/matrix-org/synapse/issues/7839))


Improved Documentation
----------------------

- Provide instructions on using `register_new_matrix_user` via docker. ([\#7885](https://github.com/matrix-org/synapse/issues/7885))
- Change the sample config postgres user section to use `synapse_user` instead of `synapse` to align with the documentation. ([\#7889](https://github.com/matrix-org/synapse/issues/7889))
- Reorder database paragraphs to promote postgres over sqlite. ([\#7933](https://github.com/matrix-org/synapse/issues/7933))
- Update the dates of ACME v1's end of life in [`ACME.md`](https://github.com/matrix-org/synapse/blob/master/docs/ACME.md). ([\#7934](https://github.com/matrix-org/synapse/issues/7934))


Deprecations and Removals
-------------------------

- Remove unused `synapse_replication_tcp_resource_invalidate_cache` prometheus metric. ([\#7878](https://github.com/matrix-org/synapse/issues/7878))
- Remove Ubuntu Eoan from the list of `.deb` packages that we build as it is now end-of-life. Contributed by @gary-kim. ([\#7888](https://github.com/matrix-org/synapse/issues/7888))


Internal Changes
----------------

- Switch parts of the codebase from `simplejson` to the standard library `json`. ([\#7802](https://github.com/matrix-org/synapse/issues/7802))
- Add type hints to the http server code and remove an unused parameter. ([\#7813](https://github.com/matrix-org/synapse/issues/7813))
- Add type hints to synapse.api.errors module. ([\#7820](https://github.com/matrix-org/synapse/issues/7820))
- Ensure that calls to `json.dumps` are compatible with the standard library json. ([\#7836](https://github.com/matrix-org/synapse/issues/7836))
- Remove redundant `retry_on_integrity_error` wrapper for event persistence code. ([\#7848](https://github.com/matrix-org/synapse/issues/7848))
- Consistently use `db_to_json` to convert from database values to JSON objects. ([\#7849](https://github.com/matrix-org/synapse/issues/7849))
- Convert various parts of the codebase to async/await. ([\#7851](https://github.com/matrix-org/synapse/issues/7851), [\#7860](https://github.com/matrix-org/synapse/issues/7860), [\#7868](https://github.com/matrix-org/synapse/issues/7868), [\#7871](https://github.com/matrix-org/synapse/issues/7871), [\#7873](https://github.com/matrix-org/synapse/issues/7873), [\#7874](https://github.com/matrix-org/synapse/issues/7874), [\#7884](https://github.com/matrix-org/synapse/issues/7884), [\#7912](https://github.com/matrix-org/synapse/issues/7912), [\#7935](https://github.com/matrix-org/synapse/issues/7935), [\#7939](https://github.com/matrix-org/synapse/issues/7939), [\#7942](https://github.com/matrix-org/synapse/issues/7942), [\#7944](https://github.com/matrix-org/synapse/issues/7944))
- Add support for handling registration requests across multiple client reader workers. ([\#7853](https://github.com/matrix-org/synapse/issues/7853))
- Small performance improvement in typing processing. ([\#7856](https://github.com/matrix-org/synapse/issues/7856))
- The default value of `filter_timeline_limit` was changed from -1 (no limit) to 100. ([\#7858](https://github.com/matrix-org/synapse/issues/7858))
- Optimise queueing of inbound replication commands. ([\#7861](https://github.com/matrix-org/synapse/issues/7861))
- Add some type annotations to `HomeServer` and `BaseHandler`. ([\#7870](https://github.com/matrix-org/synapse/issues/7870))
- Clean up `PreserveLoggingContext`. ([\#7877](https://github.com/matrix-org/synapse/issues/7877))
- Change "unknown room version" logging from 'error' to 'warning'. ([\#7881](https://github.com/matrix-org/synapse/issues/7881))
- Stop using `device_max_stream_id` table and just use `device_inbox.stream_id`. ([\#7882](https://github.com/matrix-org/synapse/issues/7882))
- Return an empty body for OPTIONS requests. ([\#7886](https://github.com/matrix-org/synapse/issues/7886))
- Fix typo in generated config file. Contributed by @ThiefMaster. ([\#7890](https://github.com/matrix-org/synapse/issues/7890))
- Import ABC from `collections.abc` for Python 3.10 compatibility. ([\#7892](https://github.com/matrix-org/synapse/issues/7892))
- Remove unused functions `time_function`, `trace_function`, `get_previous_frames`
  and `get_previous_frame` from `synapse.logging.utils` module. ([\#7897](https://github.com/matrix-org/synapse/issues/7897))
- Lint the `contrib/` directory in CI and linting scripts, add `synctl` to the linting script for consistency with CI. ([\#7914](https://github.com/matrix-org/synapse/issues/7914))
- Use Element CSS and logo in notification emails when app name is Element. ([\#7919](https://github.com/matrix-org/synapse/issues/7919))
- Optimisation to /sync handling: skip serializing the response if the client has already disconnected. ([\#7927](https://github.com/matrix-org/synapse/issues/7927))
- When a client disconnects, don't log it as 'Error processing request'. ([\#7928](https://github.com/matrix-org/synapse/issues/7928))
- Add debugging to `/sync` response generation (disabled by default). ([\#7929](https://github.com/matrix-org/synapse/issues/7929))
- Update comments that refer to Deferreds for async functions. ([\#7945](https://github.com/matrix-org/synapse/issues/7945))
- Simplify error handling in federation handler. ([\#7950](https://github.com/matrix-org/synapse/issues/7950))


Synapse 1.17.0 (2020-07-13)
===========================

Synapse 1.17.0 is identical to 1.17.0rc1, with the addition of the fix that was included in 1.16.1.


Synapse 1.16.1 (2020-07-10)
===========================

In some distributions of Synapse 1.16.0, we incorrectly included a database migration which added a new, unused table. This release removes the redundant table.

Bugfixes
--------

- Drop table `local_rejections_stream` which was incorrectly added in Synapse 1.16.0. ([\#7816](https://github.com/matrix-org/synapse/issues/7816), [b1beb3ff5](https://github.com/matrix-org/synapse/commit/b1beb3ff5))


Synapse 1.17.0rc1 (2020-07-09)
==============================

Bugfixes
--------

- Fix inconsistent handling of upper and lower case in email addresses when used as identifiers for login, etc. Contributed by @dklimpel. ([\#7021](https://github.com/matrix-org/synapse/issues/7021))
- Fix "Tried to close a non-active scope!" error messages when opentracing is enabled. ([\#7732](https://github.com/matrix-org/synapse/issues/7732))
- Fix incorrect error message when database CTYPE was set incorrectly. ([\#7760](https://github.com/matrix-org/synapse/issues/7760))
- Fix to not ignore `set_tweak` actions in Push Rules that have no `value`, as permitted by the specification. ([\#7766](https://github.com/matrix-org/synapse/issues/7766))
- Fix synctl to handle empty config files correctly. Contributed by @kotovalexarian. ([\#7779](https://github.com/matrix-org/synapse/issues/7779))
- Fixes a long standing bug in worker mode where worker information was saved in the devices table instead of the original IP address and user agent. ([\#7797](https://github.com/matrix-org/synapse/issues/7797))
- Fix 'stuck invites' which happen when we are unable to reject a room invite received over federation. ([\#7804](https://github.com/matrix-org/synapse/issues/7804), [\#7809](https://github.com/matrix-org/synapse/issues/7809), [\#7810](https://github.com/matrix-org/synapse/issues/7810))


Updates to the Docker image
---------------------------

- Include libwebp in the Docker file to properly handle webp image uploads. ([\#7791](https://github.com/matrix-org/synapse/issues/7791))


Improved Documentation
----------------------

- Improve the documentation of the non-standard JSON web token login type. ([\#7776](https://github.com/matrix-org/synapse/issues/7776))
- Update doc links for caddy. Contributed by Nicolai Søborg. ([\#7789](https://github.com/matrix-org/synapse/issues/7789))


Internal Changes
----------------

- Refactor getting replication updates from database. ([\#7740](https://github.com/matrix-org/synapse/issues/7740))
- Send push notifications with a high or low priority depending upon whether they may generate user-observable effects. ([\#7765](https://github.com/matrix-org/synapse/issues/7765))
- Use symbolic names for replication stream names. ([\#7768](https://github.com/matrix-org/synapse/issues/7768))
- Add early returns to `_check_for_soft_fail`. ([\#7769](https://github.com/matrix-org/synapse/issues/7769))
- Fix up `synapse.handlers.federation` to pass mypy. ([\#7770](https://github.com/matrix-org/synapse/issues/7770))
- Convert the appserver handler to async/await. ([\#7775](https://github.com/matrix-org/synapse/issues/7775))
- Allow to use higher versions of prometheus_client <0.9.0 which are expected to introduce no breaking changes. Contributed by Oliver Kurz. ([\#7780](https://github.com/matrix-org/synapse/issues/7780))
- Update linting scripts and codebase to be compatible with `isort` v5. ([\#7786](https://github.com/matrix-org/synapse/issues/7786))
- Stop populating unused table `local_invites`. ([\#7793](https://github.com/matrix-org/synapse/issues/7793))
- Ensure that strings (not bytes) are passed into JSON serialization. ([\#7799](https://github.com/matrix-org/synapse/issues/7799))
- Switch from simplejson to the standard library json. ([\#7800](https://github.com/matrix-org/synapse/issues/7800))
- Add `signing_key` property to `HomeServer` to save code duplication. ([\#7805](https://github.com/matrix-org/synapse/issues/7805))
- Improve stacktraces from exceptions in background processes. ([\#7808](https://github.com/matrix-org/synapse/issues/7808))
- Fix various spelling errors in comments and log lines. ([\#7811](https://github.com/matrix-org/synapse/issues/7811))


Synapse 1.16.0 (2020-07-08)
===========================

No significant changes since 1.16.0rc2.

Note that this release deprecates the `m.login.jwt` login method, renaming it
to `org.matrix.login.jwt`, as `m.login.jwt` is not part of the Matrix spec.
Otherwise the behaviour is identical. Synapse will accept both names for now,
but this may change in a future release.

Synapse 1.16.0rc2 (2020-07-02)
==============================

Synapse 1.16.0rc2 includes the security fixes released with Synapse 1.15.2.
Please see [below](#synapse-1152-2020-07-02) for more details.

Improved Documentation
----------------------

- Update postgres image in example `docker-compose.yaml` to tag `12-alpine`. ([\#7696](https://github.com/matrix-org/synapse/issues/7696))


Internal Changes
----------------

- Add some metrics for inbound and outbound federation latencies: `synapse_federation_server_pdu_process_time` and `synapse_event_processing_lag_by_event`. ([\#7771](https://github.com/matrix-org/synapse/issues/7771))


Synapse 1.15.2 (2020-07-02)
===========================

Due to the two security issues highlighted below, server administrators are
encouraged to update Synapse. We are not aware of these vulnerabilities being
exploited in the wild.

Security advisory
-----------------

* A malicious homeserver could force Synapse to reset the state in a room to a
  small subset of the correct state. This affects all Synapse deployments which
  federate with untrusted servers. ([96e9afe6](https://github.com/matrix-org/synapse/commit/96e9afe62500310977dc3cbc99a8d16d3d2fa15c))
* HTML pages served via Synapse were vulnerable to clickjacking attacks. This
  predominantly affects homeservers with single-sign-on enabled, but all server
  administrators are encouraged to upgrade. ([ea26e9a9](https://github.com/matrix-org/synapse/commit/ea26e9a98b0541fc886a1cb826a38352b7599dbe))

  This was reported by [Quentin Gliech](https://sandhose.fr/).


Synapse 1.16.0rc1 (2020-07-01)
==============================

Features
--------

- Add an option to enable encryption by default for new rooms. ([\#7639](https://github.com/matrix-org/synapse/issues/7639))
- Add support for running multiple media repository workers. See [docs/workers.md](https://github.com/matrix-org/synapse/blob/release-v1.16.0/docs/workers.md) for instructions. ([\#7706](https://github.com/matrix-org/synapse/issues/7706))
- Media can now be marked as safe from quarantined. ([\#7718](https://github.com/matrix-org/synapse/issues/7718))
- Expand the configuration options for auto-join rooms. ([\#7763](https://github.com/matrix-org/synapse/issues/7763))


Bugfixes
--------

- Remove `user_id` from the response to `GET /_matrix/client/r0/presence/{userId}/status` to match the specification. ([\#7606](https://github.com/matrix-org/synapse/issues/7606))
- In worker mode, ensure that replicated data has not already been received. ([\#7648](https://github.com/matrix-org/synapse/issues/7648))
- Fix intermittent exception during startup, introduced in Synapse 1.14.0. ([\#7663](https://github.com/matrix-org/synapse/issues/7663))
- Include a user-agent for federation and well-known requests. ([\#7677](https://github.com/matrix-org/synapse/issues/7677))
- Accept the proper field (`phone`) for the `m.id.phone` identifier type. The legacy field of `number` is still accepted as a fallback. Bug introduced in v0.20.0. ([\#7687](https://github.com/matrix-org/synapse/issues/7687))
- Fix "Starting db txn 'get_completed_ui_auth_stages' from sentinel context" warning. The bug was introduced in 1.13.0. ([\#7688](https://github.com/matrix-org/synapse/issues/7688))
- Compare the URI and method during user interactive authentication (instead of the URI twice). Bug introduced in 1.13.0. ([\#7689](https://github.com/matrix-org/synapse/issues/7689))
- Fix a long standing bug where the response to the `GET room_keys/version` endpoint had the incorrect type for the `etag` field. ([\#7691](https://github.com/matrix-org/synapse/issues/7691))
- Fix logged error during device resync in opentracing. Broke in v1.14.0. ([\#7698](https://github.com/matrix-org/synapse/issues/7698))
- Do not break push rule evaluation when receiving an event with a non-string body. This is a long-standing bug. ([\#7701](https://github.com/matrix-org/synapse/issues/7701))
- Fixs a long standing bug which resulted in an exception: "TypeError: argument of type 'ObservableDeferred' is not iterable". ([\#7708](https://github.com/matrix-org/synapse/issues/7708))
- The `synapse_port_db` script no longer fails when the `ui_auth_sessions` table is non-empty. This bug has existed since v1.13.0. ([\#7711](https://github.com/matrix-org/synapse/issues/7711))
- Synapse will now fetch media from the proper specified URL (using the r0 prefix instead of the unspecified v1). ([\#7714](https://github.com/matrix-org/synapse/issues/7714))
- Fix the tables ignored by `synapse_port_db` to be in sync the current database schema. ([\#7717](https://github.com/matrix-org/synapse/issues/7717))
- Fix missing `Content-Length` on HTTP responses from the metrics handler. ([\#7730](https://github.com/matrix-org/synapse/issues/7730))
- Fix large state resolutions from stalling Synapse for seconds at a time. ([\#7735](https://github.com/matrix-org/synapse/issues/7735), [\#7746](https://github.com/matrix-org/synapse/issues/7746))


Improved Documentation
----------------------

- Spelling correction in sample_config.yaml. ([\#7652](https://github.com/matrix-org/synapse/issues/7652))
- Added instructions for how to use Keycloak via OpenID Connect to authenticate with Synapse. ([\#7659](https://github.com/matrix-org/synapse/issues/7659))
- Corrected misspelling of PostgreSQL. ([\#7724](https://github.com/matrix-org/synapse/issues/7724))


Deprecations and Removals
-------------------------

- Deprecate `m.login.jwt` login method in favour of `org.matrix.login.jwt`, as `m.login.jwt` is not part of the Matrix spec. ([\#7675](https://github.com/matrix-org/synapse/issues/7675))


Internal Changes
----------------

- Refactor getting replication updates from database. ([\#7636](https://github.com/matrix-org/synapse/issues/7636))
- Clean-up the login fallback code. ([\#7657](https://github.com/matrix-org/synapse/issues/7657))
- Increase the default SAML session expiry time to 15 minutes. ([\#7664](https://github.com/matrix-org/synapse/issues/7664))
- Convert the device message and pagination handlers to async/await. ([\#7678](https://github.com/matrix-org/synapse/issues/7678))
- Convert typing handler to async/await. ([\#7679](https://github.com/matrix-org/synapse/issues/7679))
- Require `parameterized` package version to be at least 0.7.0. ([\#7680](https://github.com/matrix-org/synapse/issues/7680))
- Refactor handling of `listeners` configuration settings. ([\#7681](https://github.com/matrix-org/synapse/issues/7681))
- Replace uses of `six.iterkeys`/`iteritems`/`itervalues` with `keys()`/`items()`/`values()`. ([\#7692](https://github.com/matrix-org/synapse/issues/7692))
- Add support for using `rust-python-jaeger-reporter` library to reduce jaeger tracing overhead. ([\#7697](https://github.com/matrix-org/synapse/issues/7697))
- Make Tox actions work on Debian 10. ([\#7703](https://github.com/matrix-org/synapse/issues/7703))
- Replace all remaining uses of `six` with native Python 3 equivalents. Contributed by @ilmari. ([\#7704](https://github.com/matrix-org/synapse/issues/7704))
- Fix broken link in sample config. ([\#7712](https://github.com/matrix-org/synapse/issues/7712))
- Speed up state res v2 across large state differences. ([\#7725](https://github.com/matrix-org/synapse/issues/7725))
- Convert directory handler to async/await. ([\#7727](https://github.com/matrix-org/synapse/issues/7727))
- Move `flake8` to the end of `scripts-dev/lint.sh` as it takes the longest and could cause the script to exit early. ([\#7738](https://github.com/matrix-org/synapse/issues/7738))
- Explain the "test" conditional requirement for dependencies is not all of the modules necessary to run the unit tests. ([\#7751](https://github.com/matrix-org/synapse/issues/7751))
- Add some metrics for inbound and outbound federation latencies: `synapse_federation_server_pdu_process_time` and `synapse_event_processing_lag_by_event`. ([\#7755](https://github.com/matrix-org/synapse/issues/7755))


Synapse 1.15.1 (2020-06-16)
===========================

Bugfixes
--------

- Fix a bug introduced in v1.15.0 that would crash Synapse on start when using certain password auth providers. ([\#7684](https://github.com/matrix-org/synapse/issues/7684))
- Fix a bug introduced in v1.15.0 which meant that some 3PID management endpoints were not accessible on the correct URL. ([\#7685](https://github.com/matrix-org/synapse/issues/7685))


Synapse 1.15.0 (2020-06-11)
===========================

No significant changes.


Synapse 1.15.0rc1 (2020-06-09)
==============================

Features
--------

- Advertise support for Client-Server API r0.6.0 and remove related unstable feature flags. ([\#6585](https://github.com/matrix-org/synapse/issues/6585))
- Add an option to disable autojoining rooms for guest accounts. ([\#6637](https://github.com/matrix-org/synapse/issues/6637))
- For SAML authentication, add the ability to pass email addresses to be added to new users' accounts via SAML attributes. Contributed by Christopher Cooper. ([\#7385](https://github.com/matrix-org/synapse/issues/7385))
- Add admin APIs to allow server admins to manage users' devices. Contributed by @dklimpel. ([\#7481](https://github.com/matrix-org/synapse/issues/7481))
- Add support for generating thumbnails for WebP images. Previously, users would see an empty box instead of preview image. Contributed by @WGH-. ([\#7586](https://github.com/matrix-org/synapse/issues/7586))
- Support the standardized `m.login.sso` user-interactive authentication flow. ([\#7630](https://github.com/matrix-org/synapse/issues/7630))


Bugfixes
--------

- Allow new users to be registered via the admin API even if the monthly active user limit has been reached. Contributed by @dklimpel. ([\#7263](https://github.com/matrix-org/synapse/issues/7263))
- Fix email notifications not being enabled for new users when created via the Admin API. ([\#7267](https://github.com/matrix-org/synapse/issues/7267))
- Fix str placeholders in an instance of `PrepareDatabaseException`. Introduced in Synapse v1.8.0. ([\#7575](https://github.com/matrix-org/synapse/issues/7575))
- Fix a bug in automatic user creation during first time login with `m.login.jwt`. Regression in v1.6.0. Contributed by @olof. ([\#7585](https://github.com/matrix-org/synapse/issues/7585))
- Fix a bug causing the cross-signing keys to be ignored when resyncing a device list. ([\#7594](https://github.com/matrix-org/synapse/issues/7594))
- Fix metrics failing when there is a large number of active background processes. ([\#7597](https://github.com/matrix-org/synapse/issues/7597))
- Fix bug where returning rooms for a group would fail if it included a room that the server was not in. ([\#7599](https://github.com/matrix-org/synapse/issues/7599))
- Fix duplicate key violation when persisting read markers. ([\#7607](https://github.com/matrix-org/synapse/issues/7607))
- Prevent an entire iteration of the device list resync loop from failing if one server responds with a malformed result. ([\#7609](https://github.com/matrix-org/synapse/issues/7609))
- Fix exceptions when fetching events from a remote host fails. ([\#7622](https://github.com/matrix-org/synapse/issues/7622))
- Make `synctl restart` start synapse if it wasn't running. ([\#7624](https://github.com/matrix-org/synapse/issues/7624))
- Pass device information through to the login endpoint when using the login fallback. ([\#7629](https://github.com/matrix-org/synapse/issues/7629))
- Advertise the `m.login.token` login flow when OpenID Connect is enabled. ([\#7631](https://github.com/matrix-org/synapse/issues/7631))
- Fix bug in account data replication stream. ([\#7656](https://github.com/matrix-org/synapse/issues/7656))


Improved Documentation
----------------------

- Update the OpenBSD installation instructions. ([\#7587](https://github.com/matrix-org/synapse/issues/7587))
- Advertise Python 3.8 support in `setup.py`. ([\#7602](https://github.com/matrix-org/synapse/issues/7602))
- Add a link to `#synapse:matrix.org` in the troubleshooting section of the README. ([\#7603](https://github.com/matrix-org/synapse/issues/7603))
- Clarifications to the admin api documentation. ([\#7647](https://github.com/matrix-org/synapse/issues/7647))


Internal Changes
----------------

- Convert the identity handler to async/await. ([\#7561](https://github.com/matrix-org/synapse/issues/7561))
- Improve query performance for fetching state from a PostgreSQL database. Contributed by @ilmari. ([\#7567](https://github.com/matrix-org/synapse/issues/7567))
- Speed up processing of federation stream RDATA rows. ([\#7584](https://github.com/matrix-org/synapse/issues/7584))
- Add comment to systemd example to show postgresql dependency. ([\#7591](https://github.com/matrix-org/synapse/issues/7591))
- Refactor `Ratelimiter` to limit the amount of expensive config value accesses. ([\#7595](https://github.com/matrix-org/synapse/issues/7595))
- Convert groups handlers to async/await. ([\#7600](https://github.com/matrix-org/synapse/issues/7600))
- Clean up exception handling in `SAML2ResponseResource`. ([\#7614](https://github.com/matrix-org/synapse/issues/7614))
- Check that all asynchronous tasks succeed and general cleanup of `MonthlyActiveUsersTestCase` and `TestMauLimit`. ([\#7619](https://github.com/matrix-org/synapse/issues/7619))
- Convert `get_user_id_by_threepid` to async/await. ([\#7620](https://github.com/matrix-org/synapse/issues/7620))
- Switch to upstream `dh-virtualenv` rather than our fork for Debian package builds. ([\#7621](https://github.com/matrix-org/synapse/issues/7621))
- Update CI scripts to check the number in the newsfile fragment. ([\#7623](https://github.com/matrix-org/synapse/issues/7623))
- Check if the localpart of a Matrix ID is reserved for guest users earlier in the registration flow, as well as when responding to requests to `/register/available`. ([\#7625](https://github.com/matrix-org/synapse/issues/7625))
- Minor cleanups to OpenID Connect integration. ([\#7628](https://github.com/matrix-org/synapse/issues/7628))
- Attempt to fix flaky test: `PhoneHomeStatsTestCase.test_performance_100`. ([\#7634](https://github.com/matrix-org/synapse/issues/7634))
- Fix typos of `m.olm.curve25519-aes-sha2` and `m.megolm.v1.aes-sha2` in comments, test files. ([\#7637](https://github.com/matrix-org/synapse/issues/7637))
- Convert user directory, state deltas, and stats handlers to async/await. ([\#7640](https://github.com/matrix-org/synapse/issues/7640))
- Remove some unused constants. ([\#7644](https://github.com/matrix-org/synapse/issues/7644))
- Fix type information on `assert_*_is_admin` methods. ([\#7645](https://github.com/matrix-org/synapse/issues/7645))
- Convert registration handler to async/await. ([\#7649](https://github.com/matrix-org/synapse/issues/7649))


Synapse 1.14.0 (2020-05-28)
===========================

No significant changes.


Synapse 1.14.0rc2 (2020-05-27)
==============================

Bugfixes
--------

- Fix cache config to not apply cache factor to event cache. Regression in v1.14.0rc1. ([\#7578](https://github.com/matrix-org/synapse/issues/7578))
- Fix bug where `ReplicationStreamer` was not always started when replication was enabled. Bug introduced in v1.14.0rc1. ([\#7579](https://github.com/matrix-org/synapse/issues/7579))
- Fix specifying individual cache factors for caches with special characters in their name. Regression in v1.14.0rc1. ([\#7580](https://github.com/matrix-org/synapse/issues/7580))


Improved Documentation
----------------------

- Fix the OIDC `client_auth_method` value in the sample config. ([\#7581](https://github.com/matrix-org/synapse/issues/7581))


Synapse 1.14.0rc1 (2020-05-26)
==============================

Features
--------

- Synapse's cache factor can now be configured in `homeserver.yaml` by the `caches.global_factor` setting. Additionally, `caches.per_cache_factors` controls the cache factors for individual caches. ([\#6391](https://github.com/matrix-org/synapse/issues/6391))
- Add OpenID Connect login/registration support. Contributed by Quentin Gliech, on behalf of [les Connecteurs](https://connecteu.rs). ([\#7256](https://github.com/matrix-org/synapse/issues/7256), [\#7457](https://github.com/matrix-org/synapse/issues/7457))
- Add room details admin endpoint. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#7317](https://github.com/matrix-org/synapse/issues/7317))
- Allow for using more than one spam checker module at once. ([\#7435](https://github.com/matrix-org/synapse/issues/7435))
- Add additional authentication checks for `m.room.power_levels` event per [MSC2209](https://github.com/matrix-org/matrix-doc/pull/2209). ([\#7502](https://github.com/matrix-org/synapse/issues/7502))
- Implement room version 6 per [MSC2240](https://github.com/matrix-org/matrix-doc/pull/2240). ([\#7506](https://github.com/matrix-org/synapse/issues/7506))
- Add highly experimental option to move event persistence off master. ([\#7281](https://github.com/matrix-org/synapse/issues/7281), [\#7374](https://github.com/matrix-org/synapse/issues/7374), [\#7436](https://github.com/matrix-org/synapse/issues/7436), [\#7440](https://github.com/matrix-org/synapse/issues/7440), [\#7475](https://github.com/matrix-org/synapse/issues/7475), [\#7490](https://github.com/matrix-org/synapse/issues/7490), [\#7491](https://github.com/matrix-org/synapse/issues/7491), [\#7492](https://github.com/matrix-org/synapse/issues/7492), [\#7493](https://github.com/matrix-org/synapse/issues/7493), [\#7495](https://github.com/matrix-org/synapse/issues/7495), [\#7515](https://github.com/matrix-org/synapse/issues/7515), [\#7516](https://github.com/matrix-org/synapse/issues/7516), [\#7517](https://github.com/matrix-org/synapse/issues/7517), [\#7542](https://github.com/matrix-org/synapse/issues/7542))


Bugfixes
--------

- Fix a bug where event updates might not be sent over replication to worker processes after the stream falls behind. ([\#7384](https://github.com/matrix-org/synapse/issues/7384))
- Allow expired user accounts to log out their device sessions. ([\#7443](https://github.com/matrix-org/synapse/issues/7443))
- Fix a bug that would cause Synapse not to resync out-of-sync device lists. ([\#7453](https://github.com/matrix-org/synapse/issues/7453))
- Prevent rooms with 0 members or with invalid version strings from breaking group queries. ([\#7465](https://github.com/matrix-org/synapse/issues/7465))
- Workaround for an upstream Twisted bug that caused Synapse to become unresponsive after startup. ([\#7473](https://github.com/matrix-org/synapse/issues/7473))
- Fix Redis reconnection logic that can result in missed updates over replication if master reconnects to Redis without restarting. ([\#7482](https://github.com/matrix-org/synapse/issues/7482))
- When sending `m.room.member` events, omit `displayname` and `avatar_url` if they aren't set instead of setting them to `null`. Contributed by Aaron Raimist. ([\#7497](https://github.com/matrix-org/synapse/issues/7497))
- Fix incorrect `method` label on `synapse_http_matrixfederationclient_{requests,responses}` prometheus metrics. ([\#7503](https://github.com/matrix-org/synapse/issues/7503))
- Ignore incoming presence events from other homeservers if presence is disabled locally. ([\#7508](https://github.com/matrix-org/synapse/issues/7508))
- Fix a long-standing bug that broke the update remote profile background process. ([\#7511](https://github.com/matrix-org/synapse/issues/7511))
- Hash passwords as early as possible during password reset. ([\#7538](https://github.com/matrix-org/synapse/issues/7538))
- Fix bug where a local user leaving a room could fail under rare circumstances. ([\#7548](https://github.com/matrix-org/synapse/issues/7548))
- Fix "Missing RelayState parameter" error when using user interactive authentication with SAML for some SAML providers. ([\#7552](https://github.com/matrix-org/synapse/issues/7552))
- Fix exception `'GenericWorkerReplicationHandler' object has no attribute 'send_federation_ack'`, introduced in v1.13.0. ([\#7564](https://github.com/matrix-org/synapse/issues/7564))
- `synctl` now warns if it was unable to stop Synapse and will not attempt to start Synapse if nothing was stopped. Contributed by Romain Bouyé. ([\#6598](https://github.com/matrix-org/synapse/issues/6598))


Updates to the Docker image
---------------------------

- Update docker runtime image to Alpine v3.11. Contributed by @Starbix. ([\#7398](https://github.com/matrix-org/synapse/issues/7398))


Improved Documentation
----------------------

- Update information about mapping providers for SAML and OpenID. ([\#7458](https://github.com/matrix-org/synapse/issues/7458))
- Add additional reverse proxy example for Caddy v2. Contributed by Jeff Peeler. ([\#7463](https://github.com/matrix-org/synapse/issues/7463))
- Fix copy-paste error in `ServerNoticesConfig` docstring. Contributed by @ptman. ([\#7477](https://github.com/matrix-org/synapse/issues/7477))
- Improve the formatting of `reverse_proxy.md`. ([\#7514](https://github.com/matrix-org/synapse/issues/7514))
- Change the systemd worker service to check that the worker config file exists instead of silently failing. Contributed by David Vo. ([\#7528](https://github.com/matrix-org/synapse/issues/7528))
- Minor clarifications to the TURN docs. ([\#7533](https://github.com/matrix-org/synapse/issues/7533))


Internal Changes
----------------

- Add typing annotations in `synapse.federation`. ([\#7382](https://github.com/matrix-org/synapse/issues/7382))
- Convert the room handler to async/await. ([\#7396](https://github.com/matrix-org/synapse/issues/7396))
- Improve performance of `get_e2e_cross_signing_key`. ([\#7428](https://github.com/matrix-org/synapse/issues/7428))
- Improve performance of `mark_as_sent_devices_by_remote`. ([\#7429](https://github.com/matrix-org/synapse/issues/7429), [\#7562](https://github.com/matrix-org/synapse/issues/7562))
- Add type hints to the SAML handler. ([\#7445](https://github.com/matrix-org/synapse/issues/7445))
- Remove storage method `get_hosts_in_room` that is no longer called anywhere. ([\#7448](https://github.com/matrix-org/synapse/issues/7448))
- Fix some typos in the `notice_expiry` templates. ([\#7449](https://github.com/matrix-org/synapse/issues/7449))
- Convert the federation handler to async/await. ([\#7459](https://github.com/matrix-org/synapse/issues/7459))
- Convert the search handler to async/await. ([\#7460](https://github.com/matrix-org/synapse/issues/7460))
- Add type hints to `synapse.event_auth`. ([\#7505](https://github.com/matrix-org/synapse/issues/7505))
- Convert the room member handler to async/await. ([\#7507](https://github.com/matrix-org/synapse/issues/7507))
- Add type hints to room member handler. ([\#7513](https://github.com/matrix-org/synapse/issues/7513))
- Fix typing annotations in `tests.replication`. ([\#7518](https://github.com/matrix-org/synapse/issues/7518))
- Remove some redundant Python 2 support code. ([\#7519](https://github.com/matrix-org/synapse/issues/7519))
- All endpoints now respond with a 200 OK for `OPTIONS` requests. ([\#7534](https://github.com/matrix-org/synapse/issues/7534), [\#7560](https://github.com/matrix-org/synapse/issues/7560))
- Synapse now exports [detailed allocator statistics](https://doc.pypy.org/en/latest/gc_info.html#gc-get-stats) and basic GC timings as Prometheus metrics (`pypy_gc_time_seconds_total` and `pypy_memory_bytes`) when run under PyPy. Contributed by Ivan Shapovalov. ([\#7536](https://github.com/matrix-org/synapse/issues/7536))
- Remove Ubuntu Cosmic and Disco from the list of distributions which we provide `.deb`s for, due to end-of-life. ([\#7539](https://github.com/matrix-org/synapse/issues/7539))
- Make worker processes return a stubbed-out response to `GET /presence` requests. ([\#7545](https://github.com/matrix-org/synapse/issues/7545))
- Optimise some references to `hs.config`. ([\#7546](https://github.com/matrix-org/synapse/issues/7546))
- On upgrade room only send canonical alias once. ([\#7547](https://github.com/matrix-org/synapse/issues/7547))
- Fix some indentation inconsistencies in the sample config. ([\#7550](https://github.com/matrix-org/synapse/issues/7550))
- Include `synapse.http.site` in type checking. ([\#7553](https://github.com/matrix-org/synapse/issues/7553))
- Fix some test code to not mangle stacktraces, to make it easier to debug errors. ([\#7554](https://github.com/matrix-org/synapse/issues/7554))
- Refresh apt cache when building `dh_virtualenv` docker image. ([\#7555](https://github.com/matrix-org/synapse/issues/7555))
- Stop logging some expected HTTP request errors as exceptions. ([\#7556](https://github.com/matrix-org/synapse/issues/7556), [\#7563](https://github.com/matrix-org/synapse/issues/7563))
- Convert sending mail to async/await. ([\#7557](https://github.com/matrix-org/synapse/issues/7557))
- Simplify `reap_monthly_active_users`. ([\#7558](https://github.com/matrix-org/synapse/issues/7558))


Synapse 1.13.0 (2020-05-19)
===========================

This release brings some potential changes necessary for certain
configurations of Synapse:

* If your Synapse is configured to use SSO and have a custom
  `sso_redirect_confirm_template_dir` configuration option set, you will need
  to duplicate the new `sso_auth_confirm.html`, `sso_auth_success.html` and
  `sso_account_deactivated.html` templates into that directory.
* Synapse plugins using the `complete_sso_login` method of
  `synapse.module_api.ModuleApi` should instead switch to the async/await
  version, `complete_sso_login_async`, which includes additional checks. The
  former version is now deprecated.
* A bug was introduced in Synapse 1.4.0 which could cause the room directory
  to be incomplete or empty if Synapse was upgraded directly from v1.2.1 or
  earlier, to versions between v1.4.0 and v1.12.x.

Please review the [upgrade notes](docs/upgrade.md) for more details on these changes
and for general upgrade guidance.


Notice of change to the default `git` branch for Synapse
--------------------------------------------------------

With the release of Synapse 1.13.0, the default `git` branch for Synapse has
changed to `develop`, which is the development tip. This is more consistent with
common practice and modern `git` usage.

The `master` branch, which tracks the latest release, is still available. It is
recommended that developers and distributors who have scripts which run builds
using the default branch of Synapse should therefore consider pinning their
scripts to `master`.


Internal Changes
----------------

- Update the version of dh-virtualenv we use to build debs, and add focal to the list of target distributions. ([\#7526](https://github.com/matrix-org/synapse/issues/7526))


Synapse 1.13.0rc3 (2020-05-18)
==============================

Bugfixes
--------

- Hash passwords as early as possible during registration. ([\#7523](https://github.com/matrix-org/synapse/issues/7523))


Synapse 1.13.0rc2 (2020-05-14)
==============================

Bugfixes
--------

- Fix a long-standing bug which could cause messages not to be sent over federation, when state events with state keys matching user IDs (such as custom user statuses) were received. ([\#7376](https://github.com/matrix-org/synapse/issues/7376))
- Restore compatibility with non-compliant clients during the user interactive authentication process, fixing a problem introduced in v1.13.0rc1. ([\#7483](https://github.com/matrix-org/synapse/issues/7483))

Internal Changes
----------------

- Fix linting errors in new version of Flake8. ([\#7470](https://github.com/matrix-org/synapse/issues/7470))


Synapse 1.13.0rc1 (2020-05-11)
==============================

Features
--------

- Extend the `web_client_location` option to accept an absolute URL to use as a redirect. Adds a warning when running the web client on the same hostname as homeserver. Contributed by Martin Milata. ([\#7006](https://github.com/matrix-org/synapse/issues/7006))
- Set `Referrer-Policy` header to `no-referrer` on media downloads. ([\#7009](https://github.com/matrix-org/synapse/issues/7009))
- Add support for running replication over Redis when using workers. ([\#7040](https://github.com/matrix-org/synapse/issues/7040), [\#7325](https://github.com/matrix-org/synapse/issues/7325), [\#7352](https://github.com/matrix-org/synapse/issues/7352), [\#7401](https://github.com/matrix-org/synapse/issues/7401), [\#7427](https://github.com/matrix-org/synapse/issues/7427), [\#7439](https://github.com/matrix-org/synapse/issues/7439), [\#7446](https://github.com/matrix-org/synapse/issues/7446), [\#7450](https://github.com/matrix-org/synapse/issues/7450), [\#7454](https://github.com/matrix-org/synapse/issues/7454))
- Admin API `POST /_synapse/admin/v1/join/<roomIdOrAlias>` to join users to a room like `auto_join_rooms` for creation of users. ([\#7051](https://github.com/matrix-org/synapse/issues/7051))
- Add options to prevent users from changing their profile or associated 3PIDs. ([\#7096](https://github.com/matrix-org/synapse/issues/7096))
- Support SSO in the user interactive authentication workflow. ([\#7102](https://github.com/matrix-org/synapse/issues/7102), [\#7186](https://github.com/matrix-org/synapse/issues/7186), [\#7279](https://github.com/matrix-org/synapse/issues/7279), [\#7343](https://github.com/matrix-org/synapse/issues/7343))
- Allow server admins to define and enforce a password policy ([MSC2000](https://github.com/matrix-org/matrix-doc/issues/2000)). ([\#7118](https://github.com/matrix-org/synapse/issues/7118))
- Improve the support for SSO authentication on the login fallback page. ([\#7152](https://github.com/matrix-org/synapse/issues/7152), [\#7235](https://github.com/matrix-org/synapse/issues/7235))
- Always whitelist the login fallback in the SSO configuration if `public_baseurl` is set. ([\#7153](https://github.com/matrix-org/synapse/issues/7153))
- Admin users are no longer required to be in a room to create an alias for it. ([\#7191](https://github.com/matrix-org/synapse/issues/7191))
- Require admin privileges to enable room encryption by default. This does not affect existing rooms. ([\#7230](https://github.com/matrix-org/synapse/issues/7230))
- Add a config option for specifying the value of the Accept-Language HTTP header when generating URL previews. ([\#7265](https://github.com/matrix-org/synapse/issues/7265))
- Allow `/requestToken` endpoints to hide the existence (or lack thereof) of 3PID associations on the homeserver. ([\#7315](https://github.com/matrix-org/synapse/issues/7315))
- Add a configuration setting to tweak the threshold for dummy events. ([\#7422](https://github.com/matrix-org/synapse/issues/7422))


Bugfixes
--------

- Don't attempt to use an invalid sqlite config if no database configuration is provided. Contributed by @nekatak. ([\#6573](https://github.com/matrix-org/synapse/issues/6573))
- Fix single-sign on with CAS systems: pass the same service URL when requesting the CAS ticket and when calling the `proxyValidate` URL. Contributed by @Naugrimm. ([\#6634](https://github.com/matrix-org/synapse/issues/6634))
- Fix missing field `default` when fetching user-defined push rules. ([\#6639](https://github.com/matrix-org/synapse/issues/6639))
- Improve error responses when accessing remote public room lists. ([\#6899](https://github.com/matrix-org/synapse/issues/6899), [\#7368](https://github.com/matrix-org/synapse/issues/7368))
- Transfer alias mappings on room upgrade. ([\#6946](https://github.com/matrix-org/synapse/issues/6946))
- Ensure that a user interactive authentication session is tied to a single request. ([\#7068](https://github.com/matrix-org/synapse/issues/7068), [\#7455](https://github.com/matrix-org/synapse/issues/7455))
- Fix a bug in the federation API which could cause occasional "Failed to get PDU" errors. ([\#7089](https://github.com/matrix-org/synapse/issues/7089))
- Return the proper error (`M_BAD_ALIAS`) when a non-existent canonical alias is provided. ([\#7109](https://github.com/matrix-org/synapse/issues/7109))
- Fix a bug which meant that groups updates were not correctly replicated between workers. ([\#7117](https://github.com/matrix-org/synapse/issues/7117))
- Fix starting workers when federation sending not split out. ([\#7133](https://github.com/matrix-org/synapse/issues/7133))
- Ensure `is_verified` is a boolean in responses to `GET /_matrix/client/r0/room_keys/keys`. Also warn the user if they forgot the `version` query param. ([\#7150](https://github.com/matrix-org/synapse/issues/7150))
- Fix error page being shown when a custom SAML handler attempted to redirect when processing an auth response. ([\#7151](https://github.com/matrix-org/synapse/issues/7151))
- Avoid importing `sqlite3` when using the postgres backend. Contributed by David Vo. ([\#7155](https://github.com/matrix-org/synapse/issues/7155))
- Fix excessive CPU usage by `prune_old_outbound_device_pokes` job. ([\#7159](https://github.com/matrix-org/synapse/issues/7159))
- Fix a bug which could cause outbound federation traffic to stop working if a client uploaded an incorrect e2e device signature. ([\#7177](https://github.com/matrix-org/synapse/issues/7177))
- Fix a bug which could cause incorrect 'cyclic dependency' error. ([\#7178](https://github.com/matrix-org/synapse/issues/7178))
- Fix a bug that could cause a user to be invited to a server notices (aka System Alerts) room without any notice being sent. ([\#7199](https://github.com/matrix-org/synapse/issues/7199))
- Fix some worker-mode replication handling not being correctly recorded in CPU usage stats. ([\#7203](https://github.com/matrix-org/synapse/issues/7203))
- Do not allow a deactivated user to login via SSO. ([\#7240](https://github.com/matrix-org/synapse/issues/7240), [\#7259](https://github.com/matrix-org/synapse/issues/7259))
- Fix --help command-line argument. ([\#7249](https://github.com/matrix-org/synapse/issues/7249))
- Fix room publish permissions not being checked on room creation. ([\#7260](https://github.com/matrix-org/synapse/issues/7260))
- Reject unknown session IDs during user interactive authentication instead of silently creating a new session. ([\#7268](https://github.com/matrix-org/synapse/issues/7268))
- Fix a SQL query introduced in Synapse 1.12.0 which could cause large amounts of logging to the postgres slow-query log. ([\#7274](https://github.com/matrix-org/synapse/issues/7274))
- Persist user interactive authentication sessions across workers and Synapse restarts. ([\#7302](https://github.com/matrix-org/synapse/issues/7302))
- Fixed backwards compatibility logic of the first value of `trusted_third_party_id_servers` being used for `account_threepid_delegates.email`, which occurs when the former, deprecated option is set and the latter is not. ([\#7316](https://github.com/matrix-org/synapse/issues/7316))
- Fix a bug where event updates might not be sent over replication to worker processes after the stream falls behind. ([\#7337](https://github.com/matrix-org/synapse/issues/7337), [\#7358](https://github.com/matrix-org/synapse/issues/7358))
- Fix bad error handling that would cause Synapse to crash if it's provided with a YAML configuration file that's either empty or doesn't parse into a key-value map. ([\#7341](https://github.com/matrix-org/synapse/issues/7341))
- Fix incorrect metrics reporting for `renew_attestations` background task. ([\#7344](https://github.com/matrix-org/synapse/issues/7344))
- Prevent non-federating rooms from appearing in responses to federated `POST /publicRoom` requests when a filter was included. ([\#7367](https://github.com/matrix-org/synapse/issues/7367))
- Fix a bug which would cause the room directory to be incorrectly populated if Synapse was upgraded directly from v1.2.1 or earlier to v1.4.0 or later. Note that this fix does not apply retrospectively; see the [upgrade notes](docs/upgrade.md#upgrading-to-v1130) for more information. ([\#7387](https://github.com/matrix-org/synapse/issues/7387))
- Fix bug in `EventContext.deserialize`. ([\#7393](https://github.com/matrix-org/synapse/issues/7393))


Improved Documentation
----------------------

- Update Debian installation instructions to recommend installing the `virtualenv` package instead of `python3-virtualenv`. ([\#6892](https://github.com/matrix-org/synapse/issues/6892))
- Improve the documentation for database configuration. ([\#6988](https://github.com/matrix-org/synapse/issues/6988))
- Improve the documentation of application service configuration files. ([\#7091](https://github.com/matrix-org/synapse/issues/7091))
- Update pre-built package name for FreeBSD. ([\#7107](https://github.com/matrix-org/synapse/issues/7107))
- Update postgres docs with login troubleshooting information. ([\#7119](https://github.com/matrix-org/synapse/issues/7119))
- Clean up INSTALL.md a bit. ([\#7141](https://github.com/matrix-org/synapse/issues/7141))
- Add documentation for running a local CAS server for testing. ([\#7147](https://github.com/matrix-org/synapse/issues/7147))
- Improve README.md by being explicit about public IP recommendation for TURN relaying. ([\#7167](https://github.com/matrix-org/synapse/issues/7167))
- Fix a small typo in the `metrics_flags` config option. ([\#7171](https://github.com/matrix-org/synapse/issues/7171))
- Update the contributed documentation on managing synapse workers with systemd, and bring it into the core distribution. ([\#7234](https://github.com/matrix-org/synapse/issues/7234))
- Add documentation to the `password_providers` config option. Add known password provider implementations to docs. ([\#7238](https://github.com/matrix-org/synapse/issues/7238), [\#7248](https://github.com/matrix-org/synapse/issues/7248))
- Modify suggested nginx reverse proxy configuration to match Synapse's default file upload size. Contributed by @ProCycleDev. ([\#7251](https://github.com/matrix-org/synapse/issues/7251))
- Documentation of media_storage_providers options updated to avoid misunderstandings. Contributed by Tristan Lins. ([\#7272](https://github.com/matrix-org/synapse/issues/7272))
- Add documentation on monitoring workers with Prometheus. ([\#7357](https://github.com/matrix-org/synapse/issues/7357))
- Clarify endpoint usage in the users admin api documentation. ([\#7361](https://github.com/matrix-org/synapse/issues/7361))


Deprecations and Removals
-------------------------

- Remove nonfunctional `captcha_bypass_secret` option from `homeserver.yaml`. ([\#7137](https://github.com/matrix-org/synapse/issues/7137))


Internal Changes
----------------

- Add benchmarks for LruCache. ([\#6446](https://github.com/matrix-org/synapse/issues/6446))
- Return total number of users and profile attributes in admin users endpoint. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#6881](https://github.com/matrix-org/synapse/issues/6881))
- Change device list streams to have one row per ID. ([\#7010](https://github.com/matrix-org/synapse/issues/7010))
- Remove concept of a non-limited stream. ([\#7011](https://github.com/matrix-org/synapse/issues/7011))
- Move catchup of replication streams logic to worker. ([\#7024](https://github.com/matrix-org/synapse/issues/7024), [\#7195](https://github.com/matrix-org/synapse/issues/7195), [\#7226](https://github.com/matrix-org/synapse/issues/7226), [\#7239](https://github.com/matrix-org/synapse/issues/7239), [\#7286](https://github.com/matrix-org/synapse/issues/7286), [\#7290](https://github.com/matrix-org/synapse/issues/7290), [\#7318](https://github.com/matrix-org/synapse/issues/7318), [\#7326](https://github.com/matrix-org/synapse/issues/7326), [\#7378](https://github.com/matrix-org/synapse/issues/7378), [\#7421](https://github.com/matrix-org/synapse/issues/7421))
- Convert some of synapse.rest.media to async/await. ([\#7110](https://github.com/matrix-org/synapse/issues/7110), [\#7184](https://github.com/matrix-org/synapse/issues/7184), [\#7241](https://github.com/matrix-org/synapse/issues/7241))
- De-duplicate / remove unused REST code for login and auth. ([\#7115](https://github.com/matrix-org/synapse/issues/7115))
- Convert `*StreamRow` classes to inner classes. ([\#7116](https://github.com/matrix-org/synapse/issues/7116))
- Clean up some LoggingContext code. ([\#7120](https://github.com/matrix-org/synapse/issues/7120), [\#7181](https://github.com/matrix-org/synapse/issues/7181), [\#7183](https://github.com/matrix-org/synapse/issues/7183), [\#7408](https://github.com/matrix-org/synapse/issues/7408), [\#7426](https://github.com/matrix-org/synapse/issues/7426))
- Add explicit `instance_id` for USER_SYNC commands and remove implicit `conn_id` usage. ([\#7128](https://github.com/matrix-org/synapse/issues/7128))
- Refactored the CAS authentication logic to a separate class. ([\#7136](https://github.com/matrix-org/synapse/issues/7136))
- Run replication streamers on workers. ([\#7146](https://github.com/matrix-org/synapse/issues/7146))
- Add tests for outbound device pokes. ([\#7157](https://github.com/matrix-org/synapse/issues/7157))
- Fix device list update stream ids going backward. ([\#7158](https://github.com/matrix-org/synapse/issues/7158))
- Use `stream.current_token()` and remove `stream_positions()`. ([\#7172](https://github.com/matrix-org/synapse/issues/7172))
- Move client command handling out of TCP protocol. ([\#7185](https://github.com/matrix-org/synapse/issues/7185))
- Move server command handling out of TCP protocol. ([\#7187](https://github.com/matrix-org/synapse/issues/7187))
- Fix consistency of HTTP status codes reported in log lines. ([\#7188](https://github.com/matrix-org/synapse/issues/7188))
- Only run one background database update at a time. ([\#7190](https://github.com/matrix-org/synapse/issues/7190))
- Remove sent outbound device list pokes from the database. ([\#7192](https://github.com/matrix-org/synapse/issues/7192))
- Add a background database update job to clear out duplicate `device_lists_outbound_pokes`. ([\#7193](https://github.com/matrix-org/synapse/issues/7193))
- Remove some extraneous debugging log lines. ([\#7207](https://github.com/matrix-org/synapse/issues/7207))
- Add explicit Python build tooling as dependencies for the snapcraft build. ([\#7213](https://github.com/matrix-org/synapse/issues/7213))
- Add typing information to federation server code. ([\#7219](https://github.com/matrix-org/synapse/issues/7219))
- Extend room admin api (`GET /_synapse/admin/v1/rooms`) with additional attributes. ([\#7225](https://github.com/matrix-org/synapse/issues/7225))
- Unblacklist '/upgrade creates a new room' sytest for workers. ([\#7228](https://github.com/matrix-org/synapse/issues/7228))
- Remove redundant checks on `daemonize` from synctl. ([\#7233](https://github.com/matrix-org/synapse/issues/7233))
- Upgrade jQuery to v3.4.1 on fallback login/registration pages. ([\#7236](https://github.com/matrix-org/synapse/issues/7236))
- Change log line that told user to implement onLogin/onRegister fallback js functions to a warning, instead of an info, so it's more visible. ([\#7237](https://github.com/matrix-org/synapse/issues/7237))
- Correct the parameters of a test fixture. Contributed by Isaiah Singletary. ([\#7243](https://github.com/matrix-org/synapse/issues/7243))
- Convert auth handler to async/await. ([\#7261](https://github.com/matrix-org/synapse/issues/7261))
- Add some unit tests for replication. ([\#7278](https://github.com/matrix-org/synapse/issues/7278))
- Improve typing annotations in `synapse.replication.tcp.streams.Stream`. ([\#7291](https://github.com/matrix-org/synapse/issues/7291))
- Reduce log verbosity of url cache cleanup tasks. ([\#7295](https://github.com/matrix-org/synapse/issues/7295))
- Fix sample SAML Service Provider configuration. Contributed by @frcl. ([\#7300](https://github.com/matrix-org/synapse/issues/7300))
- Fix StreamChangeCache to work with multiple entities changing on the same stream id. ([\#7303](https://github.com/matrix-org/synapse/issues/7303))
- Fix an incorrect import in IdentityHandler. ([\#7319](https://github.com/matrix-org/synapse/issues/7319))
- Reduce logging verbosity for successful federation requests. ([\#7321](https://github.com/matrix-org/synapse/issues/7321))
- Convert some federation handler code to async/await. ([\#7338](https://github.com/matrix-org/synapse/issues/7338))
- Fix collation for postgres for unit tests. ([\#7359](https://github.com/matrix-org/synapse/issues/7359))
- Convert RegistrationWorkerStore.is_server_admin and dependent code to async/await. ([\#7363](https://github.com/matrix-org/synapse/issues/7363))
- Add an `instance_name` to `RDATA` and `POSITION` replication commands. ([\#7364](https://github.com/matrix-org/synapse/issues/7364))
- Thread through instance name to replication client. ([\#7369](https://github.com/matrix-org/synapse/issues/7369))
- Convert synapse.server_notices to async/await. ([\#7394](https://github.com/matrix-org/synapse/issues/7394))
- Convert synapse.notifier to async/await. ([\#7395](https://github.com/matrix-org/synapse/issues/7395))
- Fix issues with the Python package manifest. ([\#7404](https://github.com/matrix-org/synapse/issues/7404))
- Prevent methods in `synapse.handlers.auth` from polling the homeserver config every request. ([\#7420](https://github.com/matrix-org/synapse/issues/7420))
- Speed up fetching device lists changes when handling `/sync` requests. ([\#7423](https://github.com/matrix-org/synapse/issues/7423))
- Run group attestation renewal in series rather than parallel for performance. ([\#7442](https://github.com/matrix-org/synapse/issues/7442))


Synapse 1.12.4 (2020-04-23)
===========================

No significant changes.


Synapse 1.12.4rc1 (2020-04-22)
==============================

Features
--------

- Always send users their own device updates. ([\#7160](https://github.com/matrix-org/synapse/issues/7160))
- Add support for handling GET requests for `account_data` on a worker. ([\#7311](https://github.com/matrix-org/synapse/issues/7311))


Bugfixes
--------

- Fix a bug that prevented cross-signing with users on worker-mode synapses. ([\#7255](https://github.com/matrix-org/synapse/issues/7255))
- Do not treat display names as globs in push rules. ([\#7271](https://github.com/matrix-org/synapse/issues/7271))
- Fix a bug with cross-signing devices belonging to remote users who did not share a room with any user on the local homeserver. ([\#7289](https://github.com/matrix-org/synapse/issues/7289))

Synapse 1.12.3 (2020-04-03)
===========================

- Remove the the pin to Pillow 7.0 which was introduced in Synapse 1.12.2, and
correctly fix the issue with building the Debian packages. ([\#7212](https://github.com/matrix-org/synapse/issues/7212))

Synapse 1.12.2 (2020-04-02)
===========================

This release works around [an issue](https://github.com/matrix-org/synapse/issues/7208) with building the debian packages.

No other significant changes since 1.12.1.

Synapse 1.12.1 (2020-04-02)
===========================

No significant changes since 1.12.1rc1.


Synapse 1.12.1rc1 (2020-03-31)
==============================

Bugfixes
--------

- Fix starting workers when federation sending not split out. ([\#7133](https://github.com/matrix-org/synapse/issues/7133)). Introduced in v1.12.0.
- Avoid importing `sqlite3` when using the postgres backend. Contributed by David Vo. ([\#7155](https://github.com/matrix-org/synapse/issues/7155)). Introduced in v1.12.0rc1.
- Fix a bug which could cause outbound federation traffic to stop working if a client uploaded an incorrect e2e device signature. ([\#7177](https://github.com/matrix-org/synapse/issues/7177)). Introduced in v1.11.0.

Synapse 1.12.0 (2020-03-23)
===========================

Debian packages and Docker images are rebuilt using the latest versions of
dependency libraries, including Twisted 20.3.0. **Please see security advisory
below**.

Potential slow database update during upgrade
---------------------------------------------

Synapse 1.12.0 includes a database update which is run as part of the upgrade,
and which may take some time (several hours in the case of a large
server). Synapse will not respond to HTTP requests while this update is taking
place. For imformation on seeing if you are affected, and workaround if you
are, see the [upgrade notes](docs/upgrade.md#upgrading-to-v1120).

Security advisory
-----------------

Synapse may be vulnerable to request-smuggling attacks when it is used with a
reverse-proxy. The vulnerabilities are fixed in Twisted 20.3.0, and are
described in
[CVE-2020-10108](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10108)
and
[CVE-2020-10109](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10109).
For a good introduction to this class of request-smuggling attacks, see
https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn.

We are not aware of these vulnerabilities being exploited in the wild, and
do not believe that they are exploitable with current versions of any reverse
proxies. Nevertheless, we recommend that all Synapse administrators ensure that
they have the latest versions of the Twisted library to ensure that their
installation remains secure.

* Administrators using the [`matrix.org` Docker
  image](https://hub.docker.com/r/matrixdotorg/synapse/) or the [Debian/Ubuntu
  packages from
  `matrix.org`](https://matrix-org.github.io/synapse/latest/setup/installation.html#matrixorg-packages)
  should ensure that they have version 1.12.0 installed: these images include
  Twisted 20.3.0.
* Administrators who have [installed Synapse from
  source](https://matrix-org.github.io/synapse/latest/setup/installation.html#installing-from-source)
  should upgrade Twisted within their virtualenv by running:
  ```sh
  <path_to_virtualenv>/bin/pip install 'Twisted>=20.3.0'
  ```
* Administrators who have installed Synapse from distribution packages should
  consult the information from their distributions.

The `matrix.org` Synapse instance was not vulnerable to these vulnerabilities.

Advance notice of change to the default `git` branch for Synapse
----------------------------------------------------------------

Currently, the default `git` branch for Synapse is `master`, which tracks the
latest release.

After the release of Synapse 1.13.0, we intend to change this default to
`develop`, which is the development tip. This is more consistent with common
practice and modern `git` usage.

Although we try to keep `develop` in a stable state, there may be occasions
where regressions creep in. Developers and distributors who have scripts which
run builds using the default branch of `Synapse` should therefore consider
pinning their scripts to `master`.


Synapse 1.12.0rc1 (2020-03-19)
==============================

Features
--------

- Changes related to room alias management ([MSC2432](https://github.com/matrix-org/matrix-doc/pull/2432)):
  - Publishing/removing a room from the room directory now requires the user to have a power level capable of modifying the canonical alias, instead of the room aliases. ([\#6965](https://github.com/matrix-org/synapse/issues/6965))
  - Validate the `alt_aliases` property of canonical alias events. ([\#6971](https://github.com/matrix-org/synapse/issues/6971))
  - Users with a power level sufficient to modify the canonical alias of a room can now delete room aliases. ([\#6986](https://github.com/matrix-org/synapse/issues/6986))
  - Implement updated authorization rules and redaction rules for aliases events, from [MSC2261](https://github.com/matrix-org/matrix-doc/pull/2261) and [MSC2432](https://github.com/matrix-org/matrix-doc/pull/2432). ([\#7037](https://github.com/matrix-org/synapse/issues/7037))
  - Stop sending m.room.aliases events during room creation and upgrade. ([\#6941](https://github.com/matrix-org/synapse/issues/6941))
  - Synapse no longer uses room alias events to calculate room names for push notifications. ([\#6966](https://github.com/matrix-org/synapse/issues/6966))
  - The room list endpoint no longer returns a list of aliases. ([\#6970](https://github.com/matrix-org/synapse/issues/6970))
  - Remove special handling of aliases events from [MSC2260](https://github.com/matrix-org/matrix-doc/pull/2260) added in v1.10.0rc1. ([\#7034](https://github.com/matrix-org/synapse/issues/7034))
- Expose the `synctl`, `hash_password` and `generate_config` commands in the snapcraft package. Contributed by @devec0. ([\#6315](https://github.com/matrix-org/synapse/issues/6315))
- Check that server_name is correctly set before running database updates. ([\#6982](https://github.com/matrix-org/synapse/issues/6982))
- Break down monthly active users by `appservice_id` and emit via Prometheus. ([\#7030](https://github.com/matrix-org/synapse/issues/7030))
- Render a configurable and comprehensible error page if something goes wrong during the SAML2 authentication process. ([\#7058](https://github.com/matrix-org/synapse/issues/7058), [\#7067](https://github.com/matrix-org/synapse/issues/7067))
- Add an optional parameter to control whether other sessions are logged out when a user's password is modified. ([\#7085](https://github.com/matrix-org/synapse/issues/7085))
- Add prometheus metrics for the number of active pushers. ([\#7103](https://github.com/matrix-org/synapse/issues/7103), [\#7106](https://github.com/matrix-org/synapse/issues/7106))
- Improve performance when making HTTPS requests to sygnal, sydent, etc, by sharing the SSL context object between connections. ([\#7094](https://github.com/matrix-org/synapse/issues/7094))


Bugfixes
--------

- When a user's profile is updated via the admin API, also generate a displayname/avatar update for that user in each room. ([\#6572](https://github.com/matrix-org/synapse/issues/6572))
- Fix a couple of bugs in email configuration handling. ([\#6962](https://github.com/matrix-org/synapse/issues/6962))
- Fix an issue affecting worker-based deployments where replication would stop working, necessitating a full restart, after joining a large room. ([\#6967](https://github.com/matrix-org/synapse/issues/6967))
- Fix `duplicate key` error which was logged when rejoining a room over federation. ([\#6968](https://github.com/matrix-org/synapse/issues/6968))
- Prevent user from setting 'deactivated' to anything other than a bool on the v2 PUT /users Admin API. ([\#6990](https://github.com/matrix-org/synapse/issues/6990))
- Fix py35-old CI by using native tox package. ([\#7018](https://github.com/matrix-org/synapse/issues/7018))
- Fix a bug causing `org.matrix.dummy_event` to be included in responses from `/sync`. ([\#7035](https://github.com/matrix-org/synapse/issues/7035))
- Fix a bug that renders UTF-8 text files incorrectly when loaded from media. Contributed by @TheStranjer. ([\#7044](https://github.com/matrix-org/synapse/issues/7044))
- Fix a bug that would cause Synapse to respond with an error about event visibility if a client tried to request the state of a room at a given token. ([\#7066](https://github.com/matrix-org/synapse/issues/7066))
- Repair a data-corruption issue which was introduced in Synapse 1.10, and fixed in Synapse 1.11, and which could cause `/sync` to return with 404 errors about missing events and unknown rooms. ([\#7070](https://github.com/matrix-org/synapse/issues/7070))
- Fix a bug causing account validity renewal emails to be sent even if the feature is turned off in some cases. ([\#7074](https://github.com/matrix-org/synapse/issues/7074))


Improved Documentation
----------------------

- Updated CentOS8 install instructions. Contributed by Richard Kellner. ([\#6925](https://github.com/matrix-org/synapse/issues/6925))
- Fix `POSTGRES_INITDB_ARGS` in the `contrib/docker/docker-compose.yml` example docker-compose configuration. ([\#6984](https://github.com/matrix-org/synapse/issues/6984))
- Change date in [INSTALL.md](./INSTALL.md#tls-certificates) for last date of getting TLS certificates to November 2019. ([\#7015](https://github.com/matrix-org/synapse/issues/7015))
- Document that the fallback auth endpoints must be routed to the same worker node as the register endpoints. ([\#7048](https://github.com/matrix-org/synapse/issues/7048))


Deprecations and Removals
-------------------------

- Remove the unused query_auth federation endpoint per [MSC2451](https://github.com/matrix-org/matrix-doc/pull/2451). ([\#7026](https://github.com/matrix-org/synapse/issues/7026))


Internal Changes
----------------

- Add type hints to `logging/context.py`. ([\#6309](https://github.com/matrix-org/synapse/issues/6309))
- Add some clarifications to `README.md` in the database schema directory. ([\#6615](https://github.com/matrix-org/synapse/issues/6615))
- Refactoring work in preparation for changing the event redaction algorithm. ([\#6874](https://github.com/matrix-org/synapse/issues/6874), [\#6875](https://github.com/matrix-org/synapse/issues/6875), [\#6983](https://github.com/matrix-org/synapse/issues/6983), [\#7003](https://github.com/matrix-org/synapse/issues/7003))
- Improve performance of v2 state resolution for large rooms. ([\#6952](https://github.com/matrix-org/synapse/issues/6952), [\#7095](https://github.com/matrix-org/synapse/issues/7095))
- Reduce time spent doing GC, by freezing objects on startup. ([\#6953](https://github.com/matrix-org/synapse/issues/6953))
- Minor performance fixes to `get_auth_chain_ids`. ([\#6954](https://github.com/matrix-org/synapse/issues/6954))
- Don't record remote cross-signing keys in the `devices` table. ([\#6956](https://github.com/matrix-org/synapse/issues/6956))
- Use flake8-comprehensions to enforce good hygiene of list/set/dict comprehensions. ([\#6957](https://github.com/matrix-org/synapse/issues/6957))
- Merge worker apps together. ([\#6964](https://github.com/matrix-org/synapse/issues/6964), [\#7002](https://github.com/matrix-org/synapse/issues/7002), [\#7055](https://github.com/matrix-org/synapse/issues/7055), [\#7104](https://github.com/matrix-org/synapse/issues/7104))
- Remove redundant `store_room` call from `FederationHandler._process_received_pdu`. ([\#6979](https://github.com/matrix-org/synapse/issues/6979))
- Update warning for incorrect database collation/ctype to include link to documentation. ([\#6985](https://github.com/matrix-org/synapse/issues/6985))
- Add some type annotations to the database storage classes. ([\#6987](https://github.com/matrix-org/synapse/issues/6987))
- Port `synapse.handlers.presence` to async/await. ([\#6991](https://github.com/matrix-org/synapse/issues/6991), [\#7019](https://github.com/matrix-org/synapse/issues/7019))
- Add some type annotations to the federation base & client classes. ([\#6995](https://github.com/matrix-org/synapse/issues/6995))
- Port `synapse.rest.keys` to async/await. ([\#7020](https://github.com/matrix-org/synapse/issues/7020))
- Add a type check to `is_verified` when processing room keys. ([\#7045](https://github.com/matrix-org/synapse/issues/7045))
- Add type annotations and comments to the auth handler. ([\#7063](https://github.com/matrix-org/synapse/issues/7063))


Synapse 1.11.1 (2020-03-03)
===========================

This release includes a security fix impacting installations using Single Sign-On (i.e. SAML2 or CAS) for authentication. Administrators of such installations are encouraged to upgrade as soon as possible.

The release also includes fixes for a couple of other bugs.

Bugfixes
--------

- Add a confirmation step to the SSO login flow before redirecting users to the redirect URL. ([b2bd54a2](https://github.com/matrix-org/synapse/commit/b2bd54a2e31d9a248f73fadb184ae9b4cbdb49f9), [65c73cdf](https://github.com/matrix-org/synapse/commit/65c73cdfec1876a9fec2fd2c3a74923cd146fe0b), [a0178df1](https://github.com/matrix-org/synapse/commit/a0178df10422a76fd403b82d2b2a4ed28a9a9d1e))
- Fixed set a user as an admin with the admin API `PUT /_synapse/admin/v2/users/<user_id>`. Contributed by @dklimpel. ([\#6910](https://github.com/matrix-org/synapse/issues/6910))
- Fix bug introduced in Synapse 1.11.0 which sometimes caused errors when joining rooms over federation, with `'coroutine' object has no attribute 'event_id'`. ([\#6996](https://github.com/matrix-org/synapse/issues/6996))


Synapse 1.11.0 (2020-02-21)
===========================

Improved Documentation
----------------------

- Small grammatical fixes to the ACME v1 deprecation notice. ([\#6944](https://github.com/matrix-org/synapse/issues/6944))


Synapse 1.11.0rc1 (2020-02-19)
==============================

Features
--------

- Admin API to add or modify threepids of user accounts. ([\#6769](https://github.com/matrix-org/synapse/issues/6769))
- Limit the number of events that can be requested by the backfill federation API to 100. ([\#6864](https://github.com/matrix-org/synapse/issues/6864))
- Add ability to run some group APIs on workers. ([\#6866](https://github.com/matrix-org/synapse/issues/6866))
- Reject device display names over 100 characters in length to prevent abuse. ([\#6882](https://github.com/matrix-org/synapse/issues/6882))
- Add ability to route federation user device queries to workers. ([\#6873](https://github.com/matrix-org/synapse/issues/6873))
- The result of a user directory search can now be filtered via the spam checker. ([\#6888](https://github.com/matrix-org/synapse/issues/6888))
- Implement new `GET /_matrix/client/unstable/org.matrix.msc2432/rooms/{roomId}/aliases` endpoint as per [MSC2432](https://github.com/matrix-org/matrix-doc/pull/2432). ([\#6939](https://github.com/matrix-org/synapse/issues/6939), [\#6948](https://github.com/matrix-org/synapse/issues/6948), [\#6949](https://github.com/matrix-org/synapse/issues/6949))
- Stop sending `m.room.alias` events wheng adding / removing aliases. Check `alt_aliases` in the latest `m.room.canonical_alias` event when deleting an alias. ([\#6904](https://github.com/matrix-org/synapse/issues/6904))
- Change the default power levels of invites, tombstones and server ACLs for new rooms. ([\#6834](https://github.com/matrix-org/synapse/issues/6834))

Bugfixes
--------

- Fixed third party event rules function `on_create_room`'s return value being ignored. ([\#6781](https://github.com/matrix-org/synapse/issues/6781))
- Allow URL-encoded User IDs on `/_synapse/admin/v2/users/<user_id>[/admin]` endpoints. Thanks to @NHAS for reporting. ([\#6825](https://github.com/matrix-org/synapse/issues/6825))
- Fix Synapse refusing to start if `federation_certificate_verification_whitelist` option is blank. ([\#6849](https://github.com/matrix-org/synapse/issues/6849))
- Fix errors from logging in the purge jobs related to the message retention policies support. ([\#6945](https://github.com/matrix-org/synapse/issues/6945))
- Return a 404 instead of 200 for querying information of a non-existent user through the admin API. ([\#6901](https://github.com/matrix-org/synapse/issues/6901))


Updates to the Docker image
---------------------------

- The deprecated "generate-config-on-the-fly" mode is no longer supported. ([\#6918](https://github.com/matrix-org/synapse/issues/6918))


Improved Documentation
----------------------

- Add details of PR merge strategy to contributing docs. ([\#6846](https://github.com/matrix-org/synapse/issues/6846))
- Spell out that the last event sent to a room won't be deleted by a purge. ([\#6891](https://github.com/matrix-org/synapse/issues/6891))
- Update Synapse's documentation to warn about the deprecation of ACME v1. ([\#6905](https://github.com/matrix-org/synapse/issues/6905), [\#6907](https://github.com/matrix-org/synapse/issues/6907), [\#6909](https://github.com/matrix-org/synapse/issues/6909))
- Add documentation for the spam checker. ([\#6906](https://github.com/matrix-org/synapse/issues/6906))
- Fix worker docs to point `/publicised_groups` API correctly. ([\#6938](https://github.com/matrix-org/synapse/issues/6938))
- Clean up and update docs on setting up federation. ([\#6940](https://github.com/matrix-org/synapse/issues/6940))
- Add a warning about indentation to generated configuration files. ([\#6920](https://github.com/matrix-org/synapse/issues/6920))
- Databases created using the compose file in contrib/docker will now always have correct encoding and locale settings. Contributed by Fridtjof Mund. ([\#6921](https://github.com/matrix-org/synapse/issues/6921))
- Update pip install directions in readme to avoid error when using zsh. ([\#6855](https://github.com/matrix-org/synapse/issues/6855))


Deprecations and Removals
-------------------------

- Remove `m.lazy_load_members` from `unstable_features` since lazy loading is in the stable Client-Server API version r0.5.0. ([\#6877](https://github.com/matrix-org/synapse/issues/6877))


Internal Changes
----------------

- Add type hints to `SyncHandler`. ([\#6821](https://github.com/matrix-org/synapse/issues/6821))
- Refactoring work in preparation for changing the event redaction algorithm. ([\#6823](https://github.com/matrix-org/synapse/issues/6823), [\#6827](https://github.com/matrix-org/synapse/issues/6827), [\#6854](https://github.com/matrix-org/synapse/issues/6854), [\#6856](https://github.com/matrix-org/synapse/issues/6856), [\#6857](https://github.com/matrix-org/synapse/issues/6857), [\#6858](https://github.com/matrix-org/synapse/issues/6858))
- Fix stacktraces when using `ObservableDeferred` and async/await. ([\#6836](https://github.com/matrix-org/synapse/issues/6836))
- Port much of `synapse.handlers.federation` to async/await. ([\#6837](https://github.com/matrix-org/synapse/issues/6837), [\#6840](https://github.com/matrix-org/synapse/issues/6840))
- Populate `rooms.room_version` database column at startup, rather than in a background update. ([\#6847](https://github.com/matrix-org/synapse/issues/6847))
- Reduce amount we log at `INFO` level. ([\#6833](https://github.com/matrix-org/synapse/issues/6833), [\#6862](https://github.com/matrix-org/synapse/issues/6862))
- Remove unused `get_room_stats_state` method. ([\#6869](https://github.com/matrix-org/synapse/issues/6869))
- Add typing to `synapse.federation.sender` and port to async/await. ([\#6871](https://github.com/matrix-org/synapse/issues/6871))
- Refactor `_EventInternalMetadata` object to improve type safety. ([\#6872](https://github.com/matrix-org/synapse/issues/6872))
- Add an additional entry to the SyTest blacklist for worker mode. ([\#6883](https://github.com/matrix-org/synapse/issues/6883))
- Fix the use of sed in the linting scripts when using BSD sed. ([\#6887](https://github.com/matrix-org/synapse/issues/6887))
- Add type hints to the spam checker module. ([\#6915](https://github.com/matrix-org/synapse/issues/6915))
- Convert the directory handler tests to use HomeserverTestCase. ([\#6919](https://github.com/matrix-org/synapse/issues/6919))
- Increase DB/CPU perf of `_is_server_still_joined` check. ([\#6936](https://github.com/matrix-org/synapse/issues/6936))
- Tiny optimisation for incoming HTTP request dispatch. ([\#6950](https://github.com/matrix-org/synapse/issues/6950))


Synapse 1.10.1 (2020-02-17)
===========================

Bugfixes
--------

- Fix a bug introduced in Synapse 1.10.0 which would cause room state to be cleared in the database if Synapse was upgraded direct from 1.2.1 or earlier to 1.10.0. ([\#6924](https://github.com/matrix-org/synapse/issues/6924))


Synapse 1.10.0 (2020-02-12)
===========================

**WARNING to client developers**: As of this release Synapse validates `client_secret` parameters in the Client-Server API as per the spec. See [\#6766](https://github.com/matrix-org/synapse/issues/6766) for details.

Updates to the Docker image
---------------------------

- Update the docker images to Alpine Linux 3.11. ([\#6897](https://github.com/matrix-org/synapse/issues/6897))


Synapse 1.10.0rc5 (2020-02-11)
==============================

Bugfixes
--------

- Fix the filtering introduced in 1.10.0rc3 to also apply to the state blocks returned by `/sync`. ([\#6884](https://github.com/matrix-org/synapse/issues/6884))

Synapse 1.10.0rc4 (2020-02-11)
==============================

This release candidate was built incorrectly and is superseded by 1.10.0rc5.

Synapse 1.10.0rc3 (2020-02-10)
==============================

Features
--------

- Filter out `m.room.aliases` from the CS API to mitigate abuse while a better solution is specced. ([\#6878](https://github.com/matrix-org/synapse/issues/6878))


Internal Changes
----------------

- Fix continuous integration failures with old versions of `pip`, which were introduced by a release of the `zipp` library. ([\#6880](https://github.com/matrix-org/synapse/issues/6880))


Synapse 1.10.0rc2 (2020-02-06)
==============================

Bugfixes
--------

- Fix an issue with cross-signing where device signatures were not sent to remote servers. ([\#6844](https://github.com/matrix-org/synapse/issues/6844))
- Fix to the unknown remote device detection which was introduced in 1.10.rc1. ([\#6848](https://github.com/matrix-org/synapse/issues/6848))


Internal Changes
----------------

- Detect unexpected sender keys on remote encrypted events and resync device lists. ([\#6850](https://github.com/matrix-org/synapse/issues/6850))


Synapse 1.10.0rc1 (2020-01-31)
==============================

Features
--------

- Add experimental support for updated authorization rules for aliases events, from [MSC2260](https://github.com/matrix-org/matrix-doc/pull/2260). ([\#6787](https://github.com/matrix-org/synapse/issues/6787), [\#6790](https://github.com/matrix-org/synapse/issues/6790), [\#6794](https://github.com/matrix-org/synapse/issues/6794))


Bugfixes
--------

- Warn if postgres database has a non-C locale, as that can cause issues when upgrading locales (e.g. due to upgrading OS). ([\#6734](https://github.com/matrix-org/synapse/issues/6734))
- Minor fixes to `PUT /_synapse/admin/v2/users` admin api. ([\#6761](https://github.com/matrix-org/synapse/issues/6761))
- Validate `client_secret` parameter using the regex provided by the Client-Server API, temporarily allowing `:` characters for older clients. The `:` character will be removed in a future release. ([\#6767](https://github.com/matrix-org/synapse/issues/6767))
- Fix persisting redaction events that have been redacted (or otherwise don't have a redacts key). ([\#6771](https://github.com/matrix-org/synapse/issues/6771))
- Fix outbound federation request metrics. ([\#6795](https://github.com/matrix-org/synapse/issues/6795))
- Fix bug where querying a remote user's device keys that weren't cached resulted in only returning a single device. ([\#6796](https://github.com/matrix-org/synapse/issues/6796))
- Fix race in federation sender worker that delayed sending of device updates. ([\#6799](https://github.com/matrix-org/synapse/issues/6799), [\#6800](https://github.com/matrix-org/synapse/issues/6800))
- Fix bug where Synapse didn't invalidate cache of remote users' devices when Synapse left a room. ([\#6801](https://github.com/matrix-org/synapse/issues/6801))
- Fix waking up other workers when remote server is detected to have come back online. ([\#6811](https://github.com/matrix-org/synapse/issues/6811))


Improved Documentation
----------------------

- Clarify documentation related to `user_dir` and `federation_reader` workers. ([\#6775](https://github.com/matrix-org/synapse/issues/6775))


Internal Changes
----------------

- Record room versions in the `rooms` table. ([\#6729](https://github.com/matrix-org/synapse/issues/6729), [\#6788](https://github.com/matrix-org/synapse/issues/6788), [\#6810](https://github.com/matrix-org/synapse/issues/6810))
- Propagate cache invalidates from workers to other workers. ([\#6748](https://github.com/matrix-org/synapse/issues/6748))
- Remove some unnecessary admin handler abstraction methods. ([\#6751](https://github.com/matrix-org/synapse/issues/6751))
- Add some debugging for media storage providers. ([\#6757](https://github.com/matrix-org/synapse/issues/6757))
- Detect unknown remote devices and mark cache as stale. ([\#6776](https://github.com/matrix-org/synapse/issues/6776), [\#6819](https://github.com/matrix-org/synapse/issues/6819))
- Attempt to resync remote users' devices when detected as stale. ([\#6786](https://github.com/matrix-org/synapse/issues/6786))
- Delete current state from the database when server leaves a room. ([\#6792](https://github.com/matrix-org/synapse/issues/6792))
- When a client asks for a remote user's device keys check if the local cache for that user has been marked as potentially stale. ([\#6797](https://github.com/matrix-org/synapse/issues/6797))
- Add background update to clean out left rooms from current state. ([\#6802](https://github.com/matrix-org/synapse/issues/6802), [\#6816](https://github.com/matrix-org/synapse/issues/6816))
- Refactoring work in preparation for changing the event redaction algorithm. ([\#6803](https://github.com/matrix-org/synapse/issues/6803), [\#6805](https://github.com/matrix-org/synapse/issues/6805), [\#6806](https://github.com/matrix-org/synapse/issues/6806), [\#6807](https://github.com/matrix-org/synapse/issues/6807), [\#6820](https://github.com/matrix-org/synapse/issues/6820))


Synapse 1.9.1 (2020-01-28)
==========================

Bugfixes
--------

- Fix bug where setting `mau_limit_reserved_threepids` config would cause Synapse to refuse to start. ([\#6793](https://github.com/matrix-org/synapse/issues/6793))


Synapse 1.9.0 (2020-01-23)
==========================

**WARNING**: As of this release, Synapse no longer supports versions of SQLite before 3.11, and will refuse to start when configured to use an older version. Administrators are recommended to migrate their database to Postgres (see instructions [here](docs/postgres.md)).

If your Synapse deployment uses workers, note that the reverse-proxy configurations for the `synapse.app.media_repository`, `synapse.app.federation_reader` and `synapse.app.event_creator` workers have changed, with the addition of a few paths (see the updated configurations [here](docs/workers.md#available-worker-applications)). Existing configurations will continue to work.


Improved Documentation
----------------------

- Fix endpoint documentation for the List Rooms admin API. ([\#6770](https://github.com/matrix-org/synapse/issues/6770))


Synapse 1.9.0rc1 (2020-01-22)
=============================

Features
--------

- Allow admin to create or modify a user. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#5742](https://github.com/matrix-org/synapse/issues/5742))
- Add new quarantine media admin APIs to quarantine by media ID or by user who uploaded the media. ([\#6681](https://github.com/matrix-org/synapse/issues/6681), [\#6756](https://github.com/matrix-org/synapse/issues/6756))
- Add `org.matrix.e2e_cross_signing` to `unstable_features` in `/versions` as per [MSC1756](https://github.com/matrix-org/matrix-doc/pull/1756). ([\#6712](https://github.com/matrix-org/synapse/issues/6712))
- Add a new admin API to list and filter rooms on the server. ([\#6720](https://github.com/matrix-org/synapse/issues/6720))


Bugfixes
--------

- Correctly proxy HTTP errors due to API calls to remote group servers. ([\#6654](https://github.com/matrix-org/synapse/issues/6654))
- Fix media repo admin APIs when using a media worker. ([\#6664](https://github.com/matrix-org/synapse/issues/6664))
- Fix "CRITICAL" errors being logged when a request is received for a uri containing non-ascii characters. ([\#6682](https://github.com/matrix-org/synapse/issues/6682))
- Fix a bug where we would assign a numeric user ID if somebody tried registering with an empty username. ([\#6690](https://github.com/matrix-org/synapse/issues/6690))
- Fix `purge_room` admin API. ([\#6711](https://github.com/matrix-org/synapse/issues/6711))
- Fix a bug causing Synapse to not always purge quiet rooms with a low `max_lifetime` in their message retention policies when running the automated purge jobs. ([\#6714](https://github.com/matrix-org/synapse/issues/6714))
- Fix the `synapse_port_db` not correctly running background updates. Thanks @tadzik for reporting. ([\#6718](https://github.com/matrix-org/synapse/issues/6718))
- Fix changing password via user admin API. ([\#6730](https://github.com/matrix-org/synapse/issues/6730))
- Fix `/events/:event_id` deprecated API. ([\#6731](https://github.com/matrix-org/synapse/issues/6731))
- Fix monthly active user limiting support for worker mode, fixes [#4639](https://github.com/matrix-org/synapse/issues/4639). ([\#6742](https://github.com/matrix-org/synapse/issues/6742))
- Fix bug when setting `account_validity` to an empty block in the config. Thanks to @Sorunome for reporting. ([\#6747](https://github.com/matrix-org/synapse/issues/6747))
- Fix `AttributeError: 'NoneType' object has no attribute 'get'` in `hash_password` when configuration has an empty `password_config`. Contributed by @ivilata. ([\#6753](https://github.com/matrix-org/synapse/issues/6753))
- Fix the `docker-compose.yaml` overriding the entire `/etc` folder of the container. Contributed by Fabian Meyer. ([\#6656](https://github.com/matrix-org/synapse/issues/6656))


Improved Documentation
----------------------

- Fix a typo in the configuration example for purge jobs in the sample configuration file. ([\#6621](https://github.com/matrix-org/synapse/issues/6621))
- Add complete documentation of the message retention policies support. ([\#6624](https://github.com/matrix-org/synapse/issues/6624), [\#6665](https://github.com/matrix-org/synapse/issues/6665))
- Add some helpful tips about changelog entries to the GitHub pull request template. ([\#6663](https://github.com/matrix-org/synapse/issues/6663))
- Clarify the `account_validity` and `email` sections of the sample configuration. ([\#6685](https://github.com/matrix-org/synapse/issues/6685))
- Add more endpoints to the documentation for Synapse workers. ([\#6698](https://github.com/matrix-org/synapse/issues/6698))


Deprecations and Removals
-------------------------

- Synapse no longer supports versions of SQLite before 3.11, and will refuse to start when configured to use an older version. Administrators are recommended to migrate their database to Postgres (see instructions [here](docs/postgres.md)). ([\#6675](https://github.com/matrix-org/synapse/issues/6675))


Internal Changes
----------------

- Add `local_current_membership` table for tracking local user membership state in rooms. ([\#6655](https://github.com/matrix-org/synapse/issues/6655), [\#6728](https://github.com/matrix-org/synapse/issues/6728))
- Port `synapse.replication.tcp` to async/await. ([\#6666](https://github.com/matrix-org/synapse/issues/6666))
- Fixup `synapse.replication` to pass mypy checks. ([\#6667](https://github.com/matrix-org/synapse/issues/6667))
- Allow `additional_resources` to implement `IResource` directly. ([\#6686](https://github.com/matrix-org/synapse/issues/6686))
- Allow REST endpoint implementations to raise a `RedirectException`, which will redirect the user's browser to a given location. ([\#6687](https://github.com/matrix-org/synapse/issues/6687))
- Updates and extensions to the module API. ([\#6688](https://github.com/matrix-org/synapse/issues/6688))
- Updates to the SAML mapping provider API. ([\#6689](https://github.com/matrix-org/synapse/issues/6689), [\#6723](https://github.com/matrix-org/synapse/issues/6723))
- Remove redundant `RegistrationError` class. ([\#6691](https://github.com/matrix-org/synapse/issues/6691))
- Don't block processing of incoming EDUs behind processing PDUs in the same transaction. ([\#6697](https://github.com/matrix-org/synapse/issues/6697))
- Remove duplicate check for the `session` query parameter on the `/auth/xxx/fallback/web` Client-Server endpoint. ([\#6702](https://github.com/matrix-org/synapse/issues/6702))
- Attempt to retry sending a transaction when we detect a remote server has come back online, rather than waiting for a transaction to be triggered by new data. ([\#6706](https://github.com/matrix-org/synapse/issues/6706))
- Add `StateMap` type alias to simplify types. ([\#6715](https://github.com/matrix-org/synapse/issues/6715))
- Add a `DeltaState` to track changes to be made to current state during event persistence. ([\#6716](https://github.com/matrix-org/synapse/issues/6716))
- Add more logging around message retention policies support. ([\#6717](https://github.com/matrix-org/synapse/issues/6717))
- When processing a SAML response, log the assertions for easier configuration. ([\#6724](https://github.com/matrix-org/synapse/issues/6724))
- Fixup `synapse.rest` to pass mypy. ([\#6732](https://github.com/matrix-org/synapse/issues/6732), [\#6764](https://github.com/matrix-org/synapse/issues/6764))
- Fixup `synapse.api` to pass mypy. ([\#6733](https://github.com/matrix-org/synapse/issues/6733))
- Allow streaming cache 'invalidate all' to workers. ([\#6749](https://github.com/matrix-org/synapse/issues/6749))
- Remove unused CI docker compose files. ([\#6754](https://github.com/matrix-org/synapse/issues/6754))


Synapse 1.8.0 (2020-01-09)
==========================

**WARNING**: As of this release Synapse will refuse to start if the `log_file` config option is specified. Support for the option was removed in v1.3.0.


Bugfixes
--------

- Fix `GET` request on `/_synapse/admin/v2/users` endpoint. Contributed by Awesome Technologies Innovationslabor GmbH. ([\#6563](https://github.com/matrix-org/synapse/issues/6563))
- Fix incorrect signing of responses from the key server implementation. ([\#6657](https://github.com/matrix-org/synapse/issues/6657))


Synapse 1.8.0rc1 (2020-01-07)
=============================

Features
--------

- Add v2 APIs for the `send_join` and `send_leave` federation endpoints (as described in [MSC1802](https://github.com/matrix-org/matrix-doc/pull/1802)). ([\#6349](https://github.com/matrix-org/synapse/issues/6349))
- Add a develop script to generate full SQL schemas. ([\#6394](https://github.com/matrix-org/synapse/issues/6394))
- Add custom SAML username mapping functionality through an external provider plugin. ([\#6411](https://github.com/matrix-org/synapse/issues/6411))
- Automatically delete empty groups/communities. ([\#6453](https://github.com/matrix-org/synapse/issues/6453))
- Add option `limit_profile_requests_to_users_who_share_rooms` to prevent requirement of a local user sharing a room with another user to query their profile information. ([\#6523](https://github.com/matrix-org/synapse/issues/6523))
- Add an `export_signing_key` script to extract the public part of signing keys when rotating them. ([\#6546](https://github.com/matrix-org/synapse/issues/6546))
- Add experimental config option to specify multiple databases. ([\#6580](https://github.com/matrix-org/synapse/issues/6580))
- Raise an error if someone tries to use the `log_file` config option. ([\#6626](https://github.com/matrix-org/synapse/issues/6626))


Bugfixes
--------

- Prevent redacted events from being returned during message search. ([\#6377](https://github.com/matrix-org/synapse/issues/6377), [\#6522](https://github.com/matrix-org/synapse/issues/6522))
- Prevent error on trying to search a upgraded room when the server is not in the predecessor room. ([\#6385](https://github.com/matrix-org/synapse/issues/6385))
- Improve performance of looking up cross-signing keys. ([\#6486](https://github.com/matrix-org/synapse/issues/6486))
- Fix race which occasionally caused deleted devices to reappear. ([\#6514](https://github.com/matrix-org/synapse/issues/6514))
- Fix missing row in `device_max_stream_id` that could cause unable to decrypt errors after server restart. ([\#6555](https://github.com/matrix-org/synapse/issues/6555))
- Fix a bug which meant that we did not send systemd notifications on startup if acme was enabled. ([\#6571](https://github.com/matrix-org/synapse/issues/6571))
- Fix exception when fetching the `matrix.org:ed25519:auto` key. ([\#6625](https://github.com/matrix-org/synapse/issues/6625))
- Fix bug where a moderator upgraded a room and became an admin in the new room. ([\#6633](https://github.com/matrix-org/synapse/issues/6633))
- Fix an error which was thrown by the `PresenceHandler` `_on_shutdown` handler. ([\#6640](https://github.com/matrix-org/synapse/issues/6640))
- Fix exceptions in the synchrotron worker log when events are rejected. ([\#6645](https://github.com/matrix-org/synapse/issues/6645))
- Ensure that upgraded rooms are removed from the directory. ([\#6648](https://github.com/matrix-org/synapse/issues/6648))
- Fix a bug causing Synapse not to fetch missing events when it believes it has every event in the room. ([\#6652](https://github.com/matrix-org/synapse/issues/6652))


Improved Documentation
----------------------

- Document the Room Shutdown Admin API. ([\#6541](https://github.com/matrix-org/synapse/issues/6541))
- Reword sections of [docs/federate.md](docs/federate.md) that explained delegation at time of Synapse 1.0 transition. ([\#6601](https://github.com/matrix-org/synapse/issues/6601))
- Added the section 'Configuration' in [docs/turn-howto.md](docs/turn-howto.md). ([\#6614](https://github.com/matrix-org/synapse/issues/6614))


Deprecations and Removals
-------------------------

- Remove redundant code from event authorisation implementation. ([\#6502](https://github.com/matrix-org/synapse/issues/6502))
- Remove unused, undocumented `/_matrix/content` API. ([\#6628](https://github.com/matrix-org/synapse/issues/6628))


Internal Changes
----------------

- Add *experimental* support for multiple physical databases and split out state storage to separate data store. ([\#6245](https://github.com/matrix-org/synapse/issues/6245), [\#6510](https://github.com/matrix-org/synapse/issues/6510), [\#6511](https://github.com/matrix-org/synapse/issues/6511), [\#6513](https://github.com/matrix-org/synapse/issues/6513), [\#6564](https://github.com/matrix-org/synapse/issues/6564), [\#6565](https://github.com/matrix-org/synapse/issues/6565))
- Port sections of code base to async/await. ([\#6496](https://github.com/matrix-org/synapse/issues/6496), [\#6504](https://github.com/matrix-org/synapse/issues/6504), [\#6505](https://github.com/matrix-org/synapse/issues/6505), [\#6517](https://github.com/matrix-org/synapse/issues/6517), [\#6559](https://github.com/matrix-org/synapse/issues/6559), [\#6647](https://github.com/matrix-org/synapse/issues/6647), [\#6653](https://github.com/matrix-org/synapse/issues/6653))
- Remove `SnapshotCache` in favour of `ResponseCache`. ([\#6506](https://github.com/matrix-org/synapse/issues/6506))
- Silence mypy errors for files outside those specified. ([\#6512](https://github.com/matrix-org/synapse/issues/6512))
- Clean up some logging when handling incoming events over federation. ([\#6515](https://github.com/matrix-org/synapse/issues/6515))
- Test more folders against mypy. ([\#6534](https://github.com/matrix-org/synapse/issues/6534))
- Update `mypy` to new version. ([\#6537](https://github.com/matrix-org/synapse/issues/6537))
- Adjust the sytest blacklist for worker mode. ([\#6538](https://github.com/matrix-org/synapse/issues/6538))
- Remove unused `get_pagination_rows` methods from `EventSource` classes. ([\#6557](https://github.com/matrix-org/synapse/issues/6557))
- Clean up logs from the push notifier at startup. ([\#6558](https://github.com/matrix-org/synapse/issues/6558))
- Improve diagnostics on database upgrade failure. ([\#6570](https://github.com/matrix-org/synapse/issues/6570))
- Reduce the reconnect time when worker replication fails, to make it easier to catch up. ([\#6617](https://github.com/matrix-org/synapse/issues/6617))
- Simplify http handling by removing redundant `SynapseRequestFactory`. ([\#6619](https://github.com/matrix-org/synapse/issues/6619))
- Add a workaround for synapse raising exceptions when fetching the notary's own key from the notary. ([\#6620](https://github.com/matrix-org/synapse/issues/6620))
- Automate generation of the sample log config. ([\#6627](https://github.com/matrix-org/synapse/issues/6627))
- Simplify event creation code by removing redundant queries on the `event_reference_hashes` table. ([\#6629](https://github.com/matrix-org/synapse/issues/6629))
- Fix errors when `frozen_dicts` are enabled. ([\#6642](https://github.com/matrix-org/synapse/issues/6642))


**Changelogs for older versions can be found [here](CHANGES-2019.md).**
