Changes in synapse v0.12.0 (2016-01-04)
=======================================

* Expose ``/login`` under ``r0`` (PR #459)

Changes in synapse v0.12.0-rc3 (2015-12-23)
===========================================

* Allow guest accounts access to ``/sync`` (PR #455)
* Allow filters to include/exclude rooms at the room level
  rather than just from the components of the sync for each
  room. (PR #454)
* Include urls for room avatars in the response to ``/publicRooms`` (PR #453)
* Don't set a identicon as the avatar for a user when they register (PR #450)
* Add a ``display_name`` to third-party invites (PR #449)
* Send more information to the identity server for third-party invites so that
  it can send richer messages to the invitee (PR #446)

* Cache the responses to ``/intialSync`` for 5 minutes. If a client
  retries a request to ``/initialSync`` before the a response was computed
  to the first request then the same response is used for both requests
  (PR #457)

* Fix a bug where synapse would always request the signing keys of
  remote servers even when the key was cached locally (PR #452)
* Fix 500 when pagination search results (PR #447)
* Fix a bug where synapse was leaking raw email address in third-party invites
   (PR #448)

Changes in synapse v0.12.0-rc2 (2015-12-14)
===========================================

* Add caches for whether rooms have been forgotten by a user (PR #434)
* Remove instructions to use ``--process-dependency-link`` since all of the
  dependencies of synapse are on PyPI (PR #436)
* Parallelise the processing of ``/sync`` requests (PR #437)
* Fix race updating presence in ``/events`` (PR #444)
* Fix bug back-populating search results (PR #441)
* Fix bug calculating state in ``/sync`` requests (PR #442)

Changes in synapse v0.12.0-rc1 (2015-12-10)
===========================================

* Host the client APIs released as r0 by
  https://matrix.org/docs/spec/r0.0.0/client_server.html
  on paths prefixed by ``/_matrix/client/r0``. (PR #430, PR #415, PR #400)
* Updates the client APIs to match r0 of the matrix specification.

  * All APIs return events in the new event format, old APIs also include
    the fields needed to parse the event using the old format for
    compatibility. (PR #402)
  * Search results are now given as a JSON array rather than
    a JSON object (PR #405)
  * Miscellaneous changes to search (PR #403, PR #406, PR #412)
  * Filter JSON objects may now be passed as query parameters to ``/sync``
    (PR #431)
  * Fix implementation of ``/admin/whois`` (PR #418)
  * Only include the rooms that user has left in ``/sync`` if the client
    requests them in the filter (PR #423)
  * Don't push for ``m.room.message`` by default (PR #411)
  * Add API for setting per account user data (PR #392)
  * Allow users to forget rooms (PR #385)

* Performance improvements and monitoring:

  * Add per-request counters for CPU time spent on the main python thread.
    (PR #421, PR #420)
  * Add per-request counters for time spent in the database (PR #429)
  * Make state updates in the C+S API idempotent (PR #416)
  * Only fire ``user_joined_room`` if the user has actually joined. (PR #410)
  * Reuse a single http client, rather than creating new ones (PR #413)

* Fixed a bug upgrading from older versions of synapse on postgresql (PR #417)

Changes in synapse v0.11.1 (2015-11-20)
=======================================

* Add extra options to search API (PR #394)
* Fix bug where we did not correctly cap federation retry timers. This meant it
  could take several hours for servers to start talking to ressurected servers,
  even when they were receiving traffic from them (PR #393)
* Don't advertise login token flow unless CAS is enabled. This caused issues
  where some clients would always use the fallback API if they did not
  recognize all login flows (PR #391)
* Change /v2 sync API to rename ``private_user_data`` to ``account_data``
  (PR #386)
* Change /v2 sync API to remove the ``event_map`` and rename keys in ``rooms``
  object (PR #389)

Changes in synapse v0.11.0-r2 (2015-11-19)
==========================================

* Fix bug in database port script (PR #387)

Changes in synapse v0.11.0-r1 (2015-11-18)
==========================================

* Retry and fail federation requests more aggressively for requests that block
  client side requests (PR #384)

Changes in synapse v0.11.0 (2015-11-17)
=======================================

* Change CAS login API (PR #349)

Changes in synapse v0.11.0-rc2 (2015-11-13)
===========================================

* Various changes to /sync API response format (PR #373)
* Fix regression when setting display name in newly joined room over
  federation (PR #368)
* Fix problem where /search was slow when using SQLite (PR #366)

Changes in synapse v0.11.0-rc1 (2015-11-11)
===========================================

* Add Search API (PR #307, #324, #327, #336, #350, #359)
* Add 'archived' state to v2 /sync API (PR #316)
* Add ability to reject invites (PR #317)
* Add config option to disable password login (PR #322)
* Add the login fallback API (PR #330)
* Add room context API (PR #334)
* Add room tagging support (PR #335)
* Update v2 /sync API to match spec (PR #305, #316, #321, #332, #337, #341)
* Change retry schedule for application services (PR #320)
* Change retry schedule for remote servers (PR #340)
* Fix bug where we hosted static content in the incorrect place (PR #329)
* Fix bug where we didn't increment retry interval for remote servers (PR #343)

Changes in synapse v0.10.1-rc1 (2015-10-15)
===========================================

* Add support for CAS, thanks to Steven Hammerton (PR #295, #296)
* Add support for using macaroons for ``access_token`` (PR #256, #229)
* Add support for ``m.room.canonical_alias`` (PR #287)
* Add support for viewing the history of rooms that they have left. (PR #276,
  #294)
* Add support for refresh tokens (PR #240)
* Add flag on creation which disables federation of the room (PR #279)
* Add some room state to invites. (PR #275)
* Atomically persist events when joining a room over federation (PR #283)
* Change default history visibility for private rooms (PR #271)
* Allow users to redact their own sent events (PR #262)
* Use tox for tests (PR #247)
* Split up syutil into separate libraries (PR #243)

Changes in synapse v0.10.0-r2 (2015-09-16)
==========================================

* Fix bug where we always fetched remote server signing keys instead of using
  ones in our cache.
* Fix adding threepids to an existing account.
* Fix bug with invinting over federation where remote server was already in
  the room. (PR #281, SYN-392)

Changes in synapse v0.10.0-r1 (2015-09-08)
==========================================

* Fix bug with python packaging

Changes in synapse v0.10.0 (2015-09-03)
=======================================

No change from release candidate.

Changes in synapse v0.10.0-rc6 (2015-09-02)
===========================================

* Remove some of the old database upgrade scripts.
* Fix database port script to work with newly created sqlite databases.

Changes in synapse v0.10.0-rc5 (2015-08-27)
===========================================

* Fix bug that broke downloading files with ascii filenames across federation.

Changes in synapse v0.10.0-rc4 (2015-08-27)
===========================================

* Allow UTF-8 filenames for upload. (PR #259)

Changes in synapse v0.10.0-rc3 (2015-08-25)
===========================================

* Add ``--keys-directory`` config option to specify where files such as
  certs and signing keys should be stored in, when using ``--generate-config``
  or ``--generate-keys``. (PR #250)
* Allow ``--config-path`` to specify a directory, causing synapse to use all
  \*.yaml files in the directory as config files. (PR #249)
* Add ``web_client_location`` config option to specify static files to be
  hosted by synapse under ``/_matrix/client``. (PR #245)
* Add helper utility to synapse to read and parse the config files and extract
  the value of a given key. For example::

    $ python -m synapse.config read server_name -c homeserver.yaml
    localhost

  (PR #246)


Changes in synapse v0.10.0-rc2 (2015-08-24)
===========================================

* Fix bug where we incorrectly populated the ``event_forward_extremities``
  table, resulting in problems joining large remote rooms (e.g.
  ``#matrix:matrix.org``)
* Reduce the number of times we wake up pushers by not listening for presence
  or typing events, reducing the CPU cost of each pusher.


Changes in synapse v0.10.0-rc1 (2015-08-21)
===========================================

Also see v0.9.4-rc1 changelog, which has been amalgamated into this release.

General:

* Upgrade to Twisted 15 (PR #173)
* Add support for serving and fetching encryption keys over federation.
  (PR #208)
* Add support for logging in with email address (PR #234)
* Add support for new ``m.room.canonical_alias`` event. (PR #233)
* Change synapse to treat user IDs case insensitively during registration and
  login. (If two users already exist with case insensitive matching user ids,
  synapse will continue to require them to specify their user ids exactly.)
* Error if a user tries to register with an email already in use. (PR #211)
* Add extra and improve existing caches  (PR #212, #219, #226, #228)
* Batch various storage request (PR #226, #228)
* Fix bug where we didn't correctly log the entity that triggered the request
  if the request came in via an application service (PR #230)
* Fix bug where we needlessly regenerated the full list of rooms an AS is
  interested in. (PR #232)
* Add support for AS's to use v2_alpha registration API (PR #210)


Configuration:

* Add ``--generate-keys`` that will generate any missing cert and key files in
  the configuration files. This is equivalent to running ``--generate-config``
  on an existing configuration file. (PR #220)
* ``--generate-config`` now no longer requires a ``--server-name`` parameter
  when used on existing configuration files. (PR #220)
* Add ``--print-pidfile`` flag that controls the printing of the pid to stdout
  of the demonised process. (PR #213)

Media Repository:

* Fix bug where we picked a lower resolution image than requested. (PR #205)
* Add support for specifying if a the media repository should dynamically
  thumbnail images or not. (PR #206)

Metrics:

* Add statistics from the reactor to the metrics API. (PR #224, #225)

Demo Homeservers:

* Fix starting the demo homeservers without rate-limiting enabled. (PR #182)
* Fix enabling registration on demo homeservers (PR #223)


Changes in synapse v0.9.4-rc1 (2015-07-21)
==========================================

General:

* Add basic implementation of receipts. (SPEC-99)
* Add support for configuration presets in room creation API. (PR  #203)
* Add auth event that limits the visibility of history for new users.
  (SPEC-134)
* Add SAML2 login/registration support. (PR  #201. Thanks Muthu Subramanian!)
* Add client side key management APIs for end to end encryption. (PR #198)
* Change power level semantics so that you cannot kick, ban or change power
  levels of users that have equal or greater power level than you. (SYN-192)
* Improve performance by bulk inserting events where possible. (PR #193)
* Improve performance by bulk verifying signatures where possible. (PR #194)


Configuration:

* Add support for including TLS certificate chains.

Media Repository:

* Add Content-Disposition headers to content repository responses. (SYN-150)


Changes in synapse v0.9.3 (2015-07-01)
======================================

No changes from v0.9.3 Release Candidate 1.

Changes in synapse v0.9.3-rc1 (2015-06-23)
==========================================

General:

* Fix a memory leak in the notifier. (SYN-412)
* Improve performance of room initial sync. (SYN-418)
* General improvements to logging.
* Remove ``access_token`` query params from ``INFO`` level logging.

Configuration:

* Add support for specifying and configuring multiple listeners. (SYN-389)

Application services:

* Fix bug where synapse failed to send user queries to application services.

Changes in synapse v0.9.2-r2 (2015-06-15)
=========================================

Fix packaging so that schema delta python files get included in the package.

Changes in synapse v0.9.2 (2015-06-12)
======================================

General:

* Use ultrajson for json (de)serialisation when a canonical encoding is not
  required. Ultrajson is significantly faster than simplejson in certain
  circumstances.
* Use connection pools for outgoing HTTP connections.
* Process thumbnails on separate threads.

Configuration:

* Add option, ``gzip_responses``, to disable HTTP response compression.

Federation:

* Improve resilience of backfill by ensuring we fetch any missing auth events.
* Improve performance of backfill and joining remote rooms by removing
  unnecessary computations. This included handling events we'd previously
  handled as well as attempting to compute the current state for outliers.


Changes in synapse v0.9.1 (2015-05-26)
======================================

General:

* Add support for backfilling when a client paginates. This allows servers to
  request history for a room from remote servers when a client tries to
  paginate history the server does not have - SYN-36
* Fix bug where you couldn't disable non-default pushrules - SYN-378
* Fix ``register_new_user`` script - SYN-359
* Improve performance of fetching events from the database, this improves both
  initialSync and sending of events.
* Improve performance of event streams, allowing synapse to handle more
  simultaneous connected clients.

Federation:

* Fix bug with existing backfill implementation where it returned the wrong
  selection of events in some circumstances.
* Improve performance of joining remote rooms.

Configuration:

* Add support for changing the bind host of the metrics listener via the
  ``metrics_bind_host`` option.
 

Changes in synapse v0.9.0-r5 (2015-05-21)
=========================================

* Add more database caches to reduce amount of work done for each pusher. This
  radically reduces CPU usage when multiple pushers are set up in the same room.

Changes in synapse v0.9.0 (2015-05-07)
======================================

General:

* Add support for using a PostgreSQL database instead of SQLite. See
  `docs/postgres.rst`_ for details.
* Add password change and reset APIs. See `Registration`_ in the spec.
* Fix memory leak due to not releasing stale notifiers - SYN-339.
* Fix race in caches that occasionally caused some presence updates to be
  dropped - SYN-369.
* Check server name has not changed on restart.
* Add a sample systemd unit file and a logger configuration in
  contrib/systemd. Contributed Ivan Shapovalov.

Federation:

* Add key distribution mechanisms for fetching public keys of unavailable
  remote home servers. See `Retrieving Server Keys`_ in the spec.

Configuration:

* Add support for multiple config files.
* Add support for dictionaries in config files.
* Remove support for specifying config options on the command line, except
  for:

  * ``--daemonize`` - Daemonize the home server.
  * ``--manhole`` - Turn on the twisted telnet manhole service on the given
    port.
  * ``--database-path`` - The path to a sqlite database to use.
  * ``--verbose`` - The verbosity level.
  * ``--log-file`` - File to log to.
  * ``--log-config`` - Python logging config file.
  * ``--enable-registration`` - Enable registration for new users.

Application services:

* Reliably retry sending of events from Synapse to application services, as per
  `Application Services`_ spec.
* Application services can no longer register via the ``/register`` API,
  instead their configuration should be saved to a file and listed in the
  synapse ``app_service_config_files`` config option. The AS configuration file
  has the same format as the old ``/register`` request.
  See `docs/application_services.rst`_ for more information.

.. _`docs/postgres.rst`: docs/postgres.rst
.. _`docs/application_services.rst`: docs/application_services.rst
.. _`Registration`: https://github.com/matrix-org/matrix-doc/blob/master/specification/10_client_server_api.rst#registration
.. _`Retrieving Server Keys`: https://github.com/matrix-org/matrix-doc/blob/6f2698/specification/30_server_server_api.rst#retrieving-server-keys
.. _`Application Services`: https://github.com/matrix-org/matrix-doc/blob/0c6bd9/specification/25_application_service_api.rst#home-server---application-service-api

Changes in synapse v0.8.1 (2015-03-18)
======================================

* Disable registration by default. New users can be added using the command
  ``register_new_matrix_user`` or by enabling registration in the config.
* Add metrics to synapse. To enable metrics use config options
  ``enable_metrics`` and ``metrics_port``.
* Fix bug where banning only kicked the user.

Changes in synapse v0.8.0 (2015-03-06)
======================================

General:

* Add support for registration fallback. This is a page hosted on the server
  which allows a user to register for an account, regardless of what client
  they are using (e.g. mobile devices).

* Added new default push rules and made them configurable by clients:

  * Suppress all notice messages.
  * Notify when invited to a new room.
  * Notify for messages that don't match any rule.
  * Notify on incoming call.

Federation:

* Added per host server side rate-limiting of incoming federation requests.
* Added a ``/get_missing_events/`` API to federation to reduce number of
  ``/events/`` requests.

Configuration:

* Added configuration option to disable registration:
  ``disable_registration``.
* Added configuration option to change soft limit of number of open file
  descriptors: ``soft_file_limit``.
* Make ``tls_private_key_path`` optional when running with ``no_tls``.

Application services:

* Application services can now poll on the CS API ``/events`` for their events,
  by providing their application service ``access_token``.
* Added exclusive namespace support to application services API.


Changes in synapse v0.7.1 (2015-02-19)
======================================

* Initial alpha implementation of parts of the Application Services API.
  Including:

  - AS Registration / Unregistration
  - User Query API
  - Room Alias Query API
  - Push transport for receiving events.
  - User/Alias namespace admin control

* Add cache when fetching events from remote servers to stop repeatedly
  fetching events with bad signatures.
* Respect the per remote server retry scheme when fetching both events and
  server keys to reduce the number of times we send requests to dead servers.
* Inform remote servers when the local server fails to handle a received event.
* Turn off python bytecode generation due to problems experienced when
  upgrading from previous versions.

Changes in synapse v0.7.0 (2015-02-12)
======================================

* Add initial implementation of the query auth federation API, allowing
  servers to agree on whether an event should be allowed or rejected.
* Persist events we have rejected from federation, fixing the bug where
  servers would keep requesting the same events.
* Various federation performance improvements, including:

  - Add in memory caches on queries such as:

     * Computing the state of a room at a point in time, used for
       authorization on federation requests.
     * Fetching events from the database.
     * User's room membership, used for authorizing presence updates.

  - Upgraded JSON library to improve parsing and serialisation speeds.

* Add default avatars to new user accounts using pydenticon library.
* Correctly time out federation requests.
* Retry federation requests against different servers.
* Add support for push and push rules.
* Add alpha versions of proposed new CSv2 APIs, including ``/sync`` API.

Changes in synapse 0.6.1 (2015-01-07)
=====================================

* Major optimizations to improve performance of initial sync and event sending
  in large rooms (by up to 10x)
* Media repository now includes a Content-Length header on media downloads.
* Improve quality of thumbnails by changing resizing algorithm.

Changes in synapse 0.6.0 (2014-12-16)
=====================================

* Add new API for media upload and download that supports thumbnailing.
* Replicate media uploads over multiple homeservers so media is always served
  to clients from their local homeserver.  This obsoletes the
  --content-addr parameter and confusion over accessing content directly
  from remote homeservers.
* Implement exponential backoff when retrying federation requests when
  sending to remote homeservers which are offline.
* Implement typing notifications.
* Fix bugs where we sent events with invalid signatures due to bugs where
  we incorrectly persisted events.
* Improve performance of database queries involving retrieving events.

Changes in synapse 0.5.4a (2014-12-13)
======================================

* Fix bug while generating the error message when a file path specified in
  the config doesn't exist.

Changes in synapse 0.5.4 (2014-12-03)
=====================================

* Fix presence bug where some rooms did not display presence updates for
  remote users.
* Do not log SQL timing log lines when started with "-v"
* Fix potential memory leak.

Changes in synapse 0.5.3c (2014-12-02)
======================================

* Change the default value for the `content_addr` option to use the HTTP
  listener, as by default the HTTPS listener will be using a self-signed
  certificate.

Changes in synapse 0.5.3 (2014-11-27)
=====================================

* Fix bug that caused joining a remote room to fail if a single event was not
  signed correctly.
* Fix bug which caused servers to continuously try and fetch events from other
  servers.

Changes in synapse 0.5.2 (2014-11-26)
=====================================

Fix major bug that caused rooms to disappear from peoples initial sync.

Changes in synapse 0.5.1 (2014-11-26)
=====================================
See UPGRADES.rst for specific instructions on how to upgrade.

 * Fix bug where we served up an Event that did not match its signatures.
 * Fix regression where we no longer correctly handled the case where a
   homeserver receives an event for a room it doesn't recognise (but is in.)

Changes in synapse 0.5.0 (2014-11-19)
=====================================
This release includes changes to the federation protocol and client-server API
that is not backwards compatible.

This release also changes the internal database schemas and so requires servers to
drop their current history. See UPGRADES.rst for details.

Homeserver:
 * Add authentication and authorization to the federation protocol. Events are
   now signed by their originating homeservers.
 * Implement the new authorization model for rooms.
 * Split out web client into a seperate repository: matrix-angular-sdk.
 * Change the structure of PDUs.
 * Fix bug where user could not join rooms via an alias containing 4-byte
   UTF-8 characters.
 * Merge concept of PDUs and Events internally.
 * Improve logging by adding request ids to log lines.
 * Implement a very basic room initial sync API.
 * Implement the new invite/join federation APIs.

Webclient:
 * The webclient has been moved to a seperate repository.

Changes in synapse 0.4.2 (2014-10-31)
=====================================

Homeserver:
 * Fix bugs where we did not notify users of correct presence updates.
 * Fix bug where we did not handle sub second event stream timeouts.

Webclient:
 * Add ability to click on messages to see JSON.
 * Add ability to redact messages.
 * Add ability to view and edit all room state JSON.
 * Handle incoming redactions.
 * Improve feedback on errors.
 * Fix bugs in mobile CSS.
 * Fix bugs with desktop notifications.

Changes in synapse 0.4.1 (2014-10-17)
=====================================
Webclient:
 * Fix bug with display of timestamps.

Changes in synpase 0.4.0 (2014-10-17)
=====================================
This release includes changes to the federation protocol and client-server API
that is not backwards compatible.

The Matrix specification has been moved to a separate git repository:
http://github.com/matrix-org/matrix-doc

You will also need an updated syutil and config. See UPGRADES.rst.

Homeserver:
 * Sign federation transactions to assert strong identity over federation.
 * Rename timestamp keys in PDUs and events from 'ts' and 'hsob_ts' to 'origin_server_ts'.


Changes in synapse 0.3.4 (2014-09-25)
=====================================
This version adds support for using a TURN server. See docs/turn-howto.rst on
how to set one up.

Homeserver:
 * Add support for redaction of messages.
 * Fix bug where inviting a user on a remote home server could take up to
   20-30s.
 * Implement a get current room state API.
 * Add support specifying and retrieving turn server configuration.

Webclient:
 * Add button to send messages to users from the home page.
 * Add support for using TURN for VoIP calls.
 * Show display name change messages.
 * Fix bug where the client didn't get the state of a newly joined room
   until after it has been refreshed.
 * Fix bugs with tab complete.
 * Fix bug where holding down the down arrow caused chrome to chew 100% CPU.
 * Fix bug where desktop notifications occasionally used "Undefined" as the
   display name.
 * Fix more places where we sometimes saw room IDs incorrectly.
 * Fix bug which caused lag when entering text in the text box.

Changes in synapse 0.3.3 (2014-09-22)
=====================================

Homeserver:
 * Fix bug where you continued to get events for rooms you had left.

Webclient:
 * Add support for video calls with basic UI.
 * Fix bug where one to one chats were named after your display name rather
   than the other person's.
 * Fix bug which caused lag when typing in the textarea.
 * Refuse to run on browsers we know won't work.
 * Trigger pagination when joining new rooms.
 * Fix bug where we sometimes didn't display invitations in recents.
 * Automatically join room when accepting a VoIP call.
 * Disable outgoing and reject incoming calls on browsers we don't support
   VoIP in.
 * Don't display desktop notifications for messages in the room you are
   non-idle and speaking in.

Changes in synapse 0.3.2 (2014-09-18)
=====================================

Webclient:
 * Fix bug where an empty "bing words" list in old accounts didn't send
   notifications when it should have done.

Changes in synapse 0.3.1 (2014-09-18)
=====================================
This is a release to hotfix v0.3.0 to fix two regressions.

Webclient:
 * Fix a regression where we sometimes displayed duplicate events.
 * Fix a regression where we didn't immediately remove rooms you were
   banned in from the recents list.

Changes in synapse 0.3.0 (2014-09-18)
=====================================
See UPGRADE for information about changes to the client server API, including
breaking backwards compatibility with VoIP calls and registration API.

Homeserver:
 * When a user changes their displayname or avatar the server will now update 
   all their join states to reflect this.
 * The server now adds "age" key to events to indicate how old they are. This
   is clock independent, so at no point does any server or webclient have to
   assume their clock is in sync with everyone else.
 * Fix bug where we didn't correctly pull in missing PDUs.
 * Fix bug where prev_content key wasn't always returned.
 * Add support for password resets.

Webclient:
 * Improve page content loading.
 * Join/parts now trigger desktop notifications.
 * Always show room aliases in the UI if one is present.
 * No longer show user-count in the recents side panel.
 * Add up & down arrow support to the text box for message sending to step
   through your sent history.
 * Don't display notifications for our own messages.
 * Emotes are now formatted correctly in desktop notifications.
 * The recents list now differentiates between public & private rooms.
 * Fix bug where when switching between rooms the pagination flickered before
   the view jumped to the bottom of the screen.
 * Add bing word support.

Registration API:
 * The registration API has been overhauled to function like the login API. In
   practice, this means registration requests must now include the following:
   'type':'m.login.password'. See UPGRADE for more information on this.
 * The 'user_id' key has been renamed to 'user' to better match the login API.
 * There is an additional login type: 'm.login.email.identity'.
 * The command client and web client have been updated to reflect these changes.

Changes in synapse 0.2.3 (2014-09-12)
=====================================

Homeserver:
 * Fix bug where we stopped sending events to remote home servers if a
   user from that home server left, even if there were some still in the
   room.
 * Fix bugs in the state conflict resolution where it was incorrectly
   rejecting events.

Webclient:
 * Display room names and topics.
 * Allow setting/editing of room names and topics.
 * Display information about rooms on the main page.
 * Handle ban and kick events in real time.
 * VoIP UI and reliability improvements.
 * Add glare support for VoIP.
 * Improvements to initial startup speed.
 * Don't display duplicate join events.
 * Local echo of messages.
 * Differentiate sending and sent of local echo.
 * Various minor bug fixes.

Changes in synapse 0.2.2 (2014-09-06)
=====================================

Homeserver:
 * When the server returns state events it now also includes the previous 
   content.
 * Add support for inviting people when creating a new room.
 * Make the homeserver inform the room via `m.room.aliases` when a new alias
   is added for a room.
 * Validate `m.room.power_level` events.

Webclient:
 * Add support for captchas on registration.
 * Handle `m.room.aliases` events.
 * Asynchronously send messages and show a local echo.
 * Inform the UI when a message failed to send.
 * Only autoscroll on receiving a new message if the user was already at the 
   bottom of the screen.
 * Add support for ban/kick reasons.

Changes in synapse 0.2.1 (2014-09-03)
=====================================

Homeserver:
 * Added support for signing up with a third party id.
 * Add synctl scripts.
 * Added rate limiting.
 * Add option to change the external address the content repo uses.
 * Presence bug fixes.

Webclient:
 * Added support for signing up with a third party id.
 * Added support for banning and kicking users.
 * Added support for displaying and setting ops.
 * Added support for room names.
 * Fix bugs with room membership event display.

Changes in synapse 0.2.0 (2014-09-02)
=====================================
This update changes many configuration options, updates the
database schema and mandates SSL for server-server connections.

Homeserver:
 * Require SSL for server-server connections.
 * Add SSL listener for client-server connections.
 * Add ability to use config files.
 * Add support for kicking/banning and power levels.
 * Allow setting of room names and topics on creation.
 * Change presence to include last seen time of the user.
 * Change url path prefix to /_matrix/...
 * Bug fixes to presence.

Webclient:
 * Reskin the CSS for registration and login.
 * Various improvements to rooms CSS.
 * Support changes in client-server API.
 * Bug fixes to VOIP UI.
 * Various bug fixes to handling of changes to room member list.

Changes in synapse 0.1.2 (2014-08-29)
=====================================

Webclient:
 * Add basic call state UI for VoIP calls.

Changes in synapse 0.1.1 (2014-08-29)
=====================================

Homeserver:
    * Fix bug that caused the event stream to not notify some clients about
      changes.

Changes in synapse 0.1.0 (2014-08-29)
=====================================
Presence has been reenabled in this release.

Homeserver:
 * Update client to server API, including:
    - Use a more consistent url scheme.
    - Provide more useful information in the initial sync api.
 * Change the presence handling to be much more efficient.
 * Change the presence server to server API to not require explicit polling of
   all users who share a room with a user.
 * Fix races in the event streaming logic.

Webclient:
 * Update to use new client to server API.
 * Add basic VOIP support.
 * Add idle timers that change your status to away.
 * Add recent rooms column when viewing a room.
 * Various network efficiency improvements.
 * Add basic mobile browser support.
 * Add a settings page.

Changes in synapse 0.0.1 (2014-08-22)
=====================================
Presence has been disabled in this release due to a bug that caused the
homeserver to spam other remote homeservers.

Homeserver:
 * Completely change the database schema to support generic event types.
 * Improve presence reliability.
 * Improve reliability of joining remote rooms.
 * Fix bug where room join events were duplicated.
 * Improve initial sync API to return more information to the client.
 * Stop generating fake messages for room membership events.

Webclient:
 * Add tab completion of names.
 * Add ability to upload and send images.
 * Add profile pages.
 * Improve CSS layout of room.
 * Disambiguate identical display names.
 * Don't get remote users display names and avatars individually.
 * Use the new initial sync API to reduce number of round trips to the homeserver.
 * Change url scheme to use room aliases instead of room ids where known.
 * Increase longpoll timeout.

Changes in synapse 0.0.0 (2014-08-13)
=====================================

 * Initial alpha release
