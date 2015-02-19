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
