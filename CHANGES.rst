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
