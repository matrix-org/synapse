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
