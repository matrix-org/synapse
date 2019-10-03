URL Previews
============

Design notes on a URL previewing service for Matrix:

Options are:

 1. Have an AS which listens for URLs, downloads them, and inserts an event that describes their metadata.
   * Pros:
     * Decouples the implementation entirely from Synapse.
     * Uses existing Matrix events & content repo to store the metadata.
   * Cons:
     * Which AS should provide this service for a room, and why should you trust it?
     * Doesn't work well with E2E; you'd have to cut the AS into every room
     * the AS would end up subscribing to every room anyway.

 2. Have a generic preview API (nothing to do with Matrix) that provides a previewing service:
   * Pros:
     * Simple and flexible; can be used by any clients at any point
   * Cons:
     * If each HS provides one of these independently, all the HSes in a room may needlessly DoS the target URI
     * We need somewhere to store the URL metadata rather than just using Matrix itself
     * We can't piggyback on matrix to distribute the metadata between HSes.

 3. Make the synapse of the sending user responsible for spidering the URL and inserting an event asynchronously which describes the metadata.
   * Pros:
     * Works transparently for all clients
     * Piggy-backs nicely on using Matrix for distributing the metadata.
     * No confusion as to which AS
   * Cons:
     * Doesn't work with E2E
     * We might want to decouple the implementation of the spider from the HS, given spider behaviour can be quite complicated and evolve much more rapidly than the HS.  It's more like a bot than a core part of the server.

 4. Make the sending client use the preview API and insert the event itself when successful.
   * Pros:
      * Works well with E2E
      * No custom server functionality
      * Lets the client customise the preview that they send (like on FB)
   * Cons:
      * Entirely specific to the sending client, whereas it'd be nice if /any/ URL was correctly previewed if clients support it.

 5. Have the option of specifying a shared (centralised) previewing service used by a room, to avoid all the different HSes in the room DoSing the target.

Best solution is probably a combination of both 2 and 4.
 * Sending clients do their best to create and send a preview at the point of sending the message, perhaps delaying the message until the preview is computed?  (This also lets the user validate the preview before sending)
 * Receiving clients have the option of going and creating their own preview if one doesn't arrive soon enough (or if the original sender didn't create one)

This is a bit magical though in that the preview could come from two entirely different sources - the sending HS or your local one.  However, this can always be exposed to users: "Generate your own URL previews if none are available?"

This is tantamount also to senders calculating their own thumbnails for sending in advance of the main content - we are trusting the sender not to lie about the content in the thumbnail.  Whereas currently thumbnails are calculated by the receiving homeserver to avoid this attack.

However, this kind of phishing attack does exist whether we let senders pick their thumbnails or not, in that a malicious sender can send normal text messages around the attachment claiming it to be legitimate.  We could rely on (future) reputation/abuse management to punish users who phish (be it with bogus metadata or bogus descriptions).   Bogus metadata is particularly bad though, especially if it's avoidable.

As a first cut, let's do #2 and have the receiver hit the API to calculate its own previews (as it does currently for image thumbnails).  We can then extend/optimise this to option 4 as a special extra if needed.

API
---

```
GET /_matrix/media/r0/preview_url?url=http://wherever.com
200 OK
{
    "og:type"        : "article"
    "og:url"         : "https://twitter.com/matrixdotorg/status/684074366691356672"
    "og:title"       : "Matrix on Twitter"
    "og:image"       : "https://pbs.twimg.com/profile_images/500400952029888512/yI0qtFi7_400x400.png"
    "og:description" : "“Synapse 0.12 is out! Lots of polishing, performance &amp;amp; bugfixes: /sync API, /r0 prefix, fulltext search, 3PID invites https://t.co/5alhXLLEGP”"
    "og:site_name"   : "Twitter"
}
```

* Downloads the URL
  * If HTML, just stores it in RAM and parses it for OG meta tags
    * Download any media OG meta tags to the media repo, and refer to them in the OG via mxc:// URIs.
  * If a media filetype we know we can thumbnail: store it on disk, and hand it to the thumbnailer. Generate OG meta tags from the thumbnailer contents.
  * Otherwise, don't bother downloading further.
