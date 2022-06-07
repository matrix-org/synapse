URL Previews
============

The `GET /_matrix/media/r0/preview_url` endpoint provides a generic preview API
for URLs which outputs [Open Graph](https://ogp.me/) responses (with some Matrix
specific additions).

This does have trade-offs compared to other designs:

* Pros:
  * Simple and flexible; can be used by any clients at any point
* Cons:
  * If each homeserver provides one of these independently, all the HSes in a
    room may needlessly DoS the target URI
  * The URL metadata must be stored somewhere, rather than just using Matrix
    itself to store the media.
  * Matrix cannot be used to distribute the metadata between homeservers.

When Synapse is asked to preview a URL it does the following:

1. Checks against a URL blacklist (defined as `url_preview_url_blacklist` in the
   config).
2. Checks the in-memory cache by URLs and returns the result if it exists. (This
   is also used to de-duplicate processing of multiple in-flight requests at once.)
3. Kicks off a background process to generate a preview:
   1. Checks the database cache by URL and timestamp and returns the result if it
      has not expired and was successful (a 2xx return code).
   2. Checks if the URL matches an [oEmbed](https://oembed.com/) pattern. If it
      does, update the URL to download.
   3. Downloads the URL and stores it into a file via the media storage provider
      and saves the local media metadata.
   4. If the media is an image:
      1. Generates thumbnails.
      2. Generates an Open Graph response based on image properties.
   5. If the media is HTML:
      1. Decodes the HTML via the stored file.
      2. Generates an Open Graph response from the HTML.
      3. If a JSON oEmbed URL was found in the HTML via autodiscovery:
         1. Downloads the URL and stores it into a file via the media storage provider
            and saves the local media metadata.
         2. Convert the oEmbed response to an Open Graph response.
         3. Override any Open Graph data from the HTML with data from oEmbed.
      4. If an image exists in the Open Graph response:
         1. Downloads the URL and stores it into a file via the media storage
            provider and saves the local media metadata.
         2. Generates thumbnails.
         3. Updates the Open Graph response based on image properties.
   6. If the media is JSON and an oEmbed URL was found:
      1. Convert the oEmbed response to an Open Graph response.
      2. If a thumbnail or image is in the oEmbed response:
         1. Downloads the URL and stores it into a file via the media storage
            provider and saves the local media metadata.
         2. Generates thumbnails.
         3. Updates the Open Graph response based on image properties.
   7. Stores the result in the database cache.
4. Returns the result.

The in-memory cache expires after 1 hour.

Expired entries in the database cache (and their associated media files) are
deleted every 10 seconds. The default expiration time is 1 hour from download.
