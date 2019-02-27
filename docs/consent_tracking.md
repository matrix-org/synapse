Support in Synapse for tracking agreement to server terms and conditions
========================================================================

Synapse 0.30 introduces support for tracking whether users have agreed to the
terms and conditions set by the administrator of a server - and blocking access
to the server until they have.

There are several parts to this functionality; each requires some specific
configuration in `homeserver.yaml` to be enabled.

Note that various parts of the configuation and this document refer to the
"privacy policy": agreement with a privacy policy is one particular use of this
feature, but of course adminstrators can specify other terms and conditions
unrelated to "privacy" per se.

Collecting policy agreement from a user
---------------------------------------

Synapse can be configured to serve the user a simple policy form with an
"accept" button. Clicking "Accept" records the user's acceptance in the
database and shows a success page.

To enable this, first create templates for the policy and success pages.
These should be stored on the local filesystem.

These templates use the [Jinja2](http://jinja.pocoo.org) templating language,
and [docs/privacy_policy_templates](privacy_policy_templates) gives
examples of the sort of thing that can be done.

Note that the templates must be stored under a name giving the language of the
template - currently this must always be `en` (for "English");
internationalisation support is intended for the future.

The template for the policy itself should be versioned and named according to
the version: for example `1.0.html`. The version of the policy which the user
has agreed to is stored in the database.

Once the templates are in place, make the following changes to `homeserver.yaml`:

 1. Add a `user_consent` section, which should look like:

    ```yaml
    user_consent:
      template_dir: privacy_policy_templates
      version: 1.0
    ```

    `template_dir` points to the directory containing the policy
    templates. `version` defines the version of the policy which will be served
    to the user. In the example above, Synapse will serve
    `privacy_policy_templates/en/1.0.html`.


 2. Add a `form_secret` setting at the top level:


    ```yaml
    form_secret: "<unique secret>"
    ```

    This should be set to an arbitrary secret string (try `pwgen -y 30` to
    generate suitable secrets).

    More on what this is used for below.

 3. Add `consent` wherever the `client` resource is currently enabled in the
    `listeners` configuration. For example:

    ```yaml
    listeners:
      - port: 8008
        resources:
          - names:
            - client
            - consent
    ```


Finally, ensure that `jinja2` is installed. If you are using a virtualenv, this
should be a matter of `pip install Jinja2`. On debian, try `apt-get install
python-jinja2`.

Once this is complete, and the server has been restarted, try visiting
`https://<server>/_matrix/consent`. If correctly configured, this should give
an error "Missing string query parameter 'u'". It is now possible to manually
construct URIs where users can give their consent.

### Enabling consent tracking at registration

1. Add the following to your configuration:

   ```yaml
   user_consent:
     require_at_registration: true
     policy_name: "Privacy Policy" # or whatever you'd like to call the policy
   ```

2. In your consent templates, make use of the `public_version` variable to
   see if an unauthenticated user is viewing the page. This is typically
   wrapped around the form that would be used to actually agree to the document:

   ```
   {% if not public_version %}
     <!-- The variables used here are only provided when the 'u' param is given to the homeserver -->
     <form method="post" action="consent">
       <input type="hidden" name="v" value="{{version}}"/>
       <input type="hidden" name="u" value="{{user}}"/>
       <input type="hidden" name="h" value="{{userhmac}}"/>
       <input type="submit" value="Sure thing!"/>
     </form>
   {% endif %}
   ```

3. Restart Synapse to apply the changes.

Visiting `https://<server>/_matrix/consent` should now give you a view of the privacy
document. This is what users will be able to see when registering for accounts.

### Constructing the consent URI

It may be useful to manually construct the "consent URI" for a given user - for
instance, in order to send them an email asking them to consent. To do this,
take the base `https://<server>/_matrix/consent` URL and add the following
query parameters:

 * `u`: the user id of the user. This can either be a full MXID
   (`@user:server.com`) or just the localpart (`user`).

 * `h`: hex-encoded HMAC-SHA256 of `u` using the `form_secret` as a key. It is
   possible to calculate this on the commandline with something like:

   ```bash
   echo -n '<user>' | openssl sha256 -hmac '<form_secret>'
   ```

   This should result in a URI which looks something like:
   `https://<server>/_matrix/consent?u=<user>&h=68a152465a4d...`.


Note that not providing a `u` parameter will be interpreted as wanting to view
the document from an unauthenticated perspective, such as prior to registration.
Therefore, the `h` parameter is not required in this scenario. To enable this
behaviour, set `require_at_registration` to `true` in your `user_consent` config.


Sending users a server notice asking them to agree to the policy
----------------------------------------------------------------

It is possible to configure Synapse to send a [server
notice](server_notices.md) to anybody who has not yet agreed to the current
version of the policy. To do so:

 * ensure that the consent resource is configured, as in the previous section

 * ensure that server notices are configured, as in [server_notices.md](server_notices.md).

 * Add `server_notice_content` under `user_consent` in `homeserver.yaml`. For
   example:

   ```yaml
   user_consent:
     server_notice_content:
       msgtype: m.text
       body: >-
         Please give your consent to the privacy policy at %(consent_uri)s.
   ```

   Synapse automatically replaces the placeholder `%(consent_uri)s` with the
   consent uri for that user.

 * ensure that `public_baseurl` is set in `homeserver.yaml`, and gives the base
   URI that clients use to connect to the server. (It is used to construct
   `consent_uri` in the server notice.)


Blocking users from using the server until they agree to the policy
-------------------------------------------------------------------

Synapse can be configured to block any attempts to join rooms or send messages
until the user has given their agreement to the policy. (Joining the server
notices room is exempted from this).

To enable this, add `block_events_error` under `user_consent`. For example:

```yaml
user_consent:
  block_events_error: >-
    You can't send any messages until you consent to the privacy policy at
    %(consent_uri)s.
```

Synapse automatically replaces the placeholder `%(consent_uri)s` with the
consent uri for that user.

ensure that `public_baseurl` is set in `homeserver.yaml`, and gives the base
URI that clients use to connect to the server. (It is used to construct
`consent_uri` in the error.)
