# Templates

Synapse uses parametrised templates to generate the content of emails it sends and
webpages it shows to users.

By default, Synapse will use the templates listed [here](https://github.com/matrix-org/synapse/tree/master/synapse/res/templates).
Server admins can configure an additional directory for Synapse to look for templates
in, allowing them to specify custom templates:

```yaml
templates:
  custom_template_directory: /path/to/custom/templates/
```

If this setting is not set, or the files named below are not found within the directory,
default templates from within the Synapse package will be used.

Templates that are given variables when being rendered are rendered using [Jinja 2](https://jinja.palletsprojects.com/en/2.11.x/).
Templates rendered by Jinja 2 can also access two functions on top of the functions
already available as part of Jinja 2:

```python
format_ts(value: int, format: str) -> str
```

Formats a timestamp in milliseconds.

Example: `reason.last_sent_ts|format_ts("%c")`

```python
mxc_to_http(value: str, width: int, height: int, resize_method: str = "crop") -> str
```

Turns a `mxc://` URL for media content into an HTTP(S) one using the homeserver's
`public_baseurl` configuration setting as the URL's base.

Example: `message.sender_avatar_url|mxc_to_http(32,32)`

```python
localpart_from_email(address: str) -> str
```

Returns the local part of an email address (e.g. `alice` in `alice@example.com`).

Example: `user.email_address|localpart_from_email`

## Email templates

Below are the templates Synapse will look for when generating the content of an email:

* `notif_mail.html` and `notif_mail.txt`: The contents of email notifications of missed
  events.
  When rendering, this template is given the following variables:
    * `user_display_name`: the display name for the user receiving the notification
    * `unsubscribe_link`: the link users can click to unsubscribe from email notifications
    * `summary_text`: a summary of the notification(s). The text used can be customised
      by configuring the various settings in the `email.subjects` section of the
      configuration file.
    * `rooms`: a list of rooms containing events to include in the email. Each element is
      an object with the following attributes:
        * `title`: a human-readable name for the room
        * `hash`: a hash of the ID of the room
        * `invite`: a boolean, which is `True` if the room is an invite the user hasn't
          accepted yet, `False` otherwise
        * `notifs`: a list of events, or an empty list if `invite` is `True`. Each element
          is an object with the following attributes:
            * `link`: a `matrix.to` link to the event
            * `ts`: the time in milliseconds at which the event was received
            * `messages`: a list of messages containing one message before the event, the
              message in the event, and one message after the event. Each element is an
              object with the following attributes:
                * `event_type`: the type of the event
                * `is_historical`: a boolean, which is `False` if the message is the one
                  that triggered the notification, `True` otherwise
                * `id`: the ID of the event
                * `ts`: the time in milliseconds at which the event was sent
                * `sender_name`: the display name for the event's sender
                * `sender_avatar_url`: the avatar URL (as a `mxc://` URL) for the event's
                  sender
                * `sender_hash`: a hash of the user ID of the sender
                * `msgtype`: the type of the message
                * `body_text_html`: html representation of the message
                * `body_text_plain`: plaintext representation of the message
                * `image_url`: mxc url of an image, when "msgtype" is "m.image"
        * `link`: a `matrix.to` link to the room
        * `avator_url`: url to the room's avator
    * `reason`: information on the event that triggered the email to be sent. It's an
      object with the following attributes:
        * `room_id`: the ID of the room the event was sent in
        * `room_name`: a human-readable name for the room the event was sent in
        * `now`: the current time in milliseconds
        * `received_at`: the time in milliseconds at which the event was received
        * `delay_before_mail_ms`: the amount of time in milliseconds Synapse always waits
          before ever emailing about a notification (to give the user a chance to respond
          to other push or notice the window)
        * `last_sent_ts`: the time in milliseconds at which a notification was last sent
          for an event in this room
        * `throttle_ms`: the minimum amount of time in milliseconds between two
          notifications can be sent for this room
* `password_reset.html` and `password_reset.txt`: The contents of password reset emails
  sent by the homeserver.
  When rendering, these templates are given a `link` variable which contains the link the
  user must click in order to reset their password.
* `registration.html` and `registration.txt`: The contents of address verification emails
  sent during registration.
  When rendering, these templates are given a `link` variable which contains the link the
  user must click in order to validate their email address.
* `add_threepid.html` and `add_threepid.txt`: The contents of address verification emails
  sent when an address is added to a Matrix account.
  When rendering, these templates are given a `link` variable which contains the link the
  user must click in order to validate their email address.


## HTML page templates for registration and password reset

Below are the templates Synapse will look for when generating pages related to
registration and password reset:

* `password_reset_confirmation.html`: An HTML page that a user will see when they follow
  the link in the password reset email. The user will be asked to confirm the action
  before their password is reset.
  When rendering, this template is given the following variables:
    * `sid`: the session ID for the password reset
    * `token`: the token for the password reset
    * `client_secret`: the client secret for the password reset
* `password_reset_success.html` and `password_reset_failure.html`: HTML pages for success
  and failure that a user will see when they confirm the password reset flow using the
  page above.
  When rendering, `password_reset_success.html` is given no variable, and
  `password_reset_failure.html` is given a `failure_reason`, which contains the reason
  for the password reset failure. 
* `registration_success.html` and `registration_failure.html`: HTML pages for success and
  failure that a user will see when they follow the link in an address verification email
  sent during registration.
  When rendering, `registration_success.html` is given no variable, and
  `registration_failure.html` is given a `failure_reason`, which contains the reason
  for the registration failure.
* `add_threepid_success.html` and `add_threepid_failure.html`: HTML pages for success and
  failure that a user will see when they follow the link in an address verification email
  sent when an address is added to a Matrix account.
  When rendering, `add_threepid_success.html` is given no variable, and
  `add_threepid_failure.html` is given a `failure_reason`, which contains the reason
  for the registration failure.


## HTML page templates for Single Sign-On (SSO)

Below are the templates Synapse will look for when generating pages related to SSO:

* `sso_login_idp_picker.html`: HTML page to prompt the user to choose an
  Identity Provider during login.
  This is only used if multiple SSO Identity Providers are configured.
  When rendering, this template is given the following variables:
    * `redirect_url`: the URL that the user will be redirected to after
      login.
    * `server_name`: the homeserver's name.
    * `providers`: a list of available Identity Providers. Each element is
      an object with the following attributes:
        * `idp_id`: unique identifier for the IdP
        * `idp_name`: user-facing name for the IdP
        * `idp_icon`: if specified in the IdP config, an MXC URI for an icon
             for the IdP
        * `idp_brand`: if specified in the IdP config, a textual identifier
             for the brand of the IdP
  The rendered HTML page should contain a form which submits its results
  back as a GET request, with the following query parameters:
    * `redirectUrl`: the client redirect URI (ie, the `redirect_url` passed
      to the template)
    * `idp`: the 'idp_id' of the chosen IDP.
* `sso_auth_account_details.html`: HTML page to prompt new users to enter a
  userid and confirm other details. This is only shown if the
  SSO implementation (with any `user_mapping_provider`) does not return
  a localpart.
  When rendering, this template is given the following variables:
    * `server_name`: the homeserver's name.
    * `idp`: details of the SSO Identity Provider that the user logged in
      with: an object with the following attributes:
        * `idp_id`: unique identifier for the IdP
        * `idp_name`: user-facing name for the IdP
        * `idp_icon`: if specified in the IdP config, an MXC URI for an icon
             for the IdP
        * `idp_brand`: if specified in the IdP config, a textual identifier
             for the brand of the IdP
    * `user_attributes`: an object containing details about the user that
      we received from the IdP. May have the following attributes:
        * `display_name`: the user's display name
        * `emails`: a list of email addresses
        * `localpart`: the local part of the Matrix user ID to register,
          if `localpart_template` is set in the mapping provider configuration (empty
          string if not)
  The template should render a form which submits the following fields:
    * `username`: the localpart of the user's chosen user id
* `sso_new_user_consent.html`: HTML page allowing the user to consent to the
  server's terms and conditions. This is only shown for new users, and only if
  `user_consent.require_at_registration` is set.
  When rendering, this template is given the following variables:
    * `server_name`: the homeserver's name.
    * `user_id`: the user's matrix proposed ID.
    * `user_profile.display_name`: the user's proposed display name, if any.
    * consent_version: the version of the terms that the user will be
      shown
    * `terms_url`: a link to the page showing the terms.
  The template should render a form which submits the following fields:
    * `accepted_version`: the version of the terms accepted by the user
      (ie, 'consent_version' from the input variables).
* `sso_redirect_confirm.html`: HTML page for a confirmation step before redirecting back
  to the client with the login token.
  When rendering, this template is given the following variables:
    * `redirect_url`: the URL the user is about to be redirected to.
    * `display_url`: the same as `redirect_url`, but with the query
                   parameters stripped. The intention is to have a
                   human-readable URL to show to users, not to use it as
                   the final address to redirect to.
    * `server_name`: the homeserver's name.
    * `new_user`: a boolean indicating whether this is the user's first time
         logging in.
    * `user_id`: the user's matrix ID.
    * `user_profile.avatar_url`: an MXC URI for the user's avatar, if any.
          `None` if the user has not set an avatar.
    * `user_profile.display_name`: the user's display name. `None` if the user
          has not set a display name.
* `sso_auth_confirm.html`: HTML page which notifies the user that they are authenticating
  to confirm an operation on their account during the user interactive authentication
  process.
  When rendering, this template is given the following variables:
    * `redirect_url`: the URL the user is about to be redirected to.
    * `description`: the operation which the user is being asked to confirm
    * `idp`: details of the Identity Provider that we will use to confirm
      the user's identity: an object with the following attributes:
        * `idp_id`: unique identifier for the IdP
        * `idp_name`: user-facing name for the IdP
        * `idp_icon`: if specified in the IdP config, an MXC URI for an icon
             for the IdP
        * `idp_brand`: if specified in the IdP config, a textual identifier
             for the brand of the IdP
* `sso_auth_success.html`: HTML page shown after a successful user interactive
  authentication session.
  Note that this page must include the JavaScript which notifies of a successful
  authentication (see https://matrix.org/docs/spec/client_server/r0.6.0#fallback).
  This template has no additional variables.
* `sso_auth_bad_user.html`: HTML page shown after a user-interactive authentication
  session which does not map correctly onto the expected user.
  When rendering, this template is given the following variables:
    * `server_name`: the homeserver's name.
    * `user_id_to_verify`: the MXID of the user that we are trying to
      validate.
* `sso_account_deactivated.html`: HTML page shown during single sign-on if a deactivated
  user (according to Synapse's database) attempts to login.
  This template has no additional variables.
* `sso_error.html`: HTML page to display to users if something goes wrong during the
  OpenID Connect authentication process.
  When rendering, this template is given two variables:
    * `error`: the technical name of the error
    * `error_description`: a human-readable message for the error
