# Refresh Tokens

Synapse supports refresh tokens since version 1.49 (some earlier versions had support for an earlier, experimental draft of [MSC2918] which is not compatible).


[MSC2918]: https://github.com/matrix-org/matrix-doc/blob/main/proposals/2918-refreshtokens.md#msc2918-refresh-tokens


## Background and motivation

Synapse users' sessions are identified by **access tokens**; access tokens are
issued to users on login. Each session gets a unique access token which identifies
it; the access token must be kept secret as it grants access to the user's account.

Traditionally, these access tokens were eternally valid (at least until the user
explicitly chose to log out).

In some cases, it may be desirable for these access tokens to expire so that the
potential damage caused by leaking an access token is reduced.
On the other hand, forcing a user to re-authenticate (log in again) often might
be too much of an inconvenience.

**Refresh tokens** are a mechanism to avoid some of this inconvenience whilst
still getting most of the benefits of short access token lifetimes.
Refresh tokens are also a concept present in OAuth 2 — further reading is available
[here](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5).

When refresh tokens are in use, both an access token and a refresh token will be
issued to users on login. The access token will expire after a predetermined amount
of time, but otherwise works in the same way as before. When the access token is
close to expiring (or has expired), the user's client should present the homeserver
(Synapse) with the refresh token.

The homeserver will then generate a new access token and refresh token for the user
and return them. The old refresh token is invalidated and can not be used again*.

Finally, refresh tokens also make it possible for sessions to be logged out if they
are inactive for too long, before the session naturally ends; see the configuration
guide below.


*To prevent issues if clients lose connection half-way through refreshing a token,
the refresh token is only invalidated once the new access token has been used at
least once. For all intents and purposes, the above simplification is sufficient.


## Caveats

There are some caveats:

* If a third party gets both your access token and refresh token, they will be able to
  continue to enjoy access to your session.
  * This is still an improvement because you (the user) will notice when *your*
    session expires and you're not able to use your refresh token.
    That would be a giveaway that someone else has compromised your session.
    You would be able to log in again and terminate that session.
    Previously (with long-lived access tokens), a third party that has your access
    token could go undetected for a very long time.
* Clients need to implement support for refresh tokens in order for them to be a
  useful mechanism.
  * It is up to homeserver administrators if they want to issue long-lived access
    tokens to clients not implementing refresh tokens.
    * For compatibility, it is likely that they should, at least until client support
      is widespread.
      * Users with clients that support refresh tokens will still benefit from the
        added security; it's not possible to downgrade a session to using long-lived
        access tokens so this effectively gives users the choice.
    * In a closed environment where all users use known clients, this may not be
      an issue as the homeserver administrator can know if the clients have refresh
      token support. In that case, the non-refreshable access token lifetime
      may be set to a short duration so that a similar level of security is provided.


## Configuration Guide

The following configuration options, in the `registration` section, are related:

* `session_lifetime`: maximum length of a session, even if it's refreshed.
  In other words, the client must log in again after this time period.
  In most cases, this can be unset (infinite) or set to a long time (years or months).
* `refreshable_access_token_lifetime`: lifetime of access tokens that are created
  by clients supporting refresh tokens.
  This should be short; a good value might be 5 minutes (`5m`).
* `nonrefreshable_access_token_lifetime`: lifetime of access tokens that are created
  by clients which don't support refresh tokens.
  Make this short if you want to effectively force use of refresh tokens.
  Make this long if you don't want to inconvenience users of clients which don't
  support refresh tokens (by forcing them to frequently re-authenticate using
  login credentials).
* `refresh_token_lifetime`: lifetime of refresh tokens.
  In other words, the client must refresh within this time period to maintain its session.
  Unless you want to log inactive sessions out, it is often fine to use a long
  value here or even leave it unset (infinite).
  Beware that making it too short will inconvenience clients that do not connect
  very often, including mobile clients and clients of infrequent users (by making
  it more difficult for them to refresh in time, which may force them to need to
  re-authenticate using login credentials).

**Note:** All four options above only apply when tokens are created (by logging in or refreshing).
Changes to these settings do not apply retroactively.


### Using refresh token expiry to log out inactive sessions

If you'd like to force sessions to be logged out upon inactivity, you can enable
refreshable access token expiry and refresh token expiry.

This works because a client must refresh at least once within a period of
`refresh_token_lifetime` in order to maintain valid credentials to access the
account.

(It's suggested that `refresh_token_lifetime` should be longer than
`refreshable_access_token_lifetime` and this section assumes that to be the case
for simplicity.)

Note: this will only affect sessions using refresh tokens. You may wish to
set a short `nonrefreshable_access_token_lifetime` to prevent this being bypassed
by clients that do not support refresh tokens.


#### Choosing values that guarantee permitting some inactivity

It may be desirable to permit some short periods of inactivity, for example to
accommodate brief outages in client connectivity.

The following model aims to provide guidance for choosing `refresh_token_lifetime`
and `refreshable_access_token_lifetime` to satisfy requirements of the form:

1. inactivity longer than `L` **MUST** cause the session to be logged out; and
2. inactivity shorter than `S` **MUST NOT** cause the session to be logged out.

This model makes the weakest assumption that all active clients will refresh as
needed to maintain an active access token, but no sooner.
*In reality, clients may refresh more often than this model assumes, but the
above requirements will still hold.*

To satisfy the above model,
* `refresh_token_lifetime` should be set to `L`; and
* `refreshable_access_token_lifetime` should be set to `L - S`.
