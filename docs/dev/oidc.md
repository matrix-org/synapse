# How to test OpenID Connect

Any OpenID Connect Provider (OP) should work with Synapse, as long as it supports the authorization code flow.
There are a few options for that:

 - start a local OP. Synapse has been tested with [Hydra][hydra] and [Dex][dex-idp].
   Note that for an OP to work, it should be served under a secure (HTTPS) origin.
   A certificate signed with a self-signed, locally trusted CA should work. In that case, start Synapse with a `SSL_CERT_FILE` environment variable set to the path of the CA.
 - use a publicly available OP. Synapse has been tested with [Google][google-idp].
 - setup a SaaS OP, like [Auth0][auth0] and [Okta][okta]. Auth0 has a free tier which has been tested with Synapse.

[google-idp]: https://developers.google.com/identity/protocols/OpenIDConnect#authenticatingtheuser
[auth0]: https://auth0.com/
[okta]: https://www.okta.com/
[dex-idp]: https://github.com/dexidp/dex
[hydra]: https://www.ory.sh/docs/hydra/


## Sample configs

Here are a few configs for providers that should work with Synapse.

### [Dex][dex-idp]

[Dex][dex-idp] is a simple, open-source, certified OpenID Connect Provider.
Although it is designed to help building a full-blown provider, with some external database, it can be configured with static passwords in a config file.

Follow the [Getting Started guide](https://github.com/dexidp/dex/blob/master/Documentation/getting-started.md) to install Dex.

Edit `examples/config-dev.yaml` config file from the Dex repo to add a client:

```yaml
staticClients:
- id: synapse
  secret: secret
  redirectURIs:
  - '[synapse base url]/_synapse/oidc/callback'
  name: 'Synapse'
```

Run with `dex serve examples/config-dex.yaml`

Synapse config:

```yaml
oidc_config:
   enabled: true
   skip_verification: true # This is needed as Dex is served on an insecure endpoint
   issuer: "http://127.0.0.1:5556/dex"
   discover: true
   client_id: "synapse"
   client_secret: "secret"
   scopes:
     - openid
     - profile
   mapping_templates:
     localpart: '{{ user.name }}'
     display_name: '{{ user.name|capitalize }}'
```

### [Auth0][auth0]

1. Create a regular web application for Synapse
2. Set the Allowed Callback URLs to `[synapse base url]/_synapse/oidc/callback`
3. Add a rule to add the `preferred_username` claim.
   <details>
    <summary>Code sample</summary>

    ```js
    function addPersistenceAttribute(user, context, callback) {
      user.user_metadata = user.user_metadata || {};
      user.user_metadata.preferred_username = user.user_metadata.preferred_username || user.user_id;
      context.idToken.preferred_username = user.user_metadata.preferred_username;

      auth0.users.updateUserMetadata(user.user_id, user.user_metadata)
        .then(function(){
            callback(null, user, context);
        })
        .catch(function(err){
            callback(err);
        });
    }
    ```

  </details>


```yaml
oidc_config:
   enabled: true
   issuer: "https://your-tier.eu.auth0.com/" # TO BE FILLED
   discover: true
   client_id: "your-client-id" # TO BE FILLED
   client_secret: "your-client-secret" # TO BE FILLED
   scopes:
     - openid
     - profile
   mapping_templates:
     localpart: '{{ user.preferred_username }}'
     display_name: '{{ user.name }}'
```

### GitHub

GitHub is a bit special as it is not an OpenID Connect compliant provider, but just a regular OAuth2 provider.
The `/user` API endpoint can be used to retrieve informations from the user.
As the OIDC login mechanism needs an attribute to uniquely identify users and that endpoint does not return a `sub` property, an alternative `subject_claim` has to be set.

1. Create a new OAuth application: https://github.com/settings/applications/new
2. Set the callback URL to `[synapse base url]/_synapse/oidc/callback`

```yaml
oidc_config:
   enabled: true
   issuer: "https://github.com/"
   discover: false
   client_id: "your-client-id" # TO BE FILLED
   client_secret: "your-client-secret" # TO BE FILLED
   authorization_endpoint: "https://github.com/login/oauth/authorize"
   token_endpoint: "https://github.com/login/oauth/access_token"
   userinfo_endpoint: "https://api.github.com/user"
   subject_claim: 'id'
   scopes:
     - read:user
   mapping_templates:
     localpart: '{{ user.login }}'
     display_name: '{{ user.name }}'
```

### Google

1. Setup a project in the Google API Console
2. Obtain the OAuth 2.0 credentials (see <https://developers.google.com/identity/protocols/oauth2/openid-connect>)
3. Add this Authorized redirect URI: `[synapse base url]/_synapse/oidc/callback`

```yaml
oidc_config:
   enabled: true
   issuer: "https://accounts.google.com/"
   discover: true
   client_id: "your-client-id" # TO BE FILLED
   client_secret: "your-client-secret" # TO BE FILLED
   scopes:
     - openid
     - profile
   mapping_templates:
     localpart: '{{ user.given_name|lower }}'
     display_name: '{{ user.name }}'
```
