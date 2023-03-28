# Experimental Features API

This API allows a server administrator to enable or disable some experimental features on a per-user
basis. Currently supported features are [msc3026](https://github.com/matrix-org/matrix-spec-proposals/pull/3026): busy presence state enabled,  [msc2654](https://github.com/matrix-org/matrix-spec-proposals/pull/2654): enable unread counts,
[msc3881](https://github.com/matrix-org/matrix-spec-proposals/pull/3881): enable remotely toggling push notifications for another client, and [msc3967](https://github.com/matrix-org/matrix-spec-proposals/pull/3967): do not require
UIA when first uploading cross-signing keys. 


To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

## Enable a Feature

This API allows a server administrator to enable an experimental feature for a given user, where the
user_id is the user id of the user for whom to enable the feature, and the feature is referred to by
the msc number - i.e. to enable unread counts, the parameter `msc2654` would be added to the url. 

The API is:

```
PUT /_synapse/admin/v1/experimental_features/<user_id>/<feature>
```

## Disable a Feature

To disable a currently enabled feature, the API is:

```
DELETE /_synapse/admin/v1/experimental_features/<user_id>/<feature>
```

## Check if a feature is enabled

To check if a given feature is enabled for a given user, the API is:

```
GET /_synapse/admin/v1/experimental_features/<user_id>/<feature>
```