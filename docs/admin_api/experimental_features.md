# Experimental Features API

This API allows a server administrator to enable or disable some experimental features on a per-user
basis. Currently supported features are [msc3026](https://github.com/matrix-org/matrix-spec-proposals/pull/3026): busy 
presence state enabled,  [msc2654](https://github.com/matrix-org/matrix-spec-proposals/pull/2654): enable unread counts,
[msc3881](https://github.com/matrix-org/matrix-spec-proposals/pull/3881): enable remotely toggling push notifications 
for another client, and [msc3967](https://github.com/matrix-org/matrix-spec-proposals/pull/3967): do not require
UIA when first uploading cross-signing keys. 


To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

## Enabling/Disabling Features

This API allows a server administrator to enable experimental features for a given user, where the
`user_id` is the user id of the user for whom to enable or disable the features. The request must 
provide a body listing the features to enable/disable in the following format:
```
{
"features": {"msc3026": True, "msc2654": True}
}

```
where True is  used to enable the feature, and False is used to disable the feature.


The API is:

```
PUT /_synapse/admin/v1/experimental_features/<user_id>
```

## Listing Enabled Features
 
To list the enabled features for a given user, use the following API:

```
GET /_synapse/admin/v1/experimental_features
```

It will return a list of enabled features in the following format:
```
{"user_id": user_id, "features": ["msc3026"]}
```