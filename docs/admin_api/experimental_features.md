# Experimental Features API

This API allows a server administrator to enable or disable some experimental features on a per-user
basis. The currently supported features are: 
- [MSC3026](https://github.com/matrix-org/matrix-spec-proposals/pull/3026): busy 
presence state enabled
- [MSC3881](https://github.com/matrix-org/matrix-spec-proposals/pull/3881): enable remotely toggling push notifications 
for another client 
- [MSC3967](https://github.com/matrix-org/matrix-spec-proposals/pull/3967): do not require
UIA when first uploading cross-signing keys. 


To use it, you will need to authenticate by providing an `access_token`
for a server admin: see [Admin API](../usage/administration/admin_api/).

## Enabling/Disabling Features

This API allows a server administrator to enable experimental features for a given user. The request must 
provide a body containing the user id and listing the features to enable/disable in the following format:
```json
{
   "features": {
      "msc3026":true,
      "msc3881":true
   }
}
```
where true is  used to enable the feature, and false is used to disable the feature.


The API is:

```
PUT /_synapse/admin/v1/experimental_features/<user_id>
```

## Listing Enabled Features
 
To list which features are enabled/disabled for a given user send a request to the following API:

```
GET /_synapse/admin/v1/experimental_features/<user_id>
```

It will return a list of possible features and indicate whether they are enabled or disabled for the
user like so:
```json
{
   "features": {
      "msc3026": true,
      "msc3881": false,
      "msc3967": false
   }
}
```