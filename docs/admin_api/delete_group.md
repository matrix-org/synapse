# Delete a local group

This API lets a server admin delete a local group. Doing so will kick all
users out of the group so that their clients will correctly handle the group
being deleted.

The API is:

```
POST /_synapse/admin/v1/delete_group/<group_id>
```

To use it, you will need to authenticate by providing an `access_token` for a
server admin: see [README.rst](README.rst).
