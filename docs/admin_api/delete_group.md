# Delete a local group

This API lets a server admin delete a local group. Doing so will kick all
users out of the group so that their clients will correctly handle the group
being deleted.


The API is:

```
POST /_synapse/admin/v1/delete_group/<group_id>
```

including an `access_token` of a server admin.
