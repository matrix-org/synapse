-- Add column open_id_tokens.userinfo_fields, which is used to persist the
-- additional user-requested open id userinfo fields according to MSC3356. The
-- requested fields (see synapse.api.constants.OpenIdUserInfoFields) are
-- encoded as comma separated list.
ALTER TABLE open_id_tokens ADD COLUMN userinfo_fields TEXT;
