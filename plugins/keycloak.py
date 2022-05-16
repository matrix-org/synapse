import jwt

from synapse.storage.databases.main.registration import TokenLookupResult


def get_external_id_by_access_token(token, secret):
    try:
        decoded = jwt.decode(token, secret, algorithms=["RS256"], audience="account")
        return decoded['sub']
    except (jwt.exceptions.PyJWTError, AttributeError):
        return None


async def get_user_by_external_id(external_id, db_pool):
    r = await db_pool.simple_select_one_onecol(
        table="user_external_ids",
        keyvalues={"external_id": external_id},
        retcol="user_id",
        allow_none=True,
        desc="get_user_by_external_id",
    )
    if r:
        return TokenLookupResult(user_id=r)
