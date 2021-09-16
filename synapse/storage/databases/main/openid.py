from typing import Optional

from synapse.storage._base import SQLBaseStore


class OpenIdStore(SQLBaseStore):
    async def insert_open_id_token(
        self,
        token: str,
        ts_valid_until_ms: int,
        user_id: str,
        userinfo_fields: Optional[list],
    ) -> None:
        await self.db_pool.simple_insert(
            table="open_id_tokens",
            values={
                "token": token,
                "ts_valid_until_ms": ts_valid_until_ms,
                "user_id": user_id,
                "userinfo_fields": (
                    ",".join(set(userinfo_fields)) if userinfo_fields else None
                ),
            },
            desc="insert_open_id_token",
        )

    async def get_user_id_and_userinfo_fields_for_open_id_token(
        self, token: str, ts_now_ms: int
    ) -> Optional[str]:
        def get_user_id_for_token_txn(txn):
            sql = (
                "SELECT user_id, userinfo_fields FROM open_id_tokens"
                " WHERE token = ? AND ? <= ts_valid_until_ms"
            )

            txn.execute(sql, (token, ts_now_ms))

            rows = txn.fetchall()
            if not rows:
                return None
            else:
                userinfo_fields = None
                userinfo_fields_str = rows[0][1]
                if userinfo_fields_str:
                    userinfo_fields = userinfo_fields_str.split(",")

                return rows[0][0], userinfo_fields

        return await self.db_pool.runInteraction(
            "get_user_id_for_token", get_user_id_for_token_txn
        )
