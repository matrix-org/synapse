from synapse.storage._base import SQLBaseStore


class OpenIdStore(SQLBaseStore):
    def insert_open_id_token(self, token, ts_valid_until_ms, user_id):
        return self.db.simple_insert(
            table="open_id_tokens",
            values={
                "token": token,
                "ts_valid_until_ms": ts_valid_until_ms,
                "user_id": user_id,
            },
            desc="insert_open_id_token",
        )

    def get_user_id_for_open_id_token(self, token, ts_now_ms):
        def get_user_id_for_token_txn(txn):
            sql = (
                "SELECT user_id FROM open_id_tokens"
                " WHERE token = ? AND ? <= ts_valid_until_ms"
            )

            txn.execute(sql, (token, ts_now_ms))

            rows = txn.fetchall()
            if not rows:
                return None
            else:
                return rows[0][0]

        return self.db.runInteraction(
            "get_user_id_for_token", get_user_id_for_token_txn
        )
