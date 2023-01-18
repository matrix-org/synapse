import logging
from typing import Any

from synapse.types import JsonDict
from ._base import Config

logger = logging.Logger(__name__)


class LoginConfig(Config):
    section = "login"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        #   amax_login:
        #       chain_id: 208dacab3cd2e181c86841613cf05d9c60786c677e4ce86b266d0a58884968f7
        #       signature_url: http://storage.ambt.art/api/v1/signature_verify
        amax_login = config.get("amax_login", None)

        default_chain_id = "208dacab3cd2e181c86841613cf05d9c60786c677e4ce86b266d0a58884968f7"
        default_signature_url = "http://storage.ambt.art/api/v1/signature_verify"
        if amax_login:
            self.chain_id = amax_login.get("chain_id", default_chain_id)
            self.signature_url = amax_login.get("signature_url", default_signature_url)
        else:
            self.chain_id = default_chain_id
            self.signature_url = default_signature_url

        logger.info("amax_login chain_id: %s", self.chain_id)
        logger.info("amax_login signature_url: %s", self.signature_url)
