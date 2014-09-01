from twisted.internet import reactor, ssl
from OpenSSL import SSL
from twisted.internet._sslverify import _OpenSSLECCurve, _defaultCurveName


class ServerContextFactory(ssl.ContextFactory):
    """Factory for PyOpenSSL SSL contexts that are used to handle incoming
    connections and to make connections to remote servers."""

    def __init__(self, config):
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self.configure_context(self._context, config)

    @staticmethod
    def configure_context(context, config):
        try:
            _ecCurve = _OpenSSLECCurve(_defaultCurveName)
            _ecCurve.addECKeyToContext(context)
        except:
            pass
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)
        context.use_certificate(config.tls_certificate)
        context.use_privatekey(config.tls_private_key)
        context.load_tmp_dh(config.tls_dh_params_path)
        context.set_cipher_list("!ADH:HIGH+kEDH:!AECDH:HIGH+kEECDH")

    def getContext(self):
        return self._context

