from jsonschema import ValidationError
from simplejson.errors import JSONDecodeError
from synapse_topology.model.errors import (
    BaseConfigInUseError,
    ConfigNotFoundError,
    ServernameNotSetError,
)

from .server import Server


class ErrorHandledServer(Server):
    app = Server.app

    @app.handle_errors(ValidationError)
    def validation_error(self, request, failure):
        request.setResponseCode(400)
        print("Invalid post schema {}".format(failure.getErrorMessage()))
        return "Invalid post schema {}".format(failure.getErrorMessage())

    @app.handle_errors(JSONDecodeError)
    def json_decode_error(self, request, failure):
        request.setResponseCode(400)
        return "Invalid post json"

    @app.handle_errors(ServernameNotSetError)
    def not_initialised(self, request, failure):
        request.setResponseCode(500)
        return (
            "Config file not setup, please initialise it using the /servername endpoint"
        )

    @app.handle_errors(ConfigNotFoundError)
    def config_not_found(self, request, failure):
        request.setResponseCode(404)
        return "The config does not exist"

    @app.handle_errors(BaseConfigInUseError)
    def base_config_in_use(self, request, failure):
        request.setResponseCode(409)
        return "Sever name and keys already configured"

    @app.handle_errors(Exception)
    def handle_generic_error(self, request, failure):
        print(failure)
        request.setResponseCode(500)
        return "Internal server error\n{}".format(failure)
