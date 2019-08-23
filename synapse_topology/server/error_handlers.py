from jsonschema import ValidationError
from simplejson.errors import JSONDecodeError
from synapse_topology.model.errors import (
    BasConfigInUseError,
    ConfigNotFoundError,
    ServernameNotSetError,
)

from . import app


@app.handle_errors(ValidationError)
def validation_error(request, failure):
    request.setResponseCode(400)
    print("Invalid post schema {}".format(failure.getErrorMessage()))
    return "Invalid post schema {}".format(failure.getErrorMessage())


@app.handle_errors(JSONDecodeError)
def json_decode_error(request, failure):
    request.setResponseCode(400)
    return "Invalid post json"


@app.handle_errors(ServernameNotSetError)
def not_initialised(request, failure):
    request.setResponseCode(500)
    return "Config file not setup, please initialise it using the /servername endpoint"


@app.handle_errors(ConfigNotFoundError)
def config_not_found(request, failure):
    request.setResponseCode(404)
    return "The config does not exist"


@app.handle_errors(BasConfigInUseError)
def base_config_in_use(request, failure):
    request.setResponseCode(409)
    return "Sever name and keys already configured"


@app.handle_errors(Exception)
def handle_generic_error(request, failure):
    print(failure)
    request.setResponseCode(500)
    return "Internal server error\n{}".format(failure)
