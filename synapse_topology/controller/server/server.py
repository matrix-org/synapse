from canonicaljson import json
from klein import Klein
from synapse_topology import model

from .schemas import BASE_CONFIG_SCHEMA, SERVERNAME_SCHEMA
from .utils import validate_schema

app = Klein()
from . import error_handlers


@app.route("/setup", methods=["GET"])
def get_config_setup(request):
    return json.dumps({model.constants.CONFIG_LOCK: model.config_in_use()})


@app.route("/servername", methods=["GET"])
def get_server_name(request):
    return model.get_server_name()


@app.route("/servername", methods=["POST"])
@validate_schema(SERVERNAME_SCHEMA)
def set_server_name(request, body):
    model.generate_base_config(**body)


@app.route("/secretkey", methods=["GET"])
def get_secret_key(request):
    return model.get_secret_key()


@app.route("/config", methods=["GET"])
def get_config(request):
    return str(model.get_config())


@app.route("/config", methods=["POST"])
@validate_schema(BASE_CONFIG_SCHEMA)
def set_config(request, body):
    model.set_config(body)


with app.subroute("/config") as app:
    for config in model.constants.CONFIGS:

        @app.route("/config/{}".format(config), methods=["GET"])
        def get_sub_config(request, sub_config):
            return model.get_config(sub_config=config)

        @app.route("/config/{}".format(config), methods=["POST"])
        def set_sub_config(request, sub_config):
            model.set_config(json.loads(request.content.read()), sub_config=config)
