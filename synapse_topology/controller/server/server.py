from os.path import abspath, dirname, join

from canonicaljson import json
from synapse_topology import model

from twisted.web.static import File

from .utils import port_checker

from . import error_handlers
from .schemas import (
    BASE_CONFIG_SCHEMA,
    SERVERNAME_SCHEMA,
    CERT_PATHS_SCHEMA,
    CERTS_SCHEMA,
    PORTS_SCHEMA,
)
from .utils import validate_schema

from . import app


@app.route("/topology_webui/", branch=True)
def server_webui(request):
    client_path = abspath(join(dirname(abspath(__file__)), "../../view/webui"))
    print(client_path)
    return File(client_path)


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
    return json.dumps({"secret_key": model.get_secret_key()})


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


@app.route("/testcertpaths", methods=["POST"])
@validate_schema(CERT_PATHS_SCHEMA)
def test_cert_paths(request, body):
    result = {}
    for path in ["cert_path", "cert_key_path"]:
        try:
            with open(body[path], "r"):
                result[path + "_invalid"] = False
        except:
            result[path + "_invalid"] = True
    return json.dumps(result)


@app.route("/certs", methods=["POST"])
@validate_schema(CERTS_SCHEMA)
def upload_certs(request, body):
    model.add_certs(**body)


@app.route("/ports", methods=["POST"])
@validate_schema(PORTS_SCHEMA)
def check_ports(request, body):
    results = []
    for port in body["ports"]:
        results.append(port_checker(port))
    return json.dumps({"ports": results})

