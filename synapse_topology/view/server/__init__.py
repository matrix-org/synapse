from os.path import abspath, dirname, join

from klein import Klein

from twisted.web.static import File

app = Klein()


@app.route("/topology_webui/", branch=True)
def server_webui(request):
    client_path = abspath(join(dirname(abspath(__file__)), "../webui"))
    print(client_path)
    return File(client_path)
