#!/usr/local/bin/python

import jinja2
import os
import sys
import subprocess
import glob

convert = lambda src, dst, environ: open(dst, "w").write(jinja2.Template(open(src).read()).render(**environ))
mode = sys.argv[1] if len(sys.argv) > 1 else None
environ = os.environ.copy()

# Check mandatory parameters and build the base start arguments
if "SYNAPSE_SERVER_NAME" not in environ:
    print("Environment variable SYNAPSE_SERVER_NAME is mandatory, exiting.")
    sys.exit(2)

permissions = "{}:{}".format(environ.get("UID", 991), environ.get("GID", 991))
args = ["python", "-m", "synapse.app.homeserver",
        "--server-name", environ.get("SYNAPSE_SERVER_NAME"),
        "--report-stats", environ.get("SYNAPSE_REPORT_STATS", "no"),
        "--config-path", environ.get("SYNAPSE_CONFIG_PATH", "/compiled/homeserver.yaml")]

# Generate any missing shared secret
for secret in ("SYNAPSE_REGISTRATION_SHARED_SECRET", "SYNAPSE_MACAROON_SECRET_KEY"):
    if secret not in environ:
        print("Generating a random secret for {}".format(secret))
        environ[secret] = os.urandom(32).encode("hex")

# Load appservices configurations
environ["SYNAPSE_APPSERVICES"] = glob.glob("/data/appservices/*.yaml")

# In generate mode, generate a configuration, missing keys, then exit
if mode == "generate":
    os.execv("/usr/local/bin/python", args + ["--generate-config"])

# In normal mode, generate missing keys if any, then run synapse
else:
    # Parse the configuration file
    if "SYNAPSE_CONFIG_PATH" not in environ:
        if not os.path.exists("/compiled"): os.mkdir("/compiled")
        convert("/conf/homeserver.yaml", "/compiled/homeserver.yaml", environ)
        convert("/conf/log.config", "/compiled/%s.log.config" % environ.get("SYNAPSE_SERVER_NAME"), environ)
    # Generate missing keys and start synapse
    subprocess.check_output(args + ["--generate-keys"])
    subprocess.check_output(["chown", "-R", permissions, "/data"])
    os.execv("/sbin/su-exec", ["su-exec", permissions] + args)
