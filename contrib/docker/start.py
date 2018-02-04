#!/usr/local/bin/python

import jinja2
import os
import sys
import subprocess

convert = lambda src, dst: open(dst, "w").write(jinja2.Template(open(src).read()).render(**os.environ))
mode = sys.argv[1] if len(sys.argv) > 1 else None

if "SYNAPSE_SERVER_NAME" not in os.environ:
    print("Environment variable SYNAPSE_SERVER_NAME is mandatory, exiting.")
    sys.exit(2)

args = ["python", "-m", "synapse.app.homeserver",
        "--server-name", os.environ.get("SYNAPSE_SERVER_NAME"),
        "--report-stats", os.environ.get("SYNAPSE_REPORT_STATS", "no"),
        "--config-path", os.environ.get("SYNAPSE_CONFIG_PATH", "/compiled/homeserver.yaml")]

# Parse the configuration file
if not os.path.exists("/compiled"): os.mkdir("/compiled")
convert("/conf/homeserver.yaml", "/compiled/homeserver.yaml")
convert("/conf/log.config", "/compiled/%s.log.config" % os.environ.get("SYNAPSE_SERVER_NAME"))

# In generate mode, generate a configuration, missing keys, then exit
if mode == "generate":
    os.execv("/usr/local/bin/python", args + ["--generate-config"])
# In normal mode, generate missing keys if any, then run synapse
else:
    subprocess.check_output(args + ["--generate-keys"])
    os.execv("/usr/local/bin/python", args)
