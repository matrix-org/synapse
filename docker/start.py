#!/usr/local/bin/python

import codecs
import glob
import os
import subprocess
import sys

import jinja2


# Utility functions
def log(txt):
    print(txt, file=sys.stderr)


def error(txt):
    log(txt)
    sys.exit(2)


def convert(src, dst, environ):
    """Generate a file from a template

    Args:
        src (str): path to input file
        dst (str): path to file to write
        environ (dict): environment dictionary, for replacement mappings.
    """
    with open(src) as infile:
        template = infile.read()
    rendered = jinja2.Template(template).render(**environ)
    with open(dst, "w") as outfile:
        outfile.write(rendered)


def generate_config_from_template(environ, ownership):
    """Generate a homeserver.yaml from environment variables

    Args:
        environ (dict): environment dictionary
        ownership (str): "<user>:<group>" string which will be used to set
            ownership of the generated configs

    Returns:
        path to generated config file
    """
    for v in ("SYNAPSE_SERVER_NAME", "SYNAPSE_REPORT_STATS"):
        if v not in environ:
            error(
                "Environment variable '%s' is mandatory when generating a config "
                "file on-the-fly." % (v,)
            )

    # populate some params from data files (if they exist, else create new ones)
    environ = environ.copy()
    secrets = {
        "registration": "SYNAPSE_REGISTRATION_SHARED_SECRET",
        "macaroon": "SYNAPSE_MACAROON_SECRET_KEY",
    }

    for name, secret in secrets.items():
        if secret not in environ:
            filename = "/data/%s.%s.key" % (environ["SYNAPSE_SERVER_NAME"], name)

            # if the file already exists, load in the existing value; otherwise,
            # generate a new secret and write it to a file

            if os.path.exists(filename):
                log("Reading %s from %s" % (secret, filename))
                with open(filename) as handle:
                    value = handle.read()
            else:
                log("Generating a random secret for {}".format(secret))
                value = codecs.encode(os.urandom(32), "hex").decode()
                with open(filename, "w") as handle:
                    handle.write(value)
            environ[secret] = value

    environ["SYNAPSE_APPSERVICES"] = glob.glob("/data/appservices/*.yaml")
    if not os.path.exists("/compiled"):
        os.mkdir("/compiled")

    config_path = "/compiled/homeserver.yaml"

    # Convert SYNAPSE_NO_TLS to boolean if exists
    if "SYNAPSE_NO_TLS" in environ:
        tlsanswerstring = str.lower(environ["SYNAPSE_NO_TLS"])
        if tlsanswerstring in ("true", "on", "1", "yes"):
            environ["SYNAPSE_NO_TLS"] = True
        else:
            if tlsanswerstring in ("false", "off", "0", "no"):
                environ["SYNAPSE_NO_TLS"] = False
            else:
                error(
                    'Environment variable "SYNAPSE_NO_TLS" found but value "'
                    + tlsanswerstring
                    + '" unrecognized; exiting.'
                )

    convert("/conf/homeserver.yaml", config_path, environ)
    convert("/conf/log.config", "/compiled/log.config", environ)
    subprocess.check_output(["chown", "-R", ownership, "/data"])

    # Hopefully we already have a signing key, but generate one if not.
    subprocess.check_output(
        [
            "su-exec",
            ownership,
            "python",
            "-m",
            "synapse.app.homeserver",
            "--config-path",
            config_path,
            # tell synapse to put generated keys in /data rather than /compiled
            "--keys-directory",
            "/data",
            "--generate-keys",
        ]
    )

    return config_path


def run_generate_config(environ, ownership):
    """Run synapse with a --generate-config param to generate a template config file

    Args:
        environ (dict): env var dict
        ownership (str): "userid:groupid" arg for chmod

    Never returns.
    """
    for v in ("SYNAPSE_SERVER_NAME", "SYNAPSE_REPORT_STATS", "SYNAPSE_CONFIG_PATH"):
        if v not in environ:
            error("Environment variable '%s' is mandatory in `generate` mode." % (v,))

    data_dir = environ.get("SYNAPSE_DATA_DIR", "/data")

    # make sure that synapse has perms to write to the data dir.
    subprocess.check_output(["chown", ownership, data_dir])

    args = [
        "python",
        "-m",
        "synapse.app.homeserver",
        "--server-name",
        environ["SYNAPSE_SERVER_NAME"],
        "--report-stats",
        environ["SYNAPSE_REPORT_STATS"],
        "--config-path",
        environ["SYNAPSE_CONFIG_PATH"],
        "--data-directory",
        data_dir,
        "--generate-config",
    ]
    # log("running %s" % (args, ))
    os.execv("/usr/local/bin/python", args)


def main(args, environ):
    mode = args[1] if len(args) > 1 else None
    ownership = "{}:{}".format(environ.get("UID", 991), environ.get("GID", 991))

    # In generate mode, generate a configuration and missing keys, then exit
    if mode == "generate":
        return run_generate_config(environ, ownership)

    # In normal mode, generate missing keys if any, then run synapse
    if "SYNAPSE_CONFIG_PATH" in environ:
        config_path = environ["SYNAPSE_CONFIG_PATH"]
    else:
        config_path = generate_config_from_template(environ, ownership)

    args = [
        "su-exec",
        ownership,
        "python",
        "-m",
        "synapse.app.homeserver",
        "--config-path",
        config_path,
    ]
    os.execv("/sbin/su-exec", args)


if __name__ == "__main__":
    main(sys.argv, os.environ)
