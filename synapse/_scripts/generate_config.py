#!/usr/bin/env python3

import argparse
import shutil
import sys

from synapse.config.homeserver import HomeServerConfig

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config-dir",
        default="CONFDIR",
        help="The path where the config files are kept. Used to create filenames for "
        "things like the log config and the signing key. Default: %(default)s",
    )

    parser.add_argument(
        "--data-dir",
        default="DATADIR",
        help="The path where the data files are kept. Used to create filenames for "
        "things like the database and media store. Default: %(default)s",
    )

    parser.add_argument(
        "--server-name",
        default="SERVERNAME",
        help="The server name. Used to initialise the server_name config param, but also "
        "used in the names of some of the config files. Default: %(default)s",
    )

    parser.add_argument(
        "--report-stats",
        action="store",
        help="Whether the generated config reports anonymized usage statistics",
        choices=["yes", "no"],
    )

    parser.add_argument(
        "--generate-secrets",
        action="store_true",
        help="Enable generation of new secrets for things like the macaroon_secret_key."
        "By default, these parameters will be left unset.",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="File to write the configuration to. Default: stdout",
    )

    parser.add_argument(
        "--header-file",
        type=argparse.FileType("r"),
        help="File from which to read a header, which will be printed before the "
        "generated config.",
    )

    args = parser.parse_args()

    report_stats = args.report_stats
    if report_stats is not None:
        report_stats = report_stats == "yes"

    conf = HomeServerConfig().generate_config(
        config_dir_path=args.config_dir,
        data_dir_path=args.data_dir,
        server_name=args.server_name,
        generate_secrets=args.generate_secrets,
        report_stats=report_stats,
    )

    if args.header_file:
        shutil.copyfileobj(args.header_file, args.output_file)

    args.output_file.write(conf)
