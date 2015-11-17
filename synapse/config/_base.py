# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import errno
import os
import yaml
import sys
from textwrap import dedent


class ConfigError(Exception):
    pass


class Config(object):

    stats_reporting_begging_spiel = (
        "We would really appreciate it if you could help our project out by"
        " reporting anonymized usage statistics from your homeserver. Only very"
        " basic aggregate data (e.g. number of users) will be reported, but it"
        " helps us to track the growth of the Matrix community, and helps us to"
        " make Matrix a success, as well as to convince other networks that they"
        " should peer with us."
        "\nThank you."
    )

    @staticmethod
    def parse_size(value):
        if isinstance(value, int) or isinstance(value, long):
            return value
        sizes = {"K": 1024, "M": 1024 * 1024}
        size = 1
        suffix = value[-1]
        if suffix in sizes:
            value = value[:-1]
            size = sizes[suffix]
        return int(value) * size

    @staticmethod
    def parse_duration(value):
        if isinstance(value, int) or isinstance(value, long):
            return value
        second = 1000
        hour = 60 * 60 * second
        day = 24 * hour
        week = 7 * day
        year = 365 * day
        sizes = {"s": second, "h": hour, "d": day, "w": week, "y": year}
        size = 1
        suffix = value[-1]
        if suffix in sizes:
            value = value[:-1]
            size = sizes[suffix]
        return int(value) * size

    @staticmethod
    def abspath(file_path):
        return os.path.abspath(file_path) if file_path else file_path

    @classmethod
    def check_file(cls, file_path, config_name):
        if file_path is None:
            raise ConfigError(
                "Missing config for %s."
                " You must specify a path for the config file. You can "
                "do this with the -c or --config-path option. "
                "Adding --generate-config along with --server-name "
                "<server name> will generate a config file at the given path."
                % (config_name,)
            )
        if not os.path.exists(file_path):
            raise ConfigError(
                "File %s config for %s doesn't exist."
                " Try running again with --generate-config"
                % (file_path, config_name,)
            )
        return cls.abspath(file_path)

    @classmethod
    def ensure_directory(cls, dir_path):
        dir_path = cls.abspath(dir_path)
        try:
            os.makedirs(dir_path)
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
        if not os.path.isdir(dir_path):
            raise ConfigError(
                "%s is not a directory" % (dir_path,)
            )
        return dir_path

    @classmethod
    def read_file(cls, file_path, config_name):
        cls.check_file(file_path, config_name)
        with open(file_path) as file_stream:
            return file_stream.read()

    @staticmethod
    def default_path(name):
        return os.path.abspath(os.path.join(os.path.curdir, name))

    @staticmethod
    def read_config_file(file_path):
        with open(file_path) as file_stream:
            return yaml.load(file_stream)

    def invoke_all(self, name, *args, **kargs):
        results = []
        for cls in type(self).mro():
            if name in cls.__dict__:
                results.append(getattr(cls, name)(self, *args, **kargs))
        return results

    def generate_config(self, config_dir_path, server_name, report_stats=None):
        default_config = "# vim:ft=yaml\n"

        default_config += "\n\n".join(dedent(conf) for conf in self.invoke_all(
            "default_config",
            config_dir_path=config_dir_path,
            server_name=server_name,
            report_stats=report_stats,
        ))

        config = yaml.load(default_config)

        return default_config, config

    @classmethod
    def load_config(cls, description, argv, generate_section=None):
        obj = cls()

        config_parser = argparse.ArgumentParser(add_help=False)
        config_parser.add_argument(
            "-c", "--config-path",
            action="append",
            metavar="CONFIG_FILE",
            help="Specify config file. Can be given multiple times and"
                 " may specify directories containing *.yaml files."
        )
        config_parser.add_argument(
            "--generate-config",
            action="store_true",
            help="Generate a config file for the server name"
        )
        config_parser.add_argument(
            "--report-stats",
            action="store",
            help="Stuff",
            choices=["yes", "no"]
        )
        config_parser.add_argument(
            "--generate-keys",
            action="store_true",
            help="Generate any missing key files then exit"
        )
        config_parser.add_argument(
            "--keys-directory",
            metavar="DIRECTORY",
            help="Used with 'generate-*' options to specify where files such as"
                 " certs and signing keys should be stored in, unless explicitly"
                 " specified in the config."
        )
        config_parser.add_argument(
            "-H", "--server-name",
            help="The server name to generate a config file for"
        )
        config_args, remaining_args = config_parser.parse_known_args(argv)

        generate_keys = config_args.generate_keys

        config_files = []
        if config_args.config_path:
            for config_path in config_args.config_path:
                if os.path.isdir(config_path):
                    # We accept specifying directories as config paths, we search
                    # inside that directory for all files matching *.yaml, and then
                    # we apply them in *sorted* order.
                    files = []
                    for entry in os.listdir(config_path):
                        entry_path = os.path.join(config_path, entry)
                        if not os.path.isfile(entry_path):
                            print (
                                "Found subdirectory in config directory: %r. IGNORING."
                            ) % (entry_path, )
                            continue

                        if not entry.endswith(".yaml"):
                            print (
                                "Found file in config directory that does not"
                                " end in '.yaml': %r. IGNORING."
                            ) % (entry_path, )
                            continue

                        files.append(entry_path)

                    config_files.extend(sorted(files))
                else:
                    config_files.append(config_path)

        if config_args.generate_config:
            if config_args.report_stats is None:
                config_parser.error(
                    "Please specify either --report-stats=yes or --report-stats=no\n\n" +
                    cls.stats_reporting_begging_spiel
                )
            if not config_files:
                config_parser.error(
                    "Must supply a config file.\nA config file can be automatically"
                    " generated using \"--generate-config -H SERVER_NAME"
                    " -c CONFIG-FILE\""
                )
            (config_path,) = config_files
            if not os.path.exists(config_path):
                if config_args.keys_directory:
                    config_dir_path = config_args.keys_directory
                else:
                    config_dir_path = os.path.dirname(config_path)
                config_dir_path = os.path.abspath(config_dir_path)

                server_name = config_args.server_name
                if not server_name:
                    print "Must specify a server_name to a generate config for."
                    sys.exit(1)
                if not os.path.exists(config_dir_path):
                    os.makedirs(config_dir_path)
                with open(config_path, "wb") as config_file:
                    config_bytes, config = obj.generate_config(
                        config_dir_path=config_dir_path,
                        server_name=server_name,
                        report_stats=(config_args.report_stats == "yes"),
                    )
                    obj.invoke_all("generate_files", config)
                    config_file.write(config_bytes)
                print (
                    "A config file has been generated in %r for server name"
                    " %r with corresponding SSL keys and self-signed"
                    " certificates. Please review this file and customise it"
                    " to your needs."
                ) % (config_path, server_name)
                print (
                    "If this server name is incorrect, you will need to"
                    " regenerate the SSL certificates"
                )
                sys.exit(0)
            else:
                print (
                    "Config file %r already exists. Generating any missing key"
                    " files."
                ) % (config_path,)
                generate_keys = True

        parser = argparse.ArgumentParser(
            parents=[config_parser],
            description=description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        obj.invoke_all("add_arguments", parser)
        args = parser.parse_args(remaining_args)

        if not config_files:
            config_parser.error(
                "Must supply a config file.\nA config file can be automatically"
                " generated using \"--generate-config -H SERVER_NAME"
                " -c CONFIG-FILE\""
            )

        if config_args.keys_directory:
            config_dir_path = config_args.keys_directory
        else:
            config_dir_path = os.path.dirname(config_args.config_path[-1])
        config_dir_path = os.path.abspath(config_dir_path)

        specified_config = {}
        for config_file in config_files:
            yaml_config = cls.read_config_file(config_file)
            specified_config.update(yaml_config)

        server_name = specified_config["server_name"]
        _, config = obj.generate_config(
            config_dir_path=config_dir_path,
            server_name=server_name
        )
        config.pop("log_config")
        config.update(specified_config)
        if "report_stats" not in config:
            sys.stderr.write(
                "Please opt in or out of reporting anonymized homeserver usage "
                "statistics, by setting the report_stats key in your config file "
                " ( " + config_path + " ) " +
                "to either True or False.\n\n" +
                Config.stats_reporting_begging_spiel + "\n")
            sys.exit(1)

        if generate_keys:
            obj.invoke_all("generate_files", config)
            sys.exit(0)

        obj.invoke_all("read_config", config)

        obj.invoke_all("read_arguments", args)

        return obj
