# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
from textwrap import dedent

from six import integer_types

import yaml


class ConfigError(Exception):
    pass


# We split these messages out to allow packages to override with package
# specific instructions.
MISSING_REPORT_STATS_CONFIG_INSTRUCTIONS = """\
Please opt in or out of reporting anonymized homeserver usage statistics, by
setting the `report_stats` key in your config file to either True or False.
"""

MISSING_REPORT_STATS_SPIEL = """\
We would really appreciate it if you could help our project out by reporting
anonymized usage statistics from your homeserver. Only very basic aggregate
data (e.g. number of users) will be reported, but it helps us to track the
growth of the Matrix community, and helps us to make Matrix a success, as well
as to convince other networks that they should peer with us.

Thank you.
"""

MISSING_SERVER_NAME = """\
Missing mandatory `server_name` config option.
"""


class Config(object):
    @staticmethod
    def parse_size(value):
        if isinstance(value, integer_types):
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
        if isinstance(value, integer_types):
            return value
        second = 1000
        minute = 60 * second
        hour = 60 * minute
        day = 24 * hour
        week = 7 * day
        year = 365 * day
        sizes = {"s": second, "m": minute, "h": hour, "d": day, "w": week, "y": year}
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
    def path_exists(cls, file_path):
        """Check if a file exists

        Unlike os.path.exists, this throws an exception if there is an error
        checking if the file exists (for example, if there is a perms error on
        the parent dir).

        Returns:
            bool: True if the file exists; False if not.
        """
        try:
            os.stat(file_path)
            return True
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise e
            return False

    @classmethod
    def check_file(cls, file_path, config_name):
        if file_path is None:
            raise ConfigError("Missing config for %s." % (config_name,))
        try:
            os.stat(file_path)
        except OSError as e:
            raise ConfigError(
                "Error accessing file '%s' (config for %s): %s"
                % (file_path, config_name, e.strerror)
            )
        return cls.abspath(file_path)

    @classmethod
    def ensure_directory(cls, dir_path):
        dir_path = cls.abspath(dir_path)
        try:
            os.makedirs(dir_path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
        if not os.path.isdir(dir_path):
            raise ConfigError("%s is not a directory" % (dir_path,))
        return dir_path

    @classmethod
    def read_file(cls, file_path, config_name):
        cls.check_file(file_path, config_name)
        with open(file_path) as file_stream:
            return file_stream.read()

    @staticmethod
    def read_config_file(file_path):
        with open(file_path) as file_stream:
            return yaml.safe_load(file_stream)

    def invoke_all(self, name, *args, **kargs):
        results = []
        for cls in type(self).mro():
            if name in cls.__dict__:
                results.append(getattr(cls, name)(self, *args, **kargs))
        return results

    def generate_config(
        self,
        config_dir_path,
        data_dir_path,
        server_name,
        generate_secrets=False,
        report_stats=None,
    ):
        """Build a default configuration file

        This is used both when the user explicitly asks us to generate a config file
        (eg with --generate_config), and before loading the config at runtime (to give
        a base which the config files override)

        Args:
            config_dir_path (str): The path where the config files are kept. Used to
                create filenames for things like the log config and the signing key.

            data_dir_path (str): The path where the data files are kept. Used to create
                filenames for things like the database and media store.

            server_name (str): The server name. Used to initialise the server_name
                config param, but also used in the names of some of the config files.

            generate_secrets (bool): True if we should generate new secrets for things
                like the macaroon_secret_key. If False, these parameters will be left
                unset.

            report_stats (bool|None): Initial setting for the report_stats setting.
                If None, report_stats will be left unset.

        Returns:
            str: the yaml config file
        """
        default_config = "\n\n".join(
            dedent(conf)
            for conf in self.invoke_all(
                "default_config",
                config_dir_path=config_dir_path,
                data_dir_path=data_dir_path,
                server_name=server_name,
                generate_secrets=generate_secrets,
                report_stats=report_stats,
            )
        )

        return default_config

    @classmethod
    def load_config(cls, description, argv):
        config_parser = argparse.ArgumentParser(description=description)
        config_parser.add_argument(
            "-c",
            "--config-path",
            action="append",
            metavar="CONFIG_FILE",
            help="Specify config file. Can be given multiple times and"
            " may specify directories containing *.yaml files.",
        )

        config_parser.add_argument(
            "--keys-directory",
            metavar="DIRECTORY",
            help="Where files such as certs and signing keys are stored when"
            " their location is given explicitly in the config."
            " Defaults to the directory containing the last config file",
        )

        obj = cls()

        obj.invoke_all("add_arguments", config_parser)

        config_args = config_parser.parse_args(argv)

        config_files = find_config_files(search_paths=config_args.config_path)

        obj.read_config_files(
            config_files, keys_directory=config_args.keys_directory, generate_keys=False
        )

        obj.invoke_all("read_arguments", config_args)

        return obj

    @classmethod
    def load_or_generate_config(cls, description, argv):
        config_parser = argparse.ArgumentParser(add_help=False)
        config_parser.add_argument(
            "-c",
            "--config-path",
            action="append",
            metavar="CONFIG_FILE",
            help="Specify config file. Can be given multiple times and"
            " may specify directories containing *.yaml files.",
        )
        config_parser.add_argument(
            "--generate-config",
            action="store_true",
            help="Generate a config file for the server name",
        )
        config_parser.add_argument(
            "--report-stats",
            action="store",
            help="Whether the generated config reports anonymized usage statistics",
            choices=["yes", "no"],
        )
        config_parser.add_argument(
            "--generate-keys",
            action="store_true",
            help="Generate any missing key files then exit",
        )
        config_parser.add_argument(
            "--keys-directory",
            metavar="DIRECTORY",
            help="Used with 'generate-*' options to specify where files such as"
            " signing keys should be stored, unless explicitly"
            " specified in the config.",
        )
        config_parser.add_argument(
            "-H", "--server-name", help="The server name to generate a config file for"
        )
        config_args, remaining_args = config_parser.parse_known_args(argv)

        config_files = find_config_files(search_paths=config_args.config_path)

        generate_keys = config_args.generate_keys

        obj = cls()

        if config_args.generate_config:
            if config_args.report_stats is None:
                config_parser.error(
                    "Please specify either --report-stats=yes or --report-stats=no\n\n"
                    + MISSING_REPORT_STATS_SPIEL
                )
            if not config_files:
                config_parser.error(
                    "Must supply a config file.\nA config file can be automatically"
                    " generated using \"--generate-config -H SERVER_NAME"
                    " -c CONFIG-FILE\""
                )
            (config_path,) = config_files
            if not cls.path_exists(config_path):
                if config_args.keys_directory:
                    config_dir_path = config_args.keys_directory
                else:
                    config_dir_path = os.path.dirname(config_path)
                config_dir_path = os.path.abspath(config_dir_path)

                server_name = config_args.server_name
                if not server_name:
                    raise ConfigError(
                        "Must specify a server_name to a generate config for."
                        " Pass -H server.name."
                    )

                config_str = obj.generate_config(
                    config_dir_path=config_dir_path,
                    data_dir_path=os.getcwd(),
                    server_name=server_name,
                    report_stats=(config_args.report_stats == "yes"),
                    generate_secrets=True,
                )

                if not cls.path_exists(config_dir_path):
                    os.makedirs(config_dir_path)
                with open(config_path, "w") as config_file:
                    config_file.write(
                        "# vim:ft=yaml\n\n"
                    )
                    config_file.write(config_str)

                config = yaml.safe_load(config_str)
                obj.invoke_all("generate_files", config)

                print(
                    (
                        "A config file has been generated in %r for server name"
                        " %r. Please review this file and customise it"
                        " to your needs."
                    )
                    % (config_path, server_name)
                )
                return
            else:
                print(
                    (
                        "Config file %r already exists. Generating any missing key"
                        " files."
                    )
                    % (config_path,)
                )
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

        obj.read_config_files(
            config_files,
            keys_directory=config_args.keys_directory,
            generate_keys=generate_keys,
        )

        if generate_keys:
            return None

        obj.invoke_all("read_arguments", args)

        return obj

    def read_config_files(self, config_files, keys_directory=None, generate_keys=False):
        if not keys_directory:
            keys_directory = os.path.dirname(config_files[-1])

        self.config_dir_path = os.path.abspath(keys_directory)

        specified_config = {}
        for config_file in config_files:
            yaml_config = self.read_config_file(config_file)
            specified_config.update(yaml_config)

        if "server_name" not in specified_config:
            raise ConfigError(MISSING_SERVER_NAME)

        server_name = specified_config["server_name"]
        config_string = self.generate_config(
            config_dir_path=self.config_dir_path,
            data_dir_path=os.getcwd(),
            server_name=server_name,
            generate_secrets=False,
        )
        config = yaml.safe_load(config_string)
        config.pop("log_config")
        config.update(specified_config)

        if "report_stats" not in config:
            raise ConfigError(
                MISSING_REPORT_STATS_CONFIG_INSTRUCTIONS
                + "\n"
                + MISSING_REPORT_STATS_SPIEL
            )

        if generate_keys:
            self.invoke_all("generate_files", config)
            return

        self.parse_config_dict(config)

    def parse_config_dict(self, config_dict):
        self.invoke_all("read_config", config_dict)


def find_config_files(search_paths):
    """Finds config files using a list of search paths. If a path is a file
    then that file path is added to the list. If a search path is a directory
    then all the "*.yaml" files in that directory are added to the list in
    sorted order.

    Args:
        search_paths(list(str)): A list of paths to search.

    Returns:
        list(str): A list of file paths.
    """

    config_files = []
    if search_paths:
        for config_path in search_paths:
            if os.path.isdir(config_path):
                # We accept specifying directories as config paths, we search
                # inside that directory for all files matching *.yaml, and then
                # we apply them in *sorted* order.
                files = []
                for entry in os.listdir(config_path):
                    entry_path = os.path.join(config_path, entry)
                    if not os.path.isfile(entry_path):
                        err = "Found subdirectory in config directory: %r. IGNORING."
                        print(err % (entry_path,))
                        continue

                    if not entry.endswith(".yaml"):
                        err = (
                            "Found file in config directory that does not end in "
                            "'.yaml': %r. IGNORING."
                        )
                        print(err % (entry_path,))
                        continue

                    files.append(entry_path)

                config_files.extend(sorted(files))
            else:
                config_files.append(config_path)
    return config_files
