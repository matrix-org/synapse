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
import os
import yaml
import sys
from textwrap import dedent


class ConfigError(Exception):
    pass


class Config(object):

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
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
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

    def generate_config(self, config_dir_path, server_name):
        default_config = "# vim:ft=yaml\n"

        default_config += "\n\n".join(dedent(conf) for conf in self.invoke_all(
            "default_config", config_dir_path, server_name
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
            help="Specify config file"
        )
        config_parser.add_argument(
            "--generate-config",
            action="store_true",
            help="Generate a config file for the server name"
        )
        config_parser.add_argument(
            "-H", "--server-name",
            help="The server name to generate a config file for"
        )
        config_args, remaining_args = config_parser.parse_known_args(argv)

        if config_args.generate_config:
            if not config_args.config_path:
                config_parser.error(
                    "Must supply a config file.\nA config file can be automatically"
                    " generated using \"--generate-config -h SERVER_NAME"
                    " -c CONFIG-FILE\""
                )

            config_dir_path = os.path.dirname(config_args.config_path[0])
            config_dir_path = os.path.abspath(config_dir_path)

            server_name = config_args.server_name
            if not server_name:
                print "Must specify a server_name to a generate config for."
                sys.exit(1)
            (config_path,) = config_args.config_path
            if not os.path.exists(config_dir_path):
                os.makedirs(config_dir_path)
            if os.path.exists(config_path):
                print "Config file %r already exists" % (config_path,)
                yaml_config = cls.read_config_file(config_path)
                yaml_name = yaml_config["server_name"]
                if server_name != yaml_name:
                    print (
                        "Config file %r has a different server_name: "
                        " %r != %r" % (config_path, server_name, yaml_name)
                    )
                    sys.exit(1)
                config_bytes, config = obj.generate_config(
                    config_dir_path, server_name
                )
                config.update(yaml_config)
                print "Generating any missing keys for %r" % (server_name,)
                obj.invoke_all("generate_files", config)
                sys.exit(0)
            with open(config_path, "wb") as config_file:
                config_bytes, config = obj.generate_config(
                    config_dir_path, server_name
                )
                obj.invoke_all("generate_files", config)
                config_file.write(config_bytes)
                print (
                    "A config file has been generated in %s for server name"
                    " '%s' with corresponding SSL keys and self-signed"
                    " certificates. Please review this file and customise it to"
                    " your needs."
                ) % (config_path, server_name)
            print (
                "If this server name is incorrect, you will need to regenerate"
                " the SSL certificates"
            )
            sys.exit(0)

        parser = argparse.ArgumentParser(
            parents=[config_parser],
            description=description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        obj.invoke_all("add_arguments", parser)
        args = parser.parse_args(remaining_args)

        if not config_args.config_path:
            config_parser.error(
                "Must supply a config file.\nA config file can be automatically"
                " generated using \"--generate-config -h SERVER_NAME"
                " -c CONFIG-FILE\""
            )

        config_dir_path = os.path.dirname(config_args.config_path[0])
        config_dir_path = os.path.abspath(config_dir_path)

        specified_config = {}
        for config_path in config_args.config_path:
            yaml_config = cls.read_config_file(config_path)
            specified_config.update(yaml_config)

        server_name = specified_config["server_name"]
        _, config = obj.generate_config(config_dir_path, server_name)
        config.pop("log_config")
        config.update(specified_config)

        obj.invoke_all("read_config", config)

        obj.invoke_all("read_arguments", args)

        return obj
