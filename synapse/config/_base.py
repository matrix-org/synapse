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
import sys
import os
import yaml


class ConfigError(Exception):
    pass


class Config(object):
    def __init__(self, args):
        pass

    @staticmethod
    def parse_size(string):
        sizes = {"K": 1024, "M": 1024 * 1024}
        size = 1
        suffix = string[-1]
        if suffix in sizes:
            string = string[:-1]
            size = sizes[suffix]
        return int(string) * size

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

    @classmethod
    def add_arguments(cls, parser):
        pass

    @classmethod
    def generate_config(cls, args, config_dir_path):
        pass

    @classmethod
    def load_config(cls, description, argv, generate_section=None):
        config_parser = argparse.ArgumentParser(add_help=False)
        config_parser.add_argument(
            "-c", "--config-path",
            metavar="CONFIG_FILE",
            help="Specify config file"
        )
        config_parser.add_argument(
            "--generate-config",
            action="store_true",
            help="Generate config file"
        )
        config_args, remaining_args = config_parser.parse_known_args(argv)

        if config_args.generate_config:
            if not config_args.config_path:
                config_parser.error(
                    "Must specify where to generate the config file"
                )
            config_dir_path = os.path.dirname(config_args.config_path)
            if os.path.exists(config_args.config_path):
                defaults = cls.read_config_file(config_args.config_path)
            else:
                defaults = {}
        else:
            if config_args.config_path:
                defaults = cls.read_config_file(config_args.config_path)
            else:
                defaults = {}

        parser = argparse.ArgumentParser(
            parents=[config_parser],
            description=description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        cls.add_arguments(parser)
        parser.set_defaults(**defaults)

        args = parser.parse_args(remaining_args)

        if config_args.generate_config:
            config_dir_path = os.path.dirname(config_args.config_path)
            config_dir_path = os.path.abspath(config_dir_path)
            if not os.path.exists(config_dir_path):
                os.makedirs(config_dir_path)
            cls.generate_config(args, config_dir_path)
            config = {}
            for key, value in vars(args).items():
                if (key not in set(["config_path", "generate_config"])
                        and value is not None):
                    config[key] = value
            with open(config_args.config_path, "w") as config_file:
                # TODO(paul) it would be lovely if we wrote out vim- and emacs-
                #   style mode markers into the file, to hint to people that
                #   this is a YAML file.
                yaml.dump(config, config_file, default_flow_style=False)
            print (
                "A config file has been generated in %s for server name"
                " '%s' with corresponding SSL keys and self-signed"
                " certificates. Please review this file and customise it to"
                " your needs."
            ) % (
                config_args.config_path, config['server_name']
            )
            print (
                "If this server name is incorrect, you will need to regenerate"
                " the SSL certificates"
            )
            sys.exit(0)

        return cls(args)
