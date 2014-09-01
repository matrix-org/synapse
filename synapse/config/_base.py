# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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


import ConfigParser as configparser
import argparse
import sys
import os
import yaml


class Config(object):
    def __init__(self, args):
        pass

    @staticmethod
    def abspath(file_path):
        return os.path.abspath(file_path) if file_path else file_path

    @staticmethod
    def read_file(file_path):
        with open(file_path) as file_stream:
            return file_stream.read()

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
            cls.generate_config(args, config_dir_path)
            config = {}
            for key, value in vars(args).items():
                if (key not in set(["config_path", "generate_config"])
                    and value is not None):
                    config[key] = value
            with open(config_args.config_path, "w") as config_file:
                yaml.dump(config, config_file, default_flow_style=False)
            sys.exit(0)

        return cls(args)



