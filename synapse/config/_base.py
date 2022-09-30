# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import logging
import os
import re
from collections import OrderedDict
from enum import Enum, auto
from hashlib import sha256
from textwrap import dedent
from typing import (
    Any,
    ClassVar,
    Collection,
    Dict,
    Iterable,
    Iterator,
    List,
    MutableMapping,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import attr
import jinja2
import pkg_resources
import yaml

from synapse.util.templates import _create_mxc_to_http_filter, _format_ts_filter

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Represents a problem parsing the configuration

    Args:
        msg:  A textual description of the error.
        path: Where appropriate, an indication of where in the configuration
           the problem lies.
    """

    def __init__(self, msg: str, path: Optional[Iterable[str]] = None):
        self.msg = msg
        self.path = path


def format_config_error(e: ConfigError) -> Iterator[str]:
    """
    Formats a config error neatly

    The idea is to format the immediate error, plus the "causes" of those errors,
    hopefully in a way that makes sense to the user. For example:

        Error in configuration at 'oidc_config.user_mapping_provider.config.display_name_template':
          Failed to parse config for module 'JinjaOidcMappingProvider':
            invalid jinja template:
              unexpected end of template, expected 'end of print statement'.

    Args:
        e: the error to be formatted

    Returns: An iterator which yields string fragments to be formatted
    """
    yield "Error in configuration"

    if e.path:
        yield " at '%s'" % (".".join(e.path),)

    yield ":\n  %s" % (e.msg,)

    parent_e = e.__cause__
    indent = 1
    while parent_e:
        indent += 1
        yield ":\n%s%s" % ("  " * indent, str(parent_e))
        parent_e = parent_e.__cause__


# We split these messages out to allow packages to override with package
# specific instructions.
MISSING_REPORT_STATS_CONFIG_INSTRUCTIONS = """\
Please opt in or out of reporting homeserver usage statistics, by setting
the `report_stats` key in your config file to either True or False.
"""

MISSING_REPORT_STATS_SPIEL = """\
We would really appreciate it if you could help our project out by reporting
homeserver usage statistics from your homeserver. Your homeserver's server name,
along with very basic aggregate data (e.g. number of users) will be reported. But
it helps us to track the growth of the Matrix community, and helps us to make Matrix
a success, as well as to convince other networks that they should peer with us.

Thank you.
"""

MISSING_SERVER_NAME = """\
Missing mandatory `server_name` config option.
"""


CONFIG_FILE_HEADER = """\
# Configuration file for Synapse.
#
# This is a YAML file: see [1] for a quick introduction. Note in particular
# that *indentation is important*: all the elements of a list or dictionary
# should have the same indentation.
#
# [1] https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html
#
# For more information on how to configure Synapse, including a complete accounting of
# each option, go to docs/usage/configuration/config_documentation.md or
# https://matrix-org.github.io/synapse/latest/usage/configuration/config_documentation.html
"""


def path_exists(file_path: str) -> bool:
    """Check if a file exists

    Unlike os.path.exists, this throws an exception if there is an error
    checking if the file exists (for example, if there is a perms error on
    the parent dir).

    Returns:
        True if the file exists; False if not.
    """
    try:
        os.stat(file_path)
        return True
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e
        return False


class Config:
    """
    A configuration section, containing configuration keys and values.

    Attributes:
        section: The section title of this config object, such as
            "tls" or "logger". This is used to refer to it on the root
            logger (for example, `config.tls.some_option`). Must be
            defined in subclasses.
    """

    section: ClassVar[str]

    def __init__(self, root_config: "RootConfig" = None):
        self.root = root_config

        # Get the path to the default Synapse template directory
        self.default_template_dir = pkg_resources.resource_filename(
            "synapse", "res/templates"
        )

    @staticmethod
    def parse_size(value: Union[str, int]) -> int:
        if isinstance(value, int):
            return value
        sizes = {"K": 1024, "M": 1024 * 1024}
        size = 1
        suffix = value[-1]
        if suffix in sizes:
            value = value[:-1]
            size = sizes[suffix]
        return int(value) * size

    @staticmethod
    def parse_duration(value: Union[str, int]) -> int:
        """Convert a duration as a string or integer to a number of milliseconds.

        If an integer is provided it is treated as milliseconds and is unchanged.

        String durations can have a suffix of 's', 'm', 'h', 'd', 'w', or 'y'.
        No suffix is treated as milliseconds.

        Args:
            value: The duration to parse.

        Returns:
            The number of milliseconds in the duration.
        """
        if isinstance(value, int):
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
    def abspath(file_path: str) -> str:
        return os.path.abspath(file_path) if file_path else file_path

    @classmethod
    def path_exists(cls, file_path: str) -> bool:
        return path_exists(file_path)

    @classmethod
    def check_file(cls, file_path: Optional[str], config_name: str) -> str:
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
    def ensure_directory(cls, dir_path: str) -> str:
        dir_path = cls.abspath(dir_path)
        os.makedirs(dir_path, exist_ok=True)
        if not os.path.isdir(dir_path):
            raise ConfigError("%s is not a directory" % (dir_path,))
        return dir_path

    @classmethod
    def read_file(cls, file_path: Any, config_name: str) -> str:
        """Deprecated: call read_file directly"""
        return read_file(file_path, (config_name,))

    def read_template(self, filename: str) -> jinja2.Template:
        """Load a template file from disk.

        This function will attempt to load the given template from the default Synapse
        template directory.

        Files read are treated as Jinja templates. The templates is not rendered yet
        and has autoescape enabled.

        Args:
            filename: A template filename to read.

        Raises:
            ConfigError: if the file's path is incorrect or otherwise cannot be read.

        Returns:
            A jinja2 template.
        """
        return self.read_templates([filename])[0]

    def read_templates(
        self,
        filenames: List[str],
        custom_template_directories: Optional[Iterable[str]] = None,
    ) -> List[jinja2.Template]:
        """Load a list of template files from disk using the given variables.

        This function will attempt to load the given templates from the default Synapse
        template directory. If `custom_template_directories` is supplied, any directory
        in this list is tried (in the order they appear in the list) before trying
        Synapse's default directory.

        Files read are treated as Jinja templates. The templates are not rendered yet
        and have autoescape enabled.

        Args:
            filenames: A list of template filenames to read.

            custom_template_directories: A list of directory to try to look for the
                templates before using the default Synapse template directory instead.

        Raises:
            ConfigError: if the file's path is incorrect or otherwise cannot be read.

        Returns:
            A list of jinja2 templates.
        """
        search_directories = []

        # The loader will first look in the custom template directories (if specified)
        # for the given filename. If it doesn't find it, it will use the default
        # template dir instead.
        if custom_template_directories is not None:
            for custom_template_directory in custom_template_directories:
                # Check that the given template directory exists
                if not self.path_exists(custom_template_directory):
                    raise ConfigError(
                        "Configured template directory does not exist: %s"
                        % (custom_template_directory,)
                    )

                # Search the custom template directory as well
                search_directories.append(custom_template_directory)

        # Append the default directory at the end of the list so Jinja can fallback on it
        # if a template is missing from any custom directory.
        search_directories.append(self.default_template_dir)

        # TODO: switch to synapse.util.templates.build_jinja_env
        loader = jinja2.FileSystemLoader(search_directories)
        env = jinja2.Environment(
            loader=loader,
            autoescape=jinja2.select_autoescape(),
        )

        # Update the environment with our custom filters
        env.filters.update(
            {
                "format_ts": _format_ts_filter,
                "mxc_to_http": _create_mxc_to_http_filter(
                    self.root.server.public_baseurl
                ),
            }
        )

        # Load the templates
        return [env.get_template(filename) for filename in filenames]


TRootConfig = TypeVar("TRootConfig", bound="RootConfig")


class RootConfig:
    """
    Holder of an application's configuration.

    What configuration this object holds is defined by `config_classes`, a list
    of Config classes that will be instantiated and given the contents of a
    configuration file to read. They can then be accessed on this class by their
    section name, defined in the Config or dynamically set to be the name of the
    class, lower-cased and with "Config" removed.
    """

    config_classes: List[Type[Config]] = []

    def __init__(self, config_files: Collection[str] = ()):
        # Capture absolute paths here, so we can reload config after we daemonize.
        self.config_files = [os.path.abspath(path) for path in config_files]

        for config_class in self.config_classes:
            if config_class.section is None:
                raise ValueError("%r requires a section name" % (config_class,))

            try:
                conf = config_class(self)
            except Exception as e:
                raise Exception("Failed making %s: %r" % (config_class.section, e))
            setattr(self, config_class.section, conf)

    def invoke_all(
        self, func_name: str, *args: Any, **kwargs: Any
    ) -> MutableMapping[str, Any]:
        """
        Invoke a function on all instantiated config objects this RootConfig is
        configured to use.

        Args:
            func_name: Name of function to invoke
            *args
            **kwargs

        Returns:
            ordered dictionary of config section name and the result of the
            function from it.
        """
        res = OrderedDict()

        for config_class in self.config_classes:
            config = getattr(self, config_class.section)

            if hasattr(config, func_name):
                res[config_class.section] = getattr(config, func_name)(*args, **kwargs)

        return res

    @classmethod
    def invoke_all_static(cls, func_name: str, *args: Any, **kwargs: any) -> None:
        """
        Invoke a static function on config objects this RootConfig is
        configured to use.

        Args:
            func_name: Name of function to invoke
            *args
            **kwargs

        Returns:
            ordered dictionary of config section name and the result of the
            function from it.
        """
        for config in cls.config_classes:
            if hasattr(config, func_name):
                getattr(config, func_name)(*args, **kwargs)

    def generate_config(
        self,
        config_dir_path: str,
        data_dir_path: str,
        server_name: str,
        generate_secrets: bool = False,
        report_stats: Optional[bool] = None,
        open_private_ports: bool = False,
        listeners: Optional[List[dict]] = None,
        tls_certificate_path: Optional[str] = None,
        tls_private_key_path: Optional[str] = None,
    ) -> str:
        """
        Build a default configuration file

        This is used when the user explicitly asks us to generate a config file
        (eg with --generate-config).

        Args:
            config_dir_path: The path where the config files are kept. Used to
                create filenames for things like the log config and the signing key.

            data_dir_path: The path where the data files are kept. Used to create
                filenames for things like the database and media store.

            server_name: The server name. Used to initialise the server_name
                config param, but also used in the names of some of the config files.

            generate_secrets: True if we should generate new secrets for things
                like the macaroon_secret_key. If False, these parameters will be left
                unset.

            report_stats: Initial setting for the report_stats setting.
                If None, report_stats will be left unset.

            open_private_ports: True to leave private ports (such as the non-TLS
                HTTP listener) open to the internet.

            listeners: A list of descriptions of the listeners synapse should
                start with each of which specifies a port (int), a list of
                resources (list(str)), tls (bool) and type (str). For example:
                [{
                    "port": 8448,
                    "resources": [{"names": ["federation"]}],
                    "tls": True,
                    "type": "http",
                },
                {
                    "port": 443,
                    "resources": [{"names": ["client"]}],
                    "tls": False,
                    "type": "http",
                }],

            tls_certificate_path: The path to the tls certificate.

            tls_private_key_path: The path to the tls private key.

        Returns:
            The yaml config file
        """

        conf = CONFIG_FILE_HEADER + "\n".join(
            dedent(conf)
            for conf in self.invoke_all(
                "generate_config_section",
                config_dir_path=config_dir_path,
                data_dir_path=data_dir_path,
                server_name=server_name,
                generate_secrets=generate_secrets,
                report_stats=report_stats,
                open_private_ports=open_private_ports,
                listeners=listeners,
                tls_certificate_path=tls_certificate_path,
                tls_private_key_path=tls_private_key_path,
            ).values()
        )
        conf = re.sub("\n{2,}", "\n", conf)
        return conf

    @classmethod
    def load_config(
        cls: Type[TRootConfig], description: str, argv: List[str]
    ) -> TRootConfig:
        """Parse the commandline and config files

        Doesn't support config-file-generation: used by the worker apps.

        Returns:
            Config object.
        """
        config_parser = argparse.ArgumentParser(description=description)
        cls.add_arguments_to_parser(config_parser)
        obj, _ = cls.load_config_with_parser(config_parser, argv)

        return obj

    @classmethod
    def add_arguments_to_parser(cls, config_parser: argparse.ArgumentParser) -> None:
        """Adds all the config flags to an ArgumentParser.

        Doesn't support config-file-generation: used by the worker apps.

        Used for workers where we want to add extra flags/subcommands.

        Args:
            config_parser: App description
        """

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
            " their location is not given explicitly in the config."
            " Defaults to the directory containing the last config file",
        )

        cls.invoke_all_static("add_arguments", config_parser)

    @classmethod
    def load_config_with_parser(
        cls: Type[TRootConfig], parser: argparse.ArgumentParser, argv: List[str]
    ) -> Tuple[TRootConfig, argparse.Namespace]:
        """Parse the commandline and config files with the given parser

        Doesn't support config-file-generation: used by the worker apps.

        Used for workers where we want to add extra flags/subcommands.

        Args:
            parser
            argv

        Returns:
            Returns the parsed config object and the parsed argparse.Namespace
            object from parser.parse_args(..)`
        """

        config_args = parser.parse_args(argv)

        config_files = find_config_files(search_paths=config_args.config_path)
        obj = cls(config_files)
        if not config_files:
            parser.error("Must supply a config file.")

        if config_args.keys_directory:
            config_dir_path = config_args.keys_directory
        else:
            config_dir_path = os.path.dirname(config_files[-1])
        config_dir_path = os.path.abspath(config_dir_path)
        data_dir_path = os.getcwd()

        config_dict = read_config_files(config_files)
        obj.parse_config_dict(
            config_dict, config_dir_path=config_dir_path, data_dir_path=data_dir_path
        )

        obj.invoke_all("read_arguments", config_args)

        return obj, config_args

    @classmethod
    def load_or_generate_config(
        cls: Type[TRootConfig], description: str, argv: List[str]
    ) -> Optional[TRootConfig]:
        """Parse the commandline and config files

        Supports generation of config files, so is used for the main homeserver app.

        Returns:
            Config object, or None if --generate-config or --generate-keys was set
        """
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            "-c",
            "--config-path",
            action="append",
            metavar="CONFIG_FILE",
            help="Specify config file. Can be given multiple times and"
            " may specify directories containing *.yaml files.",
        )

        # we nest the mutually-exclusive group inside another group so that the help
        # text shows them in their own group.
        generate_mode_group = parser.add_argument_group(
            "Config generation mode",
        )
        generate_mode_exclusive = generate_mode_group.add_mutually_exclusive_group()
        generate_mode_exclusive.add_argument(
            # hidden option to make the type and default work
            "--generate-mode",
            help=argparse.SUPPRESS,
            type=_ConfigGenerateMode,
            default=_ConfigGenerateMode.GENERATE_MISSING_AND_RUN,
        )
        generate_mode_exclusive.add_argument(
            "--generate-config",
            help="Generate a config file, then exit.",
            action="store_const",
            const=_ConfigGenerateMode.GENERATE_EVERYTHING_AND_EXIT,
            dest="generate_mode",
        )
        generate_mode_exclusive.add_argument(
            "--generate-missing-configs",
            "--generate-keys",
            help="Generate any missing additional config files, then exit.",
            action="store_const",
            const=_ConfigGenerateMode.GENERATE_MISSING_AND_EXIT,
            dest="generate_mode",
        )
        generate_mode_exclusive.add_argument(
            "--generate-missing-and-run",
            help="Generate any missing additional config files, then run. This is the "
            "default behaviour.",
            action="store_const",
            const=_ConfigGenerateMode.GENERATE_MISSING_AND_RUN,
            dest="generate_mode",
        )

        generate_group = parser.add_argument_group("Details for --generate-config")
        generate_group.add_argument(
            "-H", "--server-name", help="The server name to generate a config file for."
        )
        generate_group.add_argument(
            "--report-stats",
            action="store",
            help="Whether the generated config reports homeserver usage statistics.",
            choices=["yes", "no"],
        )
        generate_group.add_argument(
            "--config-directory",
            "--keys-directory",
            metavar="DIRECTORY",
            help=(
                "Specify where additional config files such as signing keys and log"
                " config should be stored. Defaults to the same directory as the last"
                " config file."
            ),
        )
        generate_group.add_argument(
            "--data-directory",
            metavar="DIRECTORY",
            help=(
                "Specify where data such as the media store and database file should be"
                " stored. Defaults to the current working directory."
            ),
        )
        generate_group.add_argument(
            "--open-private-ports",
            action="store_true",
            help=(
                "Leave private ports (such as the non-TLS HTTP listener) open to the"
                " internet. Do not use this unless you know what you are doing."
            ),
        )

        cls.invoke_all_static("add_arguments", parser)
        config_args = parser.parse_args(argv)

        config_files = find_config_files(search_paths=config_args.config_path)

        if not config_files:
            parser.error(
                "Must supply a config file.\nA config file can be automatically"
                ' generated using "--generate-config -H SERVER_NAME'
                ' -c CONFIG-FILE"'
            )

        if config_args.config_directory:
            config_dir_path = config_args.config_directory
        else:
            config_dir_path = os.path.dirname(config_files[-1])
        config_dir_path = os.path.abspath(config_dir_path)
        data_dir_path = os.getcwd()

        obj = cls(config_files)

        if (
            config_args.generate_mode
            == _ConfigGenerateMode.GENERATE_EVERYTHING_AND_EXIT
        ):
            if config_args.report_stats is None:
                parser.error(
                    "Please specify either --report-stats=yes or --report-stats=no\n\n"
                    + MISSING_REPORT_STATS_SPIEL
                )

            (config_path,) = config_files
            if not path_exists(config_path):
                print("Generating config file %s" % (config_path,))

                if config_args.data_directory:
                    data_dir_path = config_args.data_directory
                else:
                    data_dir_path = os.getcwd()
                data_dir_path = os.path.abspath(data_dir_path)

                server_name = config_args.server_name
                if not server_name:
                    raise ConfigError(
                        "Must specify a server_name to a generate config for."
                        " Pass -H server.name."
                    )

                config_str = obj.generate_config(
                    config_dir_path=config_dir_path,
                    data_dir_path=data_dir_path,
                    server_name=server_name,
                    report_stats=(config_args.report_stats == "yes"),
                    generate_secrets=True,
                    open_private_ports=config_args.open_private_ports,
                )

                os.makedirs(config_dir_path, exist_ok=True)
                with open(config_path, "w") as config_file:
                    config_file.write(config_str)
                    config_file.write("\n\n# vim:ft=yaml")

                config_dict = yaml.safe_load(config_str)
                obj.generate_missing_files(config_dict, config_dir_path)

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
                        "Config file %r already exists. Generating any missing config"
                        " files."
                    )
                    % (config_path,)
                )

        config_dict = read_config_files(config_files)
        obj.generate_missing_files(config_dict, config_dir_path)

        if config_args.generate_mode in (
            _ConfigGenerateMode.GENERATE_EVERYTHING_AND_EXIT,
            _ConfigGenerateMode.GENERATE_MISSING_AND_EXIT,
        ):
            return None

        obj.parse_config_dict(
            config_dict, config_dir_path=config_dir_path, data_dir_path=data_dir_path
        )
        obj.invoke_all("read_arguments", config_args)

        return obj

    def parse_config_dict(
        self, config_dict: Dict[str, Any], config_dir_path: str, data_dir_path: str
    ) -> None:
        """Read the information from the config dict into this Config object.

        Args:
            config_dict: Configuration data, as read from the yaml

            config_dir_path: The path where the config files are kept. Used to
                create filenames for things like the log config and the signing key.

            data_dir_path: The path where the data files are kept. Used to create
                filenames for things like the database and media store.
        """
        self.invoke_all(
            "read_config",
            config_dict,
            config_dir_path=config_dir_path,
            data_dir_path=data_dir_path,
        )

    def generate_missing_files(
        self, config_dict: Dict[str, Any], config_dir_path: str
    ) -> None:
        self.invoke_all("generate_files", config_dict, config_dir_path)

    def reload_config_section(self, section_name: str) -> Config:
        """Reconstruct the given config section, leaving all others unchanged.

        This works in three steps:

        1. Create a new instance of the relevant `Config` subclass.
        2. Call `read_config` on that instance to parse the new config.
        3. Replace the existing config instance with the new one.

        :raises ValueError: if the given `section` does not exist.
        :raises ConfigError: for any other problems reloading config.

        :returns: the previous config object, which no longer has a reference to this
            RootConfig.
        """
        existing_config: Optional[Config] = getattr(self, section_name, None)
        if existing_config is None:
            raise ValueError(f"Unknown config section '{section_name}'")
        logger.info("Reloading config section '%s'", section_name)

        new_config_data = read_config_files(self.config_files)
        new_config = type(existing_config)(self)
        new_config.read_config(new_config_data)
        setattr(self, section_name, new_config)

        existing_config.root = None
        return existing_config


def read_config_files(config_files: Iterable[str]) -> Dict[str, Any]:
    """Read the config files into a dict

    Args:
        config_files: A list of the config files to read

    Returns:
        The configuration dictionary.
    """
    specified_config = {}
    for config_file in config_files:
        with open(config_file) as file_stream:
            yaml_config = yaml.safe_load(file_stream)

        if not isinstance(yaml_config, dict):
            err = "File %r is empty or doesn't parse into a key-value map. IGNORING."
            print(err % (config_file,))
            continue

        specified_config.update(yaml_config)

    if "server_name" not in specified_config:
        raise ConfigError(MISSING_SERVER_NAME)

    if "report_stats" not in specified_config:
        raise ConfigError(
            MISSING_REPORT_STATS_CONFIG_INSTRUCTIONS + "\n" + MISSING_REPORT_STATS_SPIEL
        )
    return specified_config


def find_config_files(search_paths: List[str]) -> List[str]:
    """Finds config files using a list of search paths. If a path is a file
    then that file path is added to the list. If a search path is a directory
    then all the "*.yaml" files in that directory are added to the list in
    sorted order.

    Args:
        search_paths: A list of paths to search.

    Returns:
        A list of file paths.
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


@attr.s(auto_attribs=True)
class ShardedWorkerHandlingConfig:
    """Algorithm for choosing which instance is responsible for handling some
    sharded work.

    For example, the federation senders use this to determine which instances
    handles sending stuff to a given destination (which is used as the `key`
    below).
    """

    instances: List[str]

    def should_handle(self, instance_name: str, key: str) -> bool:
        """Whether this instance is responsible for handling the given key."""
        # If no instances are defined we assume some other worker is handling
        # this.
        if not self.instances:
            return False

        return self._get_instance(key) == instance_name

    def _get_instance(self, key: str) -> str:
        """Get the instance responsible for handling the given key.

        Note: For federation sending and pushers the config for which instance
        is sending is known only to the sender instance, so we don't expose this
        method by default.
        """

        if not self.instances:
            raise Exception("Unknown worker")

        if len(self.instances) == 1:
            return self.instances[0]

        # We shard by taking the hash, modulo it by the number of instances and
        # then checking whether this instance matches the instance at that
        # index.
        #
        # (Technically this introduces some bias and is not entirely uniform,
        # but since the hash is so large the bias is ridiculously small).
        dest_hash = sha256(key.encode("utf8")).digest()
        dest_int = int.from_bytes(dest_hash, byteorder="little")
        remainder = dest_int % (len(self.instances))
        return self.instances[remainder]


@attr.s
class RoutableShardedWorkerHandlingConfig(ShardedWorkerHandlingConfig):
    """A version of `ShardedWorkerHandlingConfig` that is used for config
    options where all instances know which instances are responsible for the
    sharded work.
    """

    def __attrs_post_init__(self):
        # We require that `self.instances` is non-empty.
        if not self.instances:
            raise Exception("Got empty list of instances for shard config")

    def get_instance(self, key: str) -> str:
        """Get the instance responsible for handling the given key."""
        return self._get_instance(key)


def read_file(file_path: Any, config_path: Iterable[str]) -> str:
    """Check the given file exists, and read it into a string

    If it does not, emit an error indicating the problem

    Args:
        file_path: the file to be read
        config_path: where in the configuration file_path came from, so that a useful
           error can be emitted if it does not exist.
    Returns:
        content of the file.
    Raises:
        ConfigError if there is a problem reading the file.
    """
    if not isinstance(file_path, str):
        raise ConfigError("%r is not a string", config_path)

    try:
        os.stat(file_path)
        with open(file_path) as file_stream:
            return file_stream.read()
    except OSError as e:
        raise ConfigError("Error accessing file %r" % (file_path,), config_path) from e


class _ConfigGenerateMode(Enum):
    GENERATE_MISSING_AND_RUN = auto()
    GENERATE_MISSING_AND_EXIT = auto()
    GENERATE_EVERYTHING_AND_EXIT = auto()


__all__ = [
    "Config",
    "RootConfig",
    "ShardedWorkerHandlingConfig",
    "RoutableShardedWorkerHandlingConfig",
    "read_file",
]
