import logging
from distutils.version import LooseVersion

logger = logging.getLogger(__name__)

REQUIREMENTS = {
    "syutil==0.0.2": ["syutil"],
    "matrix_angular_sdk==0.6.0": ["syweb>=0.6.0"],
    "Twisted==14.0.2": ["twisted==14.0.2"],
    "service_identity>=1.0.0": ["service_identity>=1.0.0"],
    "pyopenssl>=0.14": ["OpenSSL>=0.14"],
    "pyyaml": ["yaml"],
    "pyasn1": ["pyasn1"],
    "pynacl": ["nacl"],
    "daemonize": ["daemonize"],
    "py-bcrypt": ["bcrypt"],
    "frozendict>=0.4": ["frozendict"],
    "pillow": ["PIL"],
    "pydenticon": ["pydenticon"],
}


class MissingRequirementError(Exception):
    pass


def check_requirements():
    """Checks that all the modules needed by synapse have been correctly
    installed and are at the correct version"""
    for dependency, module_requirements in REQUIREMENTS.items():
        for module_requirement in module_requirements:
            if ">=" in module_requirement:
                module_name, required_version = module_requirement.split(">=")
                version_test = ">="
            elif "==" in module_requirement:
                module_name, required_version = module_requirement.split("==")
                version_test = "=="
            else:
                module_name = module_requirement
                version_test = None

            try:
                module = __import__(module_name)
            except ImportError:
                logging.exception(
                    "Can't import %r which is part of %r",
                    module_name, dependency
                )
                raise MissingRequirementError(
                    "Can't import %r which is part of %r"
                    % (module_name, dependency)
                )
            version = getattr(module, "__version__", None)
            file_path = getattr(module, "__file__", None)
            logger.info(
                "Using %r version %r from %r to satisfy %r",
                module_name, version, file_path, dependency
            )

            if version_test == ">=":
                if version is None:
                    raise MissingRequirementError(
                        "Version of %r isn't set as __version__ of module %r"
                        % (dependency, module_name)
                    )
                if LooseVersion(version) < LooseVersion(required_version):
                    raise MissingRequirementError(
                        "Version of %r in %r is too old. %r < %r"
                        % (dependency, file_path, version, required_version)
                    )
            elif version_test == "==":
                if version is None:
                    raise MissingRequirementError(
                        "Version of %r isn't set as __version__ of module %r"
                        % (dependency, module_name)
                    )
                if LooseVersion(version) != LooseVersion(required_version):
                    raise MissingRequirementError(
                        "Unexpected version of %r in %r. %r != %r"
                        % (dependency, file_path, version, required_version)
                    )
