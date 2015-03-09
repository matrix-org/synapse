import logging
from distutils.version import LooseVersion

logger = logging.getLogger(__name__)

REQUIREMENTS = {
    "syutil>=0.0.3": ["syutil"],
    "matrix_angular_sdk>=0.6.4": ["syweb>=0.6.4"],
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


def github_link(project, version, egg):
    return "https://github.com/%s/tarball/%s/#egg=%s" % (project, version, egg)

DEPENDENCY_LINKS = [
    github_link(
        project="pyca/pynacl",
        version="d4d3175589b892f6ea7c22f466e0e223853516fa",
        egg="pynacl-0.3.0",
    ),
    github_link(
        project="matrix-org/syutil",
        version="v0.0.3",
        egg="syutil-0.0.3",
    ),
    github_link(
        project="matrix-org/matrix-angular-sdk",
        version="v0.6.4",
        egg="matrix_angular_sdk-0.6.4",
    ),
]


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


def list_requirements():
    result = []
    linked = []
    for link in DEPENDENCY_LINKS:
        egg = link.split("#egg=")[1]
        linked.append(egg.split('-')[0])
        result.append(link)
    for requirement in REQUIREMENTS:
        is_linked = False
        for link in linked:
            if requirement.replace('-', '_').startswith(link):
                is_linked = True
        if not is_linked:
            result.append(requirement)
    return result

if __name__ == "__main__":
    import sys
    sys.stdout.writelines(req + "\n" for req in list_requirements())
