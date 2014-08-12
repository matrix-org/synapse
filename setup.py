import os
from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="SynapseHomeServer",
    version="0.1",
    packages=find_packages(exclude=["tests"]),
    description="Reference Synapse Home Server",
    install_requires=[
        "syutil==0.0.1",
        "Twisted>=14.0.0",
        "service_identity>=1.0.0",
        "pyasn1",
        "pynacl",
        "daemonize",
        "py-bcrypt",
    ],
    dependency_links=[
        "git+ssh://git@git.openmarket.com/tng/syutil.git#egg=syutil-0.0.1",
    ],
    setup_requires=[
        "setuptools_trial",
        "setuptools>=1.0.0", # Needs setuptools that supports git+ssh. It's not obvious when support for this was introduced.
        "mock"
    ],
    include_package_data=True,
    long_description=read("README.rst"),
    entry_points="""
    [console_scripts]
    synapse-homeserver=synapse.app.homeserver:run
    """
)
