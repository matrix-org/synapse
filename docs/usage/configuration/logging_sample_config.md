# Logging Sample Configuration File

Below is a sample logging configuration file. This file can be tweaked to control how your
homeserver will output logs. A restart of the server is generally required to apply any
changes made to this file.

Note that the contents below are *not* intended to be copied and used as the basis for
a real homeserver.yaml. Instead, if you are starting from scratch, please generate
a fresh config using Synapse by following the instructions in
[Installation](../../setup/installation.md).

```yaml
{{#include ../../sample_log_config.yaml}}
``__`