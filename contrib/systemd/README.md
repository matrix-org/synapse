# Setup Synapse with Systemd
This is a setup for managing synapse with a user contributed systemd unit 
file. It provides a `matrix-synapse` systemd unit file that should be tailored 
to accommodate your installation in accordance with the installation 
instructions provided in [installation instructions](../../INSTALL.md).

## Setup
1. Under the service section, ensure the `User` variable matches which user
you installed synapse under and wish to run it as. 
2. Under the service section, ensure the `WorkingDirectory` variable matches
where you have installed synapse.
3. Under the service section, ensure the `ExecStart` variable matches the
appropriate locations of your installation.
4. Copy the `matrix-synapse.service` to `/etc/systemd/system/`
5. Start Synapse: `sudo systemctl start matrix-synapse`
6. Verify Synapse is running: `sudo systemctl status matrix-synapse`
7. *optional* Enable Synapse to start at system boot: `sudo systemctl enable matrix-synapse`
