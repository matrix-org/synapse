# Setup Synapse with Systemd
This is a setup for managing synapse with the user contributed systemd unit 
file. It provides a `matrix-synapse` systemd unit file that should be tailored 
to accomidate your installation in accordinance with the installation 
instructions provided in [installation instructions](https://github.com/matrix-org/synapse/blob/master/INSTALL.md).

## Setup
1. Under the service section, ensure the `User` variable matches which user
you installed synapse under and wish to run it as. 
2. Under the service section, ensure the `WorkingDirectory` variablei matches
where you have installed synapse.
3. Under the service section, ensure the `ExecStart` variable matches the
appropriate locations of your installation.
4. Copy the `mastodon-synapse.service` to `/etc/systemd/system/`
5. Start the service: `sudo systemctl start matrix-synapse`
6. Verify the service: `sudo systemctl status matrix-synapse`
7. *optional* Enable the service at boot: `sudo systemctl enable matrix-synapse`
