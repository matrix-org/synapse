# Hardening 
**Disclaimer: This guide is just a collection of ideas to make a synapse homeserver more secure - It is far from complete!**

## General hardening
- SSH hardening (key-based login only, change port, etc.)
- Basic firewall (e.g. via `iptables`) - The following configuration is necessary for a matrix server to work properly (**This setup is not bulletproof, but should be a quite secure default!**):
	- incoming https rule for basic server functionality, e.g.
	`iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT`
	- outgoing rule for https (the server has to "speak" to other homeservers), e.g.
	`iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT`
	- for also reaching homservers that were set up **without a reverse proxy** the outgoing port 8448 is needed (although there seems to be some uncertainty, whether this kind of setup is recommended, see https://github.com/matrix-org/synapse/issues/2438), e.g.
	`iptables -A INPUT -p tcp --dport 8448 -m conntrack --ctstate NEW -j ACCEPT`
	- a rule on both chains to allow all established connections, e.g.
	`iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT`,
	`iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT`
	- a loopback rule on both chains to allow internal connections, e.g.
	`iptables -A INPUT -i lo -j ACCEPT`,
	`iptables -A OUTPUT -o lo -j ACCEPT`
	- and of course **don't forget a rule for your SSH connection** before changing the overall policies to *deny* or otherwise you're going to lock yourself out, e.g.
	`iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT` (change SSH port accordingly)
- Furthermore it is not advisable to run a frontend (e.g. Element) on the same server synapse is running on. (See https://github.com/vector-im/element-web/issues/1977)
- ... (there are tons of other general - non synapse specific) security measures to consider, like AppArmor or SELinux - if you're not working on a VPS - or IDS/IPS like rkhunter, CrowdSec, etc.)

## Hardening the nginx configuration
When using nginx as a reverse proxy, the following measures may be applied to your nginx configuration:
- Improve SSL security:
	- Remove support for the old/insecure protocol versions 1.0 and 1.1; activate support for the most recent version 1.3; disable some insecure ciphers
	When using Let's Encrypt for certificate generation, you have to change these settings not only in the nginx configuration file (`/etc/nginx/nginx.conf` - it contains a SSL section!) but also within the Let's Encrypt config file (`/etc/letsencrypt/options-ssl-nginx.conf`)
		```
		ssl_protocols TLSv1.2 TLSv1.3;
		ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA HIGH !RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS";
		```
		Also checked (via `cat /etc/nginx/sites-available/* | grep ssl_protocols`) for any overrides of the protocol version and change them accordingly, if there are any.
	- Create your own Diffie-Hellman group for SSL (**This may take several minutes!**)
	`openssl dhparam -out dhparams.pem 4096`
	`sudo mkdir -p /opt/cert && sudo cp dhparams.pem /opt/cert/`
	Add the following line to the nginx configuration file (`/etc/nginx/nginx.conf`):
	  ```
	  ssl_dhparam /opt/cert/dhparams.pem;
	  ```
- Add some best practice header information to the nginx configuration file (`/etc/nginx/nginx.conf`):
	```
	add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
	add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
	add_header X-Frame-Options "SAMEORIGIN";
	```

## Resources
- https://geekflare.com/nginx-webserver-security-hardening-guide/
- https://www.acunetix.com/blog/web-security-zone/hardening-nginx/
- https://libre-software.net/tls-nginx/

