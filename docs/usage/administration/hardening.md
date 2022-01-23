# Hardening
**Disclaimer: This guide is just a collection of ideas to make a synapse homeserver more secure - It is far from complete!**

## General hardening
- SSH hardening (key-based login only, change port, etc.)
- Basic firewall (e.g. via `iptables`) - The following configuration is necessary for a matrix server to work properly (**This setup is not bulletproof, but should be a quite secure default!**):
	|CHAIN|PROTOCOL|PORT|STATE|DESCRIPTION|EXAMPLE for `iptables`|
	|-|-|-|-|-|-|
	|INPUT|TCP|443|NEW|Incoming https rule for basic server functionality|`iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT`|
	|OUTPUT|TCP|443|NEW|Outgoing rule for https (the server has to "speak" with other homeservers)|`iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT`|
	|OUTPUT|TCP|8448|NEW|For also reaching homeservers that were set up **without a reverse proxy** the outgoing port 8448 is needed|`iptables -A OUTPUT -p tcp --dport 8448 -m conntrack --ctstate NEW -j ACCEPT`|
	|INPUT|*|*|ESTABLISHED|A rule to allow all incoming, established connections|`iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT`|
	|OUTPUT|*|*|ESTABLISHED|A rule to allow all outgoing, established connections|`iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT`|
	|INPUT|TCP|22 (or whatever your personal SSH port is)|NEW|Of course **don't forget a rule for your SSH connection** or otherwise you're going to lock yourself out eventually|`iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT`|
	Overall policy for all chains: DENY
	**However**, note that this approach of only allowing the ports 443 and 8448 on the outbound chain is a quite restrictive approach and may cause your homeserver to fail connect to some other homeservers that want to listen on another port. Since there is no way of knowing for certain, you have to decide for yourself if you want to follow this more secure but higher maintenance approach or be less restrictive by allowing more (or even all) outgoing ports.
- Put your synapse instance behind a reverse proxy!
- Furthermore it is not advisable to run a frontend (e.g. Element) in the same domain context as synapse. (See https://github.com/vector-im/element-web/issues/1977) So for example use different subdomains for your client and homeserver
- The Element project itself provides a list of configuration best practices to consider when using this client (See https://github.com/vector-im/element-web/#configuration-best-practices)
- ... (there are tons of other general - non synapse specific) security measures to consider, like AppArmor or SELinux - if you're not working on a VPS - or IDS/IPS like rkhunter, CrowdSec, etc.)

## Hardening the nginx configuration
When running synapse on a nginx basis the following measures may be applied to your nginx configuration:
- Improve SSL security:
	- Remove support for the old/insecure protocol versions 1.0 and 1.1; activate support for the most recent version 1.3; disable some insecure ciphers
	When using Let's Encrypt for certificate generation, you have to change these settings not only in the nginx configuration file (`/etc/nginx/nginx.conf` - it contains a SSL section!) but also within the Let's Encrypt config file (`/etc/letsencrypt/options-ssl-nginx.conf`)
	An up-to-date recommendation for these settings should be found at https://ssl-config.mozilla.org/#server=nginx&version=1.17.7&config=intermediate&openssl=1.1.1k&guideline=5.6
	An example (for the time of writing this guide) may be the following:
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
