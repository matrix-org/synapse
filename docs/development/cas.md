# How to test CAS as a developer without a server

The [django-mama-cas](https://github.com/jbittel/django-mama-cas) project is an
easy to run CAS implementation built on top of Django.

## Prerequisites

1. Create a new virtualenv: `python3 -m venv <your virtualenv>`
2. Activate your virtualenv: `source /path/to/your/virtualenv/bin/activate`
3. Install Django and django-mama-cas:
   ```sh
   python -m pip install "django<3" "django-mama-cas==2.4.0"
   ```
4. Create a Django project in the current directory:
   ```sh
   django-admin startproject cas_test .
   ```
5. Follow the [install directions](https://django-mama-cas.readthedocs.io/en/latest/installation.html#configuring) for django-mama-cas
6. Setup the SQLite database: `python manage.py migrate`
7. Create a user:
   ```sh
   python manage.py createsuperuser
   ```
   1. Use whatever you want as the username and password.
   2. Leave the other fields blank.
8. Use the built-in Django test server to serve the CAS endpoints on port 8000:
   ```sh
   python manage.py runserver
   ```

You should now have a Django project configured to serve CAS authentication with
a single user created.

## Configure Synapse (and Element) to use CAS

1. Modify your `homeserver.yaml` to enable CAS and point it to your locally
   running Django test server:
   ```yaml
   cas_config:
     enabled: true
     server_url: "http://localhost:8000"
     service_url: "http://localhost:8081"
     #displayname_attribute: name
     #required_attributes:
     #    name: value
   ```
2. Restart Synapse.

Note that the above configuration assumes the homeserver is running on port 8081
and that the CAS server is on port 8000, both on localhost.

## Testing the configuration

Then in Element:

1. Visit the login page with a Element pointing at your homeserver.
2. Click the Single Sign-On button.
3. Login using the credentials created with `createsuperuser`.
4. You should be logged in.

If you want to repeat this process you'll need to manually logout first:

1. http://localhost:8000/admin/
2. Click "logout" in the top right.
