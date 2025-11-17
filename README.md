SecurePad
========

SecurePad is a small Django application for storing notes, secrets, and environment variables. It includes features to encrypt per-user notes using a per-user data-encryption key (DEK), cache keys per session for a limited time, and manage secrets from a simple web UI.

Features
--------
- User authentication (Django auth) with login and logout.
- Per-user encryption using a server-side DEK encrypted by a password-derived key.
- Optional client-side AES-GCM encryption for creating secrets.
- One-time decrypting banner after login (auto-dismisses).
- Admin safeguards so users can only see their own items.
- Bootstrap-powered responsive UI.

Prerequisites
-------------
- Python 3.12 (recommended)
- Virtual environment
 

Configuration
-------------
1. Environment variables
   - DJANGO_SECRET_KEY (required in production settings)
    - DJANGO_DEBUG (optional, default True). Accepts: 1, true, yes
   - DJANGO_ALLOWED_HOSTS (comma-separated list; default: 127.0.0.1,localhost)
   - DJANGO_CSRF_TRUSTED_ORIGINS (comma-separated list such as https://securepad.testingurl.cloud)

 

Running locally
---------------
Clone the repository and set up a virtual environment with Python 3.12:

    python3.12 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Run migrations and create a superuser if needed:

    python manage.py migrate
    python manage.py createsuperuser

For local development run:

    python manage.py runserver

Hosting on a Linux server
-------------------------
These steps assume you have a Linux host with Python 3.12 available.

1. Prepare the system and install packages

    sudo apt update
    sudo apt install -y python3.12 python3.12-venv python3.12-dev build-essential

2. Create a system user, clone the repository, and prepare a virtual environment

    sudo adduser --system --group --home /srv/securepad securepad
    sudo mkdir -p /srv/securepad/securepad_project
    sudo chown securepad:securepad /srv/securepad/securepad_project
    # As the securepad user (or via sudo -u securepad):
    # Copy the project files to /srv/securepad/securepad_project (for example, via scp or git clone to your own repository)
    # For example, copy the files into /srv/securepad/securepad_project (via scp or by cloning your chosen repository)
    cd /srv/securepad/securepad_project
    python3.12 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

3. Set environment variables for the app (systemd or env file recommended)

    export DJANGO_DEBUG=False
    export DJANGO_SECRET_KEY="<your-secret-key>"
    export DJANGO_ALLOWED_HOSTS=securepad.testingurl.cloud
    export DJANGO_CSRF_TRUSTED_ORIGINS=https://securepad.testingurl.cloud

4. Run migrations and collect static files

    python manage.py migrate
    python manage.py collectstatic --no-input

5. Create a systemd service to run the Django development server on port 8001

This example runs the Django development server on port 8001. It's intended for personal or simple internal hosting; it's not a production-grade configuration.

Create a systemd unit file `/etc/systemd/system/securepad.service` as follows:

    [Unit]
    Description=SecurePad Django Development Server
    After=network.target

    [Service]
    User=securepad
    Group=securepad
    WorkingDirectory=/srv/securepad/securepad_project
    Environment=DJANGO_DEBUG=False
    Environment=DJANGO_SECRET_KEY="<your-secret-key>"
    Environment=DJANGO_ALLOWED_HOSTS=securepad.testingurl.cloud
    ExecStart=/srv/securepad/securepad_project/venv/bin/python3.12 manage.py runserver 0.0.0.0:8001
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target

Then enable and start the service:

    sudo systemctl daemon-reload
    sudo systemctl enable --now securepad

6. Serving static files

Set your web server or hosting panel to serve `/static/` from the `staticfiles` directory created by `collectstatic`.
7. (Optional) Secure the site with HTTPS using a cert manager and firewall rules.

8. Notes on the server environment
   - Make sure `/srv/securepad/securepad_project/db.sqlite3` and `staticfiles` are writable by the `securepad` user.
   - For multi-worker environments, switch Django cache to Redis for consistent caching of DEKs between workers.
   - To set environment variables persistently, use an env file and point systemd's `EnvironmentFile` to it.

Security considerations
-----------------------
- For local or non-production use, `DEBUG=True` is acceptable; however, do not use debug mode in a public production environment.
- Do not commit or hardcode secret keys. Use the `DJANGO_SECRET_KEY` environment variable.
- Cache configuration: this setup uses the Django in-memory cache by default. For multi-worker deployments, use Redis or Memcached for sharing the session cache.
- The app stores encrypted contents in the database. DEKs are cached per session for a short TTL. For improved security, consider using a hardware key management service or a secured secrets store.

<!-- Nginx example removed. Use a simple server or host-provided static file settings. -->

Tips
----
- If you run multiple workers or run behind multiple WSGI processes, consider using Redis for Django cache rather than the default in-memory cache.
- Ensure the `db.sqlite3` file, static directory, and any created files are readable and writable by the WSGI server user.
For an easy start, set `DJANGO_ALLOWED_HOSTS=securepad.testingurl.cloud` and `DJANGO_CSRF_TRUSTED_ORIGINS=https://securepad.testingurl.cloud` in your server's environment variables.

Contributing
------------
If you want to improve this project, submit a PR or create issues for bugs and feature requests. For a production-ready deployment, see the security considerations above and consider moving sensitive data off-premises.

License
-------
This project is MIT-licensed.
# SecurePad – Notes & Secrets Vault (Django)

A minimal Django-based web app to store personal notes and sensitive snippets such as API keys or `.env`-style entries.

> **Important:** Secrets should be stored in a dedicated secret manager with strong encryption and access control. This repository provides an example of application-level encryption and is not intended to be used as a certified production-grade secrets store.

## Features

- User-specific storage: each item is owned by a user.
- Item types: `Note`, `Secret`, `Env Variable`.
- Simple dashboard to list items.
- Detail view per item.
- Admin interface to create and edit entries.

## Tech Stack

- Python 3.12
- Django 4.2
- SQLite (default Django database)

## Setup

```bash
    python3.12 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

python manage.py migrate
python manage.py createsuperuser  # create an admin user
python manage.py runserver
```

Visit:

- `http://127.0.0.1:8000/admin/` – to log in and create `SecretItem` entries.
- `http://127.0.0.1:8000/` – to see the dashboard for the logged-in user.

## Usage

1. Run the development server.
2. Log in via `/admin/` using the superuser account.
3. Create a few `SecretItem` entries:
   - A normal note.
   - A secret/API key.
   - An env-style key-value pair.
4. Visit `/` to see them listed on the dashboard and click into a detail page.

### Frontend/UI Updates

- The UI has been improved to use Bootstrap for a neat, responsive layout.
- Secrets are masked by default on the item detail page and can be toggled with a button to show/hide their value.
- Dashboard items are presented as cards; click to open details.
 - The dashboard includes a search bar to filter notes and secrets by title and content.
 - The dashboard includes a search bar to filter notes and secrets by title and content.
 - Notes are now encrypted at rest per-user using a Data Encryption Key (DEK). On login the DEK is decrypted (using your password) and cached for 5 minutes; it is cleared on logout.
 - Clients can optionally encrypt content before sending it to the server (client-side encryption). The server also supports server-side encryption if the DEK is available.
 - Admin interface and dashboard are now restricted so users can only view their own items; admins will only see their own items.
 - Removed the 'Forgot password' link on the login page for now.
 - Added a friendly "Logged out" page that automatically attempts to close the tab in 5 seconds and redirects back to the dashboard if closing is blocked by the browser.
 - Footer is now sticky at the bottom of the screen regardless of content length.

## Security Note

This is not production-ready code. There is no built-in encryption key management, no secret rotation, and no advanced access control. Review the security considerations and use a production-grade solution and managed secret store for sensitive data in real deployments.
