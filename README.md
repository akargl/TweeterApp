# Tweeter

Tweeter is a simple microblogging app. Users can share text and files semi-publically with all other registrated and authenticated users or privatly between another user.
Images (.png, .jpg, .jpeg) are rendered directly. Other files are rendered as links.
Administrators can delete users and grant them administration priviliges.

## API

Tweeter has an inbuilt API. To access the API, authentication via HTTP Basic authentication (username and password) or via the session session cookie is necessary. The session cookie is issued on `/login`.

The following endpoints are available:

* `GET /api/files`

  Returns a json list with the names of all accessible files for the current user.

* `GET /api/files/<filename>`

  Retrieve the specified file if accessible by the current user.

* `GET /api/users`

  Requires administrative privilegies. Returns a list of all registered user with their id, name, and administrator status respectivley.

## Deployment

## Using Docker

Assuming `docker` and `docker-compose` are already installed, the app can simply be started with:

```bash
docker-compose up
```

When building the image, the database is initialized and seeded with the sample content.

## Native Deployment without Docker

Assuming that `python 2.7,` `pip`, and `openssl` are already installed. Optionally use `virtualenv` to create a new environment as well.

The following sequence of commands installs the needed requirements and sets the flask application

```bash
pip install -r requirements.txt
export FLASK_APP=run.py
```

Before the first start of the application, a SSL certificate needs to be created and the database needs to be initialized and optionally seeded.

### Create a self signed SSL certificate

Create a self-signed certificate on the command line.

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -batch
```

For production, please use a real certificate, not a self-signed one.

### Initialize Database

Set up or reset the database by invoking the following command in the root folder of the application. *This command will delete all content of the database.*

```bash
flask initdb
```

The following users created are:

| Name   | Password            | Administrator |
|--------|---------------------|---------------|
| root   | root                | yes           |
| admin  | admin               | yes           |
| Max    | max_password_123    | no            |
| Alex   | alex_password_123   | no            |
| Robert | robert_password_123 | no            |
| Anna   | anna_password_123   | no            |

### Seed Database

Initializes the database with some users, posts, and messages including image uploads. Execute the following command in the root folder of the application. *This command will delete all content of the database.*

```bash
flask seeddb
```

### Start the Application

To start the application, run the following command in the root folder of the application.

```bash
python run.py
```

Now the app will run on port 5000. Open a web browser and visit `https://127.0.0.1:5000`.
Please consider that when running the app from `localhost` rather than from the
IP address, CSP violation reports won't work. In this case, you will see an
error like following in the browser shell.

```
POST https://sentry.io/api/252244/csp-report/?sentry_key=f79b05a88e324c20ba590c4034680917 403 (FORBIDDEN)
```

The captcha on the register and login pages may not work correctly for Chrome versions < *v62.0.3202.94* because an experimental CSP policy is used. If you require compliance with older versions the CSP for inline styles may need to be changed to the more permissible and less secure `'unsafe-inline'`.

# Security Considerations

This section states the implemented security feautues. We list and comment the [Security Checklist](https://teaching.iaik.tugraz.at/akitsec2/checklist). All striken-through points are not implemented. Else, we considered it and implemented it in our application.

## XSS

* [1 point] Validate user input, e.g. white listing.
* [1 point] Sanitize user input.
  * Escape characters with special meaning before sending them back to the client.
  * Consider the context of where the user input will be displayed (e.g HTML tag vs URL parameter) and sanitize accordingly.
* [2 points] Use CSP Headers.
  * Disable inline scripts (If necessary, allow inline scripts with hashes or nonces).
  * Whitelist origins (e.g. script sources, style sources, image sources).
* [1 point] Protect cookies by setting HTTP only flag.
* [1 point] Make sure that none of the following contexts contain untrusted user data (reason: escaping can be tricky):
  * script tags : `<script>…[here]…</script>`
  * html comments : `<!–… [here]… –>`
  * html attribute names : `<div … [here]=“”>`
  * html tag names : `<[here] … />`
  * style tags : `<style>…[here]…</style>`

### Optional walls

* [1 FuzzyCoin] Set X-XSS-Protection HTTP header.
* [1 FuzzyCoin] CSP: Disable eval functions.
* [1 FuzzyCoin] Report CSP violations.
  * We report CSP violation to a [Sentry](https://sentry.io) instance. Sentry is a plattform to for real-time monitoring of errors. You can access the account on https://sentry.io/auth/login/ with the credentials `Account: robert.schilling@gmx.at` and password `PW: 0RMNsufTzUYwlEWT`. **Please do not change the password!**
* [0.5 FuzzyCoin] Using a less complex language for user input allows to use a less complex parser, which is less likely to have bugs and makes the input easier to sanitize.
  * We do not allow special languages such as markdown. Therfore, we avoid any vulnerabilities coming from a complex language parser.
* [0.5 FuzzyCoin] Limit the amount of Javascript frameworks (because they can enable DOM based XSS).
  * We only use the external javascript provided by [Bootstrap](https://getbootstrap.com), [jquery](https://jquery.com/), and [popper.js](https://popper.js.org/).

## Authentication

* [1 point] Secure password storage
  * Adaptive one-way function; e.g. Argon2, PBKDF2, scrypt. Salt the password (nonce, different for each user)
  * Passwords are hased using PBKDF2. A different salt is used for every user password.
* [1 point] Enforce reasonable password policy
  * No empty password, minimum length is 8 characters, only ASCII characters allowed.
  * Similarity to the username is measuerd. If they are too similar, the password is rejected.

### Optional walls

* [1 FuzzyCoin] Rate limiting with Google RECAPTCHA is implemented

## Authorization

* [2 points] Server-side checking for sufficient privileges on every request; e.g. session identifier, unguessable file links (for less sensitive resources)
  * Also protect static resources
* [1 point] Ask for password for sensitive requests
  * Following actions are protected by additional password requests:
    * User deletes his own account
    * Admin deletes another user
    * Admin promotes another user to an admin


## Session Management

* [3 points] Unique unguessable session identifier (cryptographically random, long enough) in cookie and state on server; or authenticated session state in cookie
  * Session cookie is 32 characters long (random) and gets signed with the application key for server-side date expiration
* [1 point] Cookies need to be protected
  * HttpOnly flag
  * Secure flag
  * Session cookie is set to `secure` and `HTTPOnly`
* [1 point] Check your deserialization. Only deserialize authenticated data. Alternative: Use e.g. JSON
  * We do not put anything inside the session cookie except the date. However, the cookie is signed and therefore, we can trust this value.

### Optional walls

* [1 FuzzyCoin] Set reasonable timeout for an active session on the server and for the cookie
  * Cookies have set an expiration time of 7 days for the client. Additionally, we support the expiration data on the server and do not accept cookies older than 7 days.
* [1 FuzzyCoin] Encrypt cookies which contain sensitive data
  * The cookie does not contain any sensitive data. However, we sign the cookie to detect any tampering. There, an attacker cannot change the expiration date.

## XSRF aka CSRF

* [2 points] Include a hidden form field in your form data (when performing requests that make changes on the server); either a “Shared CSRF Token”, or a “Double-submitted Cookie”. A “Shared CSRF Token” is an unpredictable random string/number, unique for every request of the form data, as hidden form field. A “Double-submitted cookie” is the output of a secure one-way function with the cookie value as input, e.g. SHA-512(Cookie), as hidden form field).
  * All requests that change the state of the server contain a hidden field for the unpredictable CSRF token.
* [1 point] Reauthentication for sensitive requests (e.g. password, 2nd factor)
  * We reauthenticate for critical requests like account deletion or user priviledge promotion.

## Deployment

* [1 point] Trusted third party for images of Docker container; official-tagged images (hub.docker.com) and/or source available (please argue)
  * We use the official python 2.7 image from hub.docker.com
* [1 point] Drop privileges of service inside the container (not running as root)
  * We are running the application under the `tweeter` user and application folder is owned by the `tweetergroup`

### Optional walls

* [1.5 FuzzyCoins] Encrypt your database (so that an attacker, who gets the database files, cannot do anything with it when not having the decryption key)
