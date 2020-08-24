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

Add your Rechaptcha and Sentry API Keys to config.py if you want to use them.

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


| Name   | Password            | TOTP Token       | Administrator |
|--------|---------------------|------------------|---------------|
| root   | root                | OLUZCVLVD2BKCBMP | yes           |
| admin  | admin               | 2NSG4USG6OYEQZP3 | yes           |
| Max    | max_password_123    | A3VDR4PZZYZDCAU7 | no            |
| Alex   | alex_password_123   | PMRJMUAUIPOGKUSV | no            |
| Robert | robert_password_123 | UYNKXN3BOBV2H2KG | no            |
| Anna   | anna_password_123   | 4XPLBU5GTDPT72H2 | no            |

The test users use a fixed OTP secret. Use Google authenticator or any other TOTP app to manually load the the secret to retrieve the 2FA-token.

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

### Mandatory walls

> [1 point] Validate user input, e.g. white listing.

Limited charset for username and password. See also below.

> [1 point] Sanitize user input.
> * Escape characters with special meaning before sending them back to the client.
> * Consider the context of where the user input will be displayed (e.g HTML tag vs URL parameter) and sanitize accordingly.

Possible user inputs:

* Username: Limited to alphanumeric characters.
* Password: Only the hash is saved.
* Session token & CSRF token: Signature is checked before further usage-
* File names of uploads: Renamed to numeric ID. Extension is only shown in the `Content-Disposition` header.
* File uploads: Images get checked with `imghdr`, other file types won't be shown directly.
* User posts and messages: Only shown as inner content of html elements. `&, <, \>, \\, '` and `/` are escaped beforehand.
* URL parameters such as file or user ids are all checked for being numeric only. 

> [2 points] Use CSP Headers.
> * Disable inline scripts (If necessary, allow inline scripts with hashes or nonces).
> * Whitelist origins (e.g. script sources, style sources, image sources).

We allow the following origins besides `'self'`:

* Fonts: `data:` (used by Bootstrap)
* Styles: Whitelist of hashes for inline styles used by Recaptcha. Chrome needs `'unsafe-hashed-attributes'` as well to accept this whitelist.
* Scripts: Whitelist with nonce for Recaptcha
* img: `data:` for Recaptcha
* `child-src`: Recaptcha support for legacy browsers

> [1 point] Protect cookies by setting HTTP only flag.

Done.

> [1 point] Make sure that none of the following contexts contain untrusted user data (reason: escaping can be tricky):
> * script tags : `<script>…[here]…</script>`
> * html comments : `<!–… [here]… –>`
> * html attribute names : `<div … [here]=“”>`
> * html tag names : `<[here] … />`
> * style tags : `<style>…[here]…</style>`

No user data is put into theses contexts.

### Optional walls

> [1 FuzzyCoin] Set X-XSS-Protection HTTP header.

Set to `1; mode=block`.

> [1 FuzzyCoin] CSP: Disable eval functions.

Implicitly disallowed with our settings for `script-src`.

> [1 FuzzyCoin] Report CSP violations.

We report CSP violation to a [Sentry](https://sentry.io) instance. Sentry is a plattform to for real-time monitoring of errors. You can access the account on https://sentry.io/auth/login/ with the credentials `Account: robert.schilling@gmx.at` and password `PW: 0RMNsufTzUYwlEWT`. **Please do not change the password!**

This only works if the app is accessed via `127.0.0.1`. CSP reporting does **not** work when accessing via `localhost`.

> [0.5 FuzzyCoin] Using a less complex language for user input allows to use a less complex parser, which is less likely to have bugs and makes the input easier to sanitize.

We do not allow special languages such as markdown. Therfore, we avoid any vulnerabilities coming from a complex language parser.

> [0.5 FuzzyCoin] Limit the amount of Javascript frameworks (because they can enable DOM based XSS).

We only use the external javascript provided by [Bootstrap](https://getbootstrap.com), [jquery](https://jquery.com/), and [popper.js](https://popper.js.org/).

## SQLi

### Mandatory walls

> [1 point] Sanitize user input, e.g. by type checking variables or whitelisting input.

Datatypes are check and cast if needed before insertion.

> [2 points] Parametrize queries with prepared statements.

All queries use prepared statements.

>[1 point] Apply principle of least privilege, e.g. by preventing the web app from performing DDL statements.

The web app doesn't use DDL-functions except for helper functions for seeding and database creation. These function can only be called via command line.

### Optional walls

> [1 FuzzyCoin] Use stored procedures (correctly).

Not possible with sqlite.

> [2 FuzzyCoins] Disable special functions in the DBMS (e.g. load_file, system).

Not possible with sqlite. Special, dangerous functions are generally only available in the sqlite command line.

> [1 FuzzyCoin] In general: Know your framework and what can it do for you!

We think we know it somewhat :)

## Authentication

### Mandatory walls

> [1 point] Secure password storage
> * Adaptive one-way function; e.g. Argon2, PBKDF2, scrypt. Salt the password (nonce, different for each user)

Passwords are hased using PBKDF2. A different, random salt is used for every user password.

> [1 point] Enforce reasonable password policy

* No empty password, minimum length is 8 characters, only ASCII characters allowed.
* Similarity to the username is measured. If they are too similar, the password is rejected.

### Optional walls

> 1 FuzzyCoin] Password reset; e.g. email or via token handed out when user registers

The user can reset their password via a password reset feature. The user receives a link with a password reset token to update the password. This token is valid for 1 hour. 

> [1 FuzzyCoin] Prevent brute forcing of passwords; e.g. via rate limiting or CAPTCHA

Google Recaptcha is used on registration and login pages.

> [2 FuzzyCoins] Use 2nd factor authentication; e.g. OTP or hardware token. Think about backup codes in case of loss of 2nd factor.

* We implement 2FA authentication based on TOTP.
* When registrating, the user can copy 5 recovery codes to get access in case of loss of the 2nd factor.

> ~~[2 FuzzyCoins] Use TLS in your web server, not the web app; e.g. via Let's Encrypt. For testing purposes, you can also use a self-signed certificate.~~

## Authorization

### Mandatory walls

> [2 points] Server-side checking for sufficient privileges on every request; e.g. session identifier, unguessable file links (for less sensitive resources). Also protect static resources.

Each request checks the permissions for the requested operation first. Only non-sensitive files such as CSS and JS served as static ressources.

> [1 point] Ask for password for sensitive requests

Following actions are protected by additional password requests:

* User deletes his own account
* Admin deletes another user
* Admin promotes another user to an admin

### Optional walls

> [2 FuzzyCoins] Define access control policy (written form)

The follwoing endpoints are available. The roles User and Admin require authentication.

| Endpoint                  | Guest | User | Admin |
|---------------------------|-------|------|-------|
| `GET /`                   |       | x    | x     |
| `POST /`                  |       | x    | x     |
| `GET /login`              | x     |      |       |
| `POST /login`             | x     |      |       |
| `POST /logout`            |       | x    | x     |
| `GET /register`           | x     |      |       |
| `POST /register`          | x     |      |       |
| `GET /deregister`         |       | x    | x     |
| `POST /deregister`        |       | x    |       |
| `GET /messages`           |       | x    | x     |
| `POST /messages`          |       | x    | x     |
| `GET /administration`     |       |      | x     |
| `PUT /user/<id> `         |       |      | x     |
| `DELETE /user/<id> `      |       |      | x     |
| `GET /api/files`          |       | x    | x     |
| `GET /api/files/<fileid>` |       | x    | x     |
| `GET /api/users`          |       |      | x     |
| `GET /static/*`           | x     | x    | x     |

## Session Management

### Mandatory walls

> [3 points] Unique unguessable session identifier (cryptographically random, long enough) in cookie and state on server; or authenticated session state in cookie

Session cookie is 32 characters long (random) and gets signed with the application key for server-side date expiration.

> [1 point] Cookies need to be protected
> * HttpOnly flag
> * Secure flag

Session (and CSRF) cookie is set to `secure` and `HTTPOnly`.

> [1 point] Check your deserialization. Only deserialize authenticated data. Alternative: Use e.g. JSON

We do not put anything inside the session cookie except the identifier and a timestamp. 
However, the cookie is signed and therefore, we can trust this value.

### Optional walls

> [1 FuzzyCoin] Set reasonable timeout for an active session on the server and for the cookie

Cookies have set an expiration time of 7 days for the client. Additionally, we check the (signed) timestamp contained within the cookie and reject these expired sessions.

THe CSRF cookie has a timeout of one hour.

> [1 FuzzyCoin] Encrypt cookies which contain sensitive data

The cookie does not contain any sensitive data. However, we sign the cookie to detect any tampering. Therefore an attacker cannot change the expiration date.

## XSRF aka CSRF

### Mandatory walls

> [2 points] Include a hidden form field in your form data (when performing requests that make changes on the server); either a “Shared CSRF Token”, or a “Double-submitted Cookie”. A “Shared CSRF Token” is an unpredictable random string/number, unique for every request of the form data, as hidden form field. A “Double-submitted cookie” is the output of a secure one-way function with the cookie value as input, e.g. SHA-512(Cookie), as hidden form field).

All requests that change the state of the server contain a hidden field for the unpredictable CSRF token. Unauthenticated endpoints such as login or register are secured by a double submit cookie.

> [1 point] Reauthentication for sensitive requests (e.g. password, 2nd factor)

We require reauthenticate for critical requests like account deletion or user priviledge promotion.

### Optional walls

> ~~[0.5 FuzzyCoin] Check 'referer' in HTTP request~~

## Deployment

### Mandatory walls

> [1 point] Trusted third party for images of Docker container; official-tagged images (hub.docker.com) and/or source available (please argue)

We use the official python 2.7 image from hub.docker.com

> [1 point] Drop privileges of service inside the container (not running as root)

We are running the application under the `tweeter` user and application folder is owned by the `tweetergroup`.

### Optional walls

> ~~[2 FuzzyCoins] Apply and watch (reasonable) logging & monitoring.~~

> [1.5 FuzzyCoins] Encrypt your database (so that an attacker, who gets the database files, cannot do anything with it when not having the decryption key)

We use pysqlcipher to encrypt the database.
