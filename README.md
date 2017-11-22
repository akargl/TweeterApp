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
flask run
```

Now the app will run on port 5000. Open a webbrowser and visit `https://localhost:5000`.
