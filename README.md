# Tweeter

Tweeter is a simple microblogging app. Users can share text and image files (.png, .jpg, .jpeg) with either a single or all registered users. Administrators can delete users and grant them administration priviliges.

## API

To use the API authentication either via a session cookie issued on login (*/login*) or HTTP Basic authentication is necessary.

The following endpoints are available:

* GET */api/files*

  Returns a json list with the names of all accessible files for the current user

* GET */api/files/\<filename\>*

  Retrieve the specified file if accessible by the current user

* GET */api/users*

  Requires administrative privilegies. Returns a list of all registered user with their id, name and administrator status respectivley.

## Startup

* ### using Docker

  Assuming *docker* and *docker-compose* are installed already the app can simply be started with:

  ```sh
  docker-compose up
  ```

* ### without Docker

  Assuming *python* and *pip* are already installed. Optionally use *virtualenv* to create a new environment as well.

  ```sh
  pip install -r requirements.txt # Install the needed python packages
  export FLASK_APP=run.py # set necessary environment variable for flask
  flask run # start app
  ```

Now the app will run on port 5000.

## Initial setup

Set up or reset the database:

```sh
flask initdb
```

Fill the database with some users, posts and messages:

```sh
flask seeddb
```

The users created are:

| Name   | Password            | Administrator |
|--------|---------------------|---------------|
| root   | root                | yes           |
| admin  | admin               | yes           |
| Max    | max_password_123    | no            |
| Alex   | alex_password_123   | no            |
| Robert | robert_password_123 | no            |
| Anna   | anna_password_123   | no            |
