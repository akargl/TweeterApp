import os
import sqlite3
from flask import g
from app import app

DATABASE = 'database.db'

# Based on the flask sqlite tutorial
# (http://flask.pocoo.org/docs/0.12/patterns/sqlite3/)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    # Import user only here to avoid a circular dependency
    from models import User

    # Delete the database file
    try:
        os.remove('database.db')
    except OSError:
        pass

    init_db()
    print('Initialized the database.')
    username = 'root'
    password = 'root'
    salt, hashed_password = User.create_salt_and_hashed_password(password)
    User.create(username, salt, hashed_password, True)
    print('Admin user created: username: {:s}, password: {:s}'.format(username, password))


def query_db(query, args=(), one=False):
    # TODO: Exception handling?
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def insert_db(query, args=()):
    # TODO: Exception handling?
    cur = get_db().execute(query, args)
    get_db().commit()
    cur.close()
    return True


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
