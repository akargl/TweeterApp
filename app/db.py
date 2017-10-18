import os
import sqlite3
from flask import g
from app import app


# Based on the flask sqlite tutorial
# (http://flask.pocoo.org/docs/0.12/patterns/sqlite3/)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        query_db('PRAGMA foreign_keys = ON')
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def create_user(username, password, is_admin):
    # Import user only here to avoid a circular dependency
    from models import User

    salt, hashed_password = User.create_salt_and_hashed_password(password)
    User.create(username, salt, hashed_password, is_admin)
    print('User created: username: {:s}, password: {:s}, is_admin: {:d}'.format(username, password, is_admin))


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    # Delete the database file
    try:
        os.remove('database.db')
    except OSError:
        pass

    init_db()
    print('Initialized the database.')

    # TODO: Sample content
    create_user('root', 'root', True)
    create_user('root1', 'root1', False)


def query_db(query, args=(), one=False):
    try:
        cur = get_db().execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        app.logger.debug('sqlite3 error ' + e.message)
        return None


def insert_db(query, args=()):
    try:
        cur = get_db().execute(query, args)
        get_db().commit()
        lastId = cur.lastrowid
        cur.close()
        return lastId
    except sqlite3.Error as e:
        app.logger.debug('sqlite3 error ' + e.message)
        return None


@app.before_first_request
def clear_sessions():
    from models import Session
    Session.clear()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
