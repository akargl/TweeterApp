from __future__ import print_function
import os
import sys
import sqlite3
import random
from flask import g
from app import app
from loremipsum import get_sentences


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
    # Delete the database file
    try:
        os.remove(app.config['DATABASE'])
    except OSError:
        pass

    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def print_dot():
    print('.', end='')
    sys.stdout.flush()


def seed_test_db():
    """ Seed the database for testing purpose """
    from models import Post, Message

    create_user('root', 'root', True)
    create_user('foo', 'mypassword', False)
    Post.create(1, 'My news', None)
    Message.create(2, 1, 'My message', None)


def seed_db():
    """ Seed the database """
    from models import Post, Message

    user_seed = [
        ('root', 'root', True),
        ('admin', 'admin', True),
        ('Max', 'max_password_123', False),
        ('Alex', 'alex_password_123', False),
        ('Robert', 'robert_password_123', False),
        ('Anna', 'anna_password_123', False),
    ]
    nr_public_posts = 100
    nr_private_posts = 100

    users = []
    print('Creating users')
    # Create users
    for u in user_seed:
        user = create_user(*u)
        if user:
            users.append(user) 
            print_dot()


    print('\nCreating public posts')
    # Create public posts for each user
    for i in range(nr_public_posts):
        # TODO: Manage uploads
        user = random.choice(users)
        sentence = ' '.join(get_sentences(random.randint(1, 4)))
        Post.create(user.id, sentence, None)
        print_dot()

    print('\nCreating private messages')
    for i in range(nr_public_posts):
        # TODO: Manage uploads
        random.shuffle(users)
        author = users[0]
        recipient = users[1]

        sentence = ' '.join(get_sentences(random.randint(1, 4)))
        Message.create(author.id, recipient.id, sentence, None)
        print_dot()

    print("")


def create_user(username, password, is_admin):
    # Import user only here to avoid a circular dependency
    from models import User

    salt, hashed_password = User.create_salt_and_hashed_password(password)
    user = User.create(username, salt, hashed_password, is_admin)
    print(user)
    return user


@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()


@app.cli.command('seeddb')
def seeddb_command():
    """ Seed the database with the default data """
    init_db()
    seed_db()


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
