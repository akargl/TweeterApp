import os
import re
import sqlite3
import hashlib
import time
from hmac import compare_digest
from base64 import b64encode
from werkzeug.utils import secure_filename
from db import query_db, insert_db
from app import app
from os import path


class User:
    # int id (Primary key)
    # str username
    # str password_token
    # bool is_admin
    MAX_USERNAME_LEN = 256
    MIN_PASSWORD_LEN = 8
    MAX_PASSWORD_LEN = 256

    SALT_LENGTH = 32
    HASH_ALGO = 'sha256'
    HASH_ITERATIONS = 10000

    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
        }

    @staticmethod
    def verify_credential_policy(username, password):
        """ Checks against the password policy """
        errors = []
        if len(username) < 1 or len(username) > User.MAX_USERNAME_LEN:
            errors.append('Length of username invalid. Maximum length: {:d}'.format(User.MAX_USERNAME_LEN))
        if len(password) < User.MIN_PASSWORD_LEN or len(password) > User.MAX_PASSWORD_LEN:
            errors.append('Invalid password length. Minimum length: {:d}, Maximum length: {:d}'.format(User.MIN_PASSWORD_LEN, User.MAX_PASSWORD_LEN))
        if not re.match("^[A-Za-z0-9_-]*$", username):
            errors.append('Username must only contain letters, numbers, and underscores')
        return errors

    @staticmethod
    def get_all():
        result = query_db('SELECT * from Users')
        users = []
        for r in result:
            users.append(User(r['id'], r['username'], bool(r['is_admin'])))
        return users

    @staticmethod
    def create_salt_and_hashed_password(password):
        salt = os.urandom(User.SALT_LENGTH)
        salt = b64encode(salt)

        return User.create_hashed_password(salt, password)

    @staticmethod
    def create_hashed_password(salt, password):
        hash_bytes = hashlib.pbkdf2_hmac(User.HASH_ALGO, password, salt, User.HASH_ITERATIONS)
        hashed_password = b64encode(hash_bytes)

        return salt, hashed_password

    @staticmethod
    def password_compare(a, b):
        # TODO: check if we aren't throwing away entropy here
        return compare_digest(a.decode('utf-8'), b.decode('utf-8'))

    @staticmethod
    def get_user_by_id(user_id):
        app.logger.debug("User::get_user_by_id called with {:d}".format(user_id))
        user_data = query_db('SELECT * from Users WHERE id = ?', [user_id], one=True)
        if user_data is None:
            return None
        return User(user_data['id'], user_data['username'], bool(user_data['is_admin']))

    @staticmethod
    def get_user_by_name(username):
        user_data = query_db('SELECT * from Users WHERE LOWER(username) = LOWER(?)', [username], one=True)
        if user_data is None:
            return None
        return User(user_data['id'], user_data['username'], user_data['is_admin'])

    @staticmethod
    def get_and_validate_user(username, hashed_password):
        user_data = query_db('SELECT * FROM Users WHERE LOWER(username) = LOWER(?)', [username], one=True)
        if user_data is None:
            return None
        if not User.password_compare(user_data['password_token'], hashed_password):
            return None
        return User(user_data['id'], user_data['username'], user_data['is_admin'])


    @staticmethod
    def get_salt(username):
        salt = query_db('SELECT password_salt FROM Users WHERE LOWER(username) = LOWER(?)', [username], one=True)
        if salt is None:
            return None
        return salt['password_salt']

    @staticmethod
    def create(username, salt, hashed_password, is_admin=False):
        #usernames are case insensitive so we need to check first regardless of unique constraint
        if User.get_user_by_name(username) is not None:
            return None
        try:
            result = insert_db('INSERT into Users (username, password_salt, password_token, is_admin) VALUES (?, ?, ?, ?)', [username, salt, hashed_password, int(is_admin)])
        except sqlite3.Error as e:
            app.logger.debug('sqlite3 error ' + e.message)
            return None
        if not result:
            return None
        return User.get_user_by_name(username)

    def delete(self):
        app.logger.debug("Delete user with id {:d}".format(self.id))
        # Delete user. All dependent data is deleted via database cascading
        insert_db('DELETE FROM Users WHERE id = ?', [self.id])

    def change_role(self, is_admin):
        if self.is_admin == is_admin:
            # Value does not change, nothing to do
            return
        try:
            insert_db('UPDATE Users SET is_admin = ? WHERE id = ?', [int(is_admin), self.id])
            self.is_admin = is_admin
        except sqlite3.Error as e:
            app.logger.debug('sqlite3 error ' + e.message)


class Post:
    # int id (Primary key)
    # int author_id -> User.id
    # str Content
    def __init__(self, author_id, content, attachment_name, timestamp):
        self.author_id = author_id
        self.content = content
        self.attachment_name = attachment_name
        self.timestamp = timestamp

    @staticmethod
    def get_posts_by_user_id(user_id):
        result = query_db('SELECT * from Posts WHERE author_id = ?', [user_id])
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r['attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def get_posts():
        result = query_db('SELECT * from Posts')
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r['attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def get_latest_posts(amount):
        result = query_db('SELECT * from Posts LIMIT ?', (amount,))
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r['attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def create(author_id, content, attachment_name=None):
        try:
            result = insert_db('INSERT into Posts (author_id, content, attachment_name, timestamp) VALUES (?, ?, ?, ?)', [author_id, content, attachment_name, int(time.time())])
        except sqlite3.Error as e:
            app.logger.debug('sqlite3 error ' + e.message)
            return None
        if not result:
            return None
        return True


class Message:
    # int id (Primary key)
    # int author_id -> User.id
    # int recipient_id -> User.id
    # str Content
    # str filename
    def __init__(self, author_id, recipient_id, content, filename, timestamp):
        self.author_id = author_id
        self.recipient_id = recipient_id
        self.content = content
        self.filename = filename
        self.timestamp = timestamp

    @staticmethod
    def get_messages_for_user_id(user_id):
        result = query_db('SELECT * from Messages WHERE recipient_id = ? OR author_id = ?', [user_id, user_id])
        messages = []
        for r in result:
            messages.append(Message(r['author_id'], r['recipient_id'], r['content'], r['filename'], r['timestamp']))
        return messages

    @staticmethod
    def create(author_id, recipient_id, content, filename=None):
        try:
            result = insert_db('INSERT into Messages (author_id, recipient_id, content, filename, timestamp) VALUES (?, ?, ?, ?, ?)', [author_id, recipient_id, content, filename, int(time.time())])
        except sqlite3.Error as e:
            app.logger.debug('sqlite3 error ' + e.message)
            return None
        if not result:
            return None
        return True


class Session:
    # int id (Primary key)
    # str session_token
    # int user_id -> User.id
    # TODO: Add namespace to SESSION_KEY
    SESSION_KEY = 'spring_session_key'
    TOKEN_LENGTH = 32

    @staticmethod
    def clear():
        users = User.get_all()
        for u in users:
            Session.delete_all(u.id)

    @staticmethod
    def active_user(session_token):
        app.logger.debug("Get active user")
        user_id = query_db('SELECT user_id from Sessions WHERE session_token = ?', [session_token], one=True)
        if user_id is None:
            return None
        return User.get_user_by_id(user_id['user_id'])

    @staticmethod
    def new_session(user):
        app.logger.debug("Create new session for user {:s}".format(user.username))
        session_token = os.urandom(Session.TOKEN_LENGTH)
        session_token = b64encode(session_token).decode('utf-8')
        result = insert_db('INSERT INTO Sessions (session_token, user_id) Values (?, ?)', [session_token, user.id])
        return result, session_token

    @staticmethod
    def delete(user_id, session_token):
        app.logger.debug("Delete session {:s} for user id {:d}".format(session_token, user_id))
        insert_db('DELETE FROM Sessions WHERE user_id = ? AND session_token = ?', [user_id, session_token])

    @staticmethod
    def delete_all(user_id):
        app.logger.debug("Delete all session for user id {:d}".format(user_id))
        insert_db('DELETE FROM Sessions WHERE user_id = ?', [user_id])


class FileWrapper:
    FILENAME_LENGTH = 32

    def __init__(self, fileId, extension, private, permittedUserIds):
        self.fileId = fileId
        self.extension = extension
        self.private = bool(private)
        self.permittedUserIds = permittedUserIds

    def get_filename(self):
        return str(self.fileId) + self.extension

    def get_storagepath(self):
        return os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], self.get_filename())

    @staticmethod
    def get_by_id(fileId):
        file_data = query_db('SELECT * from Files WHERE id = ?', [fileId], one=True)
        if not file_data:
            return None
        f_wrapper = FileWrapper(file_data['id'], file_data['extension'], file_data['private'], [])
        if f_wrapper.private:
            p_data = query_db('SELECT * from FilePermissions WHERE id = ?', [fileId])
            for p in p_data:
                f_wrapper.permittedUserIds.append(p['userId'])
        return f_wrapper

    @staticmethod
    def get_by_filename(filename):
        file_data = query_db('SELECT * from Files WHERE id || extension = ?', [filename], one=True)
        if not file_data:
            return None
        f_wrapper = FileWrapper(file_data['id'], file_data['extension'], file_data['private'], [])
        if f_wrapper.private:
            p_data = query_db('SELECT * from FilePermissions WHERE id = ?', [file_data['id']])
            for p in p_data:
                f_wrapper.permittedUserIds.append(p['userId'])
        return f_wrapper

    @staticmethod
    def is_allowed_file(file_):
        f_ext = path.splitext(file_.filename)[1]
        app.logger.debug("f_ext is" + f_ext)
        if f_ext.lower() not in app.config['ALLOWED_EXTENSIONS']:
            return False
        #TODO: check with imghdr
        return True

    @staticmethod
    def create(file_, private, permittedUserIds=[]):
        private = bool(private)
        if not FileWrapper.is_allowed_file(file_):
            return None
        f_ext = path.splitext(file_.filename)[1]
        try:
            fileId = insert_db('INSERT into Files (extension, private) VALUES (?, ?)', [f_ext, private])
        except sqlite3.Error as e:
            app.logger.debug('sqlite3 error while creating file in db:' + e.message)
            return None
        if not fileId:
            return None
        if private:
            for userId in permittedUserIds:
                insert_db('INSERT into FilePermissions (fileId, userId) VALUES (?, ?)', [fileId, userId])
        f_wrapper = FileWrapper(fileId, f_ext, private, permittedUserIds)
        storage_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], f_wrapper.get_filename())
        app.logger.debug("Saving attachment to {:s}".format(storage_path))
        file_.save(storage_path)
        return f_wrapper
