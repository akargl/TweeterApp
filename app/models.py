import os
import re
import hashlib
import time
import imghdr
from hmac import compare_digest
from base64 import b64encode
from werkzeug.utils import secure_filename
from werkzeug.security import safe_str_cmp, DEFAULT_PBKDF2_ITERATIONS
from itsdangerous import URLSafeTimedSerializer, BadData, SignatureExpired
from db import query_db, insert_db
from app import app
from os import path
from difflib import SequenceMatcher


MAX_CONTENT_LENGTH = 4 * 140


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
    HASH_ITERATIONS = 50000

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
    def similar(a, b):
        return SequenceMatcher(None, a, b).ratio()

    @staticmethod
    def contains_non_ascii(s):
        return any(ord(c) >= 128 for c in s)

    @staticmethod
    def verify_credential_policy(username, password):
        """ Checks against the password policy """
        errors = []
        if len(username) < 1 or len(username) > User.MAX_USERNAME_LEN:
            errors.append(
                'Length of username invalid. Maximum length: {:d}'.format(
                    User.MAX_USERNAME_LEN))
        if len(password) < User.MIN_PASSWORD_LEN or len(
                password) > User.MAX_PASSWORD_LEN:
            errors.append(
                'Invalid password length. Minimum length: {:d}, Maximum length: {:d}'.format(
                    User.MIN_PASSWORD_LEN, User.MAX_PASSWORD_LEN))
        if User.similar(username, password) > 0.8:
            errors.append('Password cannot be the same or similar as the username')
        if User.contains_non_ascii(password):
            errors.append('Password cannot contain non-ASCII characters')
        if not re.match("^[A-Za-z0-9_-]*$", username):
            errors.append(
                'Username must only contain letters, numbers, and underscores')
        return errors

    @staticmethod
    def get_all():
        result = query_db('SELECT * from Users')
        if not result:
            return []
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
        hash_bytes = hashlib.pbkdf2_hmac(
            User.HASH_ALGO, password, salt, User.HASH_ITERATIONS)
        hashed_password = b64encode(hash_bytes)

        return salt, hashed_password

    @staticmethod
    def password_compare(a, b):
        return safe_str_cmp(a.decode('utf-8'), b.decode('utf-8'))

    @staticmethod
    def check_password(username, password):
        salt = User.get_salt(username)
        if not salt:
            return None

        _, hashed_password = User.create_hashed_password(salt, password)
        user = User.get_and_validate_user(username, hashed_password)

        if not user:
            return None
        return user

    @staticmethod
    def get_user_by_id(user_id):
        app.logger.debug(
            "User::get_user_by_id called with {:d}".format(user_id))
        user_data = query_db(
            'SELECT * from Users WHERE id = ?', [user_id], one=True)
        if user_data is None:
            return None
        return User(user_data['id'], user_data[
                    'username'], bool(user_data['is_admin']))

    @staticmethod
    def get_user_by_name(username):
        user_data = query_db(
            'SELECT * from Users WHERE LOWER(username) = LOWER(?)',
            [username],
            one=True)
        if user_data is None:
            return None
        return User(user_data['id'], user_data[
                    'username'], user_data['is_admin'])

    @staticmethod
    def get_and_validate_user(username, hashed_password):
        user_data = query_db(
            'SELECT * FROM Users WHERE LOWER(username) = LOWER(?)',
            [username],
            one=True)
        if user_data is None:
            return None
        if not User.password_compare(
                user_data['password_token'], hashed_password):
            return None
        return User(user_data['id'], user_data[
                    'username'], user_data['is_admin'])

    @staticmethod
    def get_salt(username):
        salt = query_db(
            'SELECT password_salt FROM Users WHERE LOWER(username) = LOWER(?)',
            [username],
            one=True)
        if salt is None:
            return None
        return salt['password_salt']

    @staticmethod
    def create(username, salt, hashed_password, is_admin=False):
        # usernames are case insensitive so we need to check first regardless
        # of unique constraint
        if User.get_user_by_name(username):
            app.logger.debug("User already exists")
            return None
        result = insert_db(
            'INSERT into Users (username, password_salt, password_token, is_admin) VALUES (?, ?, ?, ?)', [
                username, salt, hashed_password, int(is_admin)])
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

        result = insert_db('UPDATE Users SET is_admin = ? WHERE id = ?', [
                           int(is_admin), self.id])
        if not result:
            return None
        self.is_admin = is_admin
        return True


class Post:
    def __init__(self, author_id, content, attachment_name, timestamp):
        self.author_id = author_id
        self.content = content

        split = path.splitext(attachment_name if attachment_name else '')
        self.attachment_name = split[0]
        self.extension = split[1] 

        self.timestamp = timestamp

    def has_file(self):
        return self.attachment_name is not ''

    def is_image(self):
        if not self.attachment_name:
            return False
        file_extension = path.splitext(self.attachment_name)[1]
        return self.extension.lower() in app.config['IMAGE_EXTENSIONS']

    @staticmethod
    def get_posts_by_user_id(user_id):
        result = query_db('SELECT * from Posts WHERE author_id = ?', [user_id])
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r[
                         'attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def get_all():
        result = query_db('SELECT * from Posts ORDER BY timestamp DESC')
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r[
                         'attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def get_latest_posts(amount):
        result = query_db('SELECT * from Posts LIMIT ?', (amount,))
        posts = []
        for r in result:
            posts.append(Post(r['author_id'], r['content'], r[
                         'attachment_name'], r['timestamp']))
        return posts

    @staticmethod
    def create(author_id, content, attachment_name):
        if len(content) > MAX_CONTENT_LENGTH:
            return None
        result = insert_db(
            'INSERT into Posts (author_id, content, attachment_name, timestamp) VALUES (?, ?, ?, ?)', [
                author_id, content, attachment_name, int(
                    time.time())])
        if not result:
            return None
        return True


class Message:
    def __init__(self, author_id, recipient_id,
                 content, attachment_name, timestamp):
        self.author_id = author_id
        self.recipient_id = recipient_id
        self.content = content

        split = path.splitext(attachment_name if attachment_name else '')
        self.attachment_name = split[0]
        self.extension = split[1] 

        self.timestamp = timestamp

    def has_file(self):
        return self.attachment_name is not ''

    def is_image(self):
        if not self.attachment_name:
            return False
        return self.extension.lower() in app.config['IMAGE_EXTENSIONS']

    @staticmethod
    def get_messages_for_user_id(user_id):
        result = query_db(
            'SELECT * from Messages WHERE recipient_id = ? OR author_id = ? ORDER BY timestamp DESC',
            [
                user_id,
                user_id])
        messages = []
        for r in result:
            messages.append(Message(r['author_id'], r['recipient_id'], 
                                    r['content'], r['filename'], r['timestamp']))
        return messages

    @staticmethod
    def create(author_id, recipient_id, content, attachment_name=None):
        if len(content) > MAX_CONTENT_LENGTH:
            return None
        result = insert_db(
            'INSERT into Messages (author_id, recipient_id, content, filename, timestamp) VALUES (?, ?, ?, ?, ?)', [
                author_id, recipient_id, content, attachment_name, int(
                    time.time())])
        if not result:
            return None
        return True


class Session:
    SESSION_KEY = 'spring_session_key'
    CSRF_KEY = 'spring_csrf_token'
    TOKEN_LENGTH = 32

    @staticmethod
    def clear():
        users = User.get_all()
        for u in users:
            Session.delete_all(u.id)

    @staticmethod
    def active_user(session_token):
        app.logger.debug("Get active user")
        data = query_db(
            'SELECT user_id, csrf_token from Sessions WHERE session_token = ?',
            [session_token],
            one=True)
        if data is None:
            return None, None

        try:
            signer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            signer.loads(session_token, max_age=app.config['MAX_SESSION_AGE'])
        except SignatureExpired:
            Session.delete(data['user_id'], session_token)
            return None, None
        except BadData:
            Session.delete(data['user_id'], session_token)
            return None, None

        return User.get_user_by_id(data['user_id']), data['csrf_token']

    @staticmethod
    def create_csrf_token():
        signer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        csrf_token = os.urandom(Session.TOKEN_LENGTH)
        csrf_token = b64encode(csrf_token).decode('utf-8')
        csrf_token = signer.dumps(csrf_token)
        return csrf_token

    @staticmethod
    def new_session(user):
        app.logger.debug(
            "Create new session for user {:s}".format(user.username))
        session_token = os.urandom(Session.TOKEN_LENGTH)
        session_token = b64encode(session_token).decode('utf-8')
        signer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

        session_token = signer.dumps(session_token)
        csrf_token = Session.create_csrf_token()

        result = insert_db(
            'INSERT INTO Sessions (session_token, user_id, csrf_token) Values (?, ?, ?)', [
                session_token, user.id, csrf_token])
        return result, session_token, csrf_token

    @staticmethod
    def delete(user_id, session_token):
        insert_db(
            'DELETE FROM Sessions WHERE user_id = ? AND session_token = ?', [
                user_id, session_token])

    @staticmethod
    def delete_all(user_id):
        app.logger.debug("Delete all session for user id {:d}".format(user_id))
        insert_db('DELETE FROM Sessions WHERE user_id = ?', [user_id])


class FileWrapper:
    FILENAME_LENGTH = 32

    def __init__(self, file_id, extension, private):
        self.file_id = file_id
        self.extension = extension
        self.private = bool(private)

    def get_filename(self):
        return str(self.file_id) + self.extension

    def get_storagepath(self):
        return os.path.join(app.root_path, app.config[
                            'UPLOAD_FOLDER'], self.get_filename())

    def serialize(self):
        return {
            'id': str(self.file_id)
        }

    @staticmethod
    def is_valid_file(attachment):
        if os.path.islink(attachment.filename):
            app.logger.debug('Symlink is not a valid file')
            return ['Malformed image']

        file_extension = path.splitext(attachment.filename)[1]
        app.logger.debug("file_extension is" + file_extension)
        if file_extension.lower() in app.config['IMAGE_EXTENSIONS']:
            # If we have an image extension, check if it is really in image
            attachment.seek(0)
            imghdr_type = imghdr.what(None, attachment.read())
            attachment.seek(0)
            if '.' + str(imghdr_type) not in app.config['IMAGE_EXTENSIONS']:
                app.logger.debug('Invalid file extenion: {:s}'.format(str(imghdr_type)))
                return ['Malformed image']
        return []

    @staticmethod
    def get_files(user_id):
        file_data = query_db(
            'SELECT * FROM Files file INNER JOIN FilePermissions permission ON file.id = permission.file_id WHERE (permission.user_id = ? or file.private=0)',
            [user_id])
        if not file_data:
            return []

        files = []
        for f in file_data:
            wrapper = FileWrapper(f['id'], f['extension'], f['private'])
            files.append(wrapper)
        return files

    @staticmethod
    def get_by_filename(filename, user_id):
        file_data = query_db(
            'SELECT * from Files file INNER JOIN FilePermissions permission ON file.id = permission.file_id WHERE (id || extension = ? and (permission.user_id = ? or file.private=0))',
            [
                filename,
                user_id],
            one=True)
        if not file_data:
            return None

        f_wrapper = FileWrapper(file_data['id'], file_data[
                                'extension'], file_data['private'])
        return f_wrapper

    @staticmethod
    def get_by_id(file_id, user_id):
        file_data = query_db(
            'SELECT * from Files file INNER JOIN FilePermissions permission ON file.id = permission.file_id WHERE (id = ? and (permission.user_id = ? or file.private=0))',
            [
                file_id,
                user_id],
            one=True)
        if not file_data:
            return None

        f_wrapper = FileWrapper(file_data['id'], file_data['extension'], 
                                file_data['private'])
        return f_wrapper

    @staticmethod
    def create(imgfile, permitted_user_ids, private):
        errors = FileWrapper.is_valid_file(imgfile)
        if len(errors):
            return None

        f_ext = path.splitext(imgfile.filename)[1]
        file_id = insert_db(
            'INSERT into Files (extension, private) VALUES (?, ?)', [
                f_ext, bool(private)])
        if not file_id:
            return None
        for user_id in permitted_user_ids:
            status = insert_db(
                'INSERT into FilePermissions (file_id, user_id) VALUES (?, ?)', [
                    file_id, user_id])
            if not status:
                return None

        f_wrapper = FileWrapper(file_id, f_ext, private)

        storage_path = os.path.join(app.root_path, app.config[
                                    'UPLOAD_FOLDER'], f_wrapper.get_filename())
        app.logger.debug("Saving attachment to {:s}".format(storage_path))
        imgfile.save(storage_path)
        return f_wrapper
