# -*- encoding: utf-8 -*-

import os
import json
import tempfile
import pytest
import time
from StringIO import StringIO
from base64 import b64encode
from werkzeug.datastructures import FileStorage
from app import app, db, models


dir_path = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['DEBUG'] = True
    app.config['UPLOAD_FOLDER'] = os.path.join(dir_path, tempfile.mkdtemp())
    # Disable CSRF for testing
    app.config['CSRF_METHODS'] = []
    # No Recaptcha
    app.config['RECAPTCHA_ENABLED'] = False
    client = app.test_client()

    with app.app_context():
        db.init_db()
        db.seed_test_db()

        yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def read_file(filename):
    dir_path = os.path.dirname(os.path.realpath(__file__))

    with open(os.path.join(dir_path, filename)) as f:
        return StringIO(f.read())


def upload_file(filename):
    panda_path = os.path.join(dir_path, "test_data", filename)
    with open(panda_path, 'rb') as f:
        panda_file = FileStorage(f)
        models.FileWrapper.create(panda_file, [1], False)


def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)


def logout(client):
    return client.get('/logout', follow_redirects=True)


def http_basic_headers(username, password):
    return { 'Authorization' : 'Basic ' + b64encode("{:s}:{:s}".format(username, password)) }


def test_database_cascading(client):
    db.create_user('foobar', 'foobar', False)
    u = models.User.get_user_by_name('foobar')
    models.Post.create(u.id, 'foo', None)
    models.Post.create(u.id, 'foo bar', None)

    # Deleting the user needs to delete all depending rows in other tables
    u.delete()

    assert len(models.Post.get_posts_by_user_id(u.id)) == 0


def test_seed_db(client):
    db.seed_db()

    assert len(models.User.get_all()) > 3
    assert len(models.Post.get_all()) > 50


def test_unauthenticated_url_points_to_login(client):
    auth_urls_get = [
        '/',
        '/messages',
        '/deregister'
    ]

    for url in auth_urls_get:
        response = client.get(url, follow_redirects=True)
        assert b'Login' in response.data

    auth_urls_post = [
        '/logout',
        '/deregister'
    ]

    for url in auth_urls_post:
        response = client.post(url, follow_redirects=True)
        assert b'Login' in response.data


def test_successful_login(client):
    response = login(client, 'root', 'root')
    assert b'Logged in as root' in response.data


def test_already_logged_in(client):
    login(client, 'root', 'root')
    response = login(client, 'root', 'root')
    assert response.status_code == 200
    assert b'Logged in as root' in response.data


def test_successful_login_case_sensitivity(client):
    response = login(client, '  ROOT ', 'root')
    assert b'Logged in as root' in response.data


def test_wrong_username_login(client):
    response = login(client, 'foobar', 'root')
    print response.data
    assert b'Invalid Login or password' in response.data


def test_wrong_password_login(client):
    response = login(client, 'root', 'bar')
    assert b'Invalid Login or password' in response.data


def test_logout(client):
    login(client, 'root', 'root')
    response = client.post('/logout')
    assert response.status_code == 204


def test_get_register(client):
    response = client.get('/register')
    assert b'Register' in response.data


def test_successful_register(client):
    response = client.post('/register', data=dict(
        username='myuser',
        password='MyPassWord'
    ), follow_redirects=True)
    assert b'Login' in response.data
    assert models.User.get_user_by_name('myuser')


def test_password_same_as_the_username_register(client):
    response = client.post('/register', data=dict(
        username='mynewuser',
        password='mynewuser'
    ), follow_redirects=True)
    assert b'Password cannot be the same or similar as the username' in response.data


def test_password_similar_as_the_username_register(client):
    response = client.post('/register', data=dict(
        username='mynewuser',
        password='mynewuser1'
    ), follow_redirects=True)
    assert b'Password cannot be the same or similar as the username' in response.data


def test_password_reject_non_ascii_register(client):
    response = client.post('/register', data=dict(
        username='mynewuser',
        password=u'My-Emoji-Password 👍'
    ), follow_redirects=True)
    assert b'Password cannot contain non-ASCII characters' in response.data


def test_register_no_form_data(client):
    response = client.post('/register')
    assert response.status_code == 400


def test_register_user_already_exists(client):
    response = client.post('/register', data=dict(
        username='root',
        password='MyPassWord'
    ))
    assert b'User already exists' in response.data


def test_register_user_already_exists_case_sensitivity(client):
    response = client.post('/register', data=dict(
        username='ROOT',
        password='MyPassWord'
    ))
    assert b'User already exists' in response.data


def test_register_no_username(client):
    response = client.post('/register', data=dict(
        username='',
        password='MyPassWord'
    ))
    assert b'Length of username invalid' in response.data


def test_register_invalid_username(client):
    response = client.post('/register', data=dict(
        username='user/foo',
        password='MyPassWord'
    ))
    assert b'Username must only contain letters, numbers, and underscores' in response.data


def test_register_no_password(client):
    response = client.post('/register', data=dict(
        username='myuser',
        password=''
    ))
    assert b'Invalid password length' in response.data


def test_register_already_logged_in(client):
    login(client, 'root', 'root')

    response = client.post('/register', data=dict(
        username='myuser',
        password='MyPassWord'
    ), follow_redirects=True)
    assert b'Logged in as root' in response.data
    assert models.User.get_user_by_name('myuser') == None


def test_register_too_short_password(client):
    response = client.post('/register', data=dict(
        username='myuser',
        password='root'
    ))
    assert b'Invalid password length' in response.data

def test_get_deregister(client):
    login(client, 'root', 'root')

    response = client.get('/deregister')

    assert response.status_code == 200
    assert b'Please enter your password to delete your account' in response.data

def test_deregister_no_password(client):
    login(client, 'root', 'root')

    response = client.post('/deregister')

    assert response.status_code == 400


def test_deregister_wrong_password(client):
    login(client, 'root', 'root')

    response = client.post('/deregister', data=dict(
        user_password='foo'
    ))

    assert response.status_code == 200
    assert b'Invalid password' in response.data

def test_deregister(client):
    login(client, 'root', 'root')

    response = client.post('/deregister', data=dict(
        user_password='root'
    ))

    assert response.status_code == 302
    assert models.User.get_user_by_name('root') is None


def test_get_posts(client):
    login(client, 'root', 'root')

    response = client.get('/')

    assert response.status_code == 200
    assert b'My news' in response.data


def test_post_feed(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        post_content='My new Post'
    ))

    assert response.status_code == 201
    assert b'My new Post' in response.data


def test_post_feed_no_content(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        post_content=""
    ))

    assert response.status_code == 200
    assert b"Post can&#x27;t be empty" in response.data


def test_post_too_long_content(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        post_content="1" * (models.MAX_CONTENT_LENGTH + 1)
    ))

    assert response.status_code == 200
    assert b"Could not create post" in response.data


def test_post_content_and_file(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (read_file('test_data/panda.png'), 'panda.png')},
        post_content='My new Post'
    ))

    assert response.status_code == 201
    assert b'My new Post' in response.data
    assert b'/api/files/1' in response.data


def test_post_non_image_file(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (StringIO('my file'), 'foo.bar')},
        post_content='My binary post'
    ))
    assert response.status_code == 201
    assert b'My binary post' in response.data
    assert b'/api/files/1' in response.data


def test_post_twice_same_data(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (read_file('test_data/panda.png'), 'panda.png')},
        post_content='My new Post'
    ))
    response = client.post('/', data=dict(
        {'attachment': (read_file('test_data/panda.png'), 'panda.png')},
        post_content='My new Post'
    ))

    assert response.status_code == 201
    assert response.data.count('My new Post') == 2
    assert b'/api/files/1' in response.data
    assert b'/api/files/2' in response.data


def test_post_wrong_file_format(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (StringIO('my file'), 'panda.png')},
        post_content='My new Post'
    ))
    assert response.status_code == 200
    assert b'Malformed image' in response.data


def test_post_no_content_given(client):
    login(client, 'root', 'root')

    response = client.post('/')

    assert response.status_code == 400


def test_get_messages(client):
    login(client, 'root', 'root')

    response = client.get('/messages')

    assert response.status_code == 200
    assert b'My message' in response.data


def test_send_message(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        message_recipient="foo",
        message_content="My new message"
    ))

    assert response.status_code == 201
    messages = models.Message.get_messages_for_user_id(2)
    assert len(messages) == 2


def test_send_message_content_and_file(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        {'attachment': (read_file('test_data/panda.png'), 'panda.png')},
        message_recipient="foo",
        message_content="My binary message"
    ))

    assert response.status_code == 201
    assert b'My binary message' in response.data
    assert b'/api/files/1' in response.data
    assert b'<img' in response.data


def test_send_message_non_image_file(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        {'attachment': (StringIO('my file'), 'foo.bar')},
        message_recipient="foo",
        message_content="My binary message"
    ))

    assert response.status_code == 201
    assert b'My binary message' in response.data
    assert b'/api/files/1' in response.data
    assert b'<img' not in response.data


def test_send_message_wrong_file_format(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (StringIO('my file'), 'panda.png')},
        post_content='My new Post'
    ))
    assert response.status_code == 200
    assert b'Malformed image' in response.data


def test_send_message_no_params(client):
    login(client, 'root', 'root')

    response = client.post('/messages')

    assert response.status_code == 400


def test_send_message_unknown_recipient(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        message_recipient="fo1o",
        message_content="My new message"
    ))

    assert response.status_code == 200
    assert b'Unknown recipient' in response.data


def test_send_message_no_content(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        message_recipient="foo",
        message_content=""
    ))

    assert response.status_code == 200
    assert b"Message can&#x27;t be empty" in response.data


def test_send_message_too_long_content(client):
    login(client, 'root', 'root')

    response = client.post('/messages', data=dict(
        message_recipient="foo",
        message_content="1" * (models.MAX_CONTENT_LENGTH + 1)
    ))

    assert response.status_code == 200
    assert b"Could not create message" in response.data


def test_api_unauthorized(client):
    data = [
        {},
        { 'username' : 'foo' },
        { 'password' : 'password' }
    ]
    endpoints = [
        '/api/files',
        '/api/files/1',
        '/api/users'
    ]
    for e in endpoints:
        for d in data:
            response = client.get(e, data=d)
            assert response.status_code == 401


def test_api_no_headers(client):
    endpoints = [
        '/api/users',
        '/api/files/1',
        '/api/users'
    ]
    for e in endpoints:
        response = client.get(e)
        assert response.status_code == 401


def test_api_wrong_credentials(client):
    data = [
        { 'username' : 'foo', 'password' : 'root' },
        { 'username' : 'root', 'password' : 'password' }
    ]
    endpoints = [
        '/api/users',
        '/api/files/1',
        '/api/users'
    ]
    for e in endpoints:
        for d in data:
            response = client.get(e, headers=http_basic_headers(d['username'], d['password']))
            assert response.status_code == 401


def test_api_get_files(client):
    upload_file("panda.png")
    upload_file("panda.jpg")

    response = client.get('/api/files', headers=http_basic_headers('root', 'root'))

    assert response.status_code == 200
    assert response.content_type == 'application/json'
    data = json.loads(response.get_data())
    assert len(data) == 2


def test_api_valid_file_access(client):
    files = [
        'panda.png',
        'panda.jpg',
        'panda.jpeg',
    ]
    for i, f in enumerate(files):
        upload_file(f)

        route = '/api/files/{:d}'.format(i+1)
        print route
        response = client.get(route, headers=http_basic_headers('root', 'root'))

        assert response.status_code == 200


def test_api_get_users(client):
    response = client.get('/api/users', headers=http_basic_headers('root', 'root'))

    assert response.status_code == 200
    assert response.content_type == 'application/json'
    data = json.loads(response.get_data())
    assert len(data) == 2
    assert data[0]['id'] == 1
    assert data[0]['username'] == 'root'
    assert data[0]['is_admin'] == True

    assert data[1]['id'] == 2
    assert data[1]['username'] == 'foo'
    assert data[1]['is_admin'] == False


def test_api_get_users_no_admin(client):
    response = client.get('/api/users', headers=http_basic_headers('foo', 'mypassword'))
    assert response.status_code == 401


def test_administration_normal_user(client):
    login(client, 'foo', 'mypassword')

    response = client.get('/administration')
    assert response.status_code == 401


def test_administration_admin_user(client):
    login(client, 'root', 'root')

    response = client.get('/administration')
    assert response.status_code == 200


def test_update_user_no_admin(client):
    login(client, 'foo', 'mypassword')

    response = client.put('/users/2', data=dict({ 'is_admin': '1' }))
    assert response.status_code == 401


def test_update_user_not_existing(client):
    login(client, 'root', 'root')

    response = client.put('/users/9999', data=dict({ 'is_admin': '1', 'password' : 'root' }))
    assert response.status_code == 404


def test_update_user_admin(client):
    login(client, 'root', 'root')

    response = client.put('/users/2', data=dict({ 'is_admin': '1', 'password' : 'root' }))

    assert response.status_code == 204
    assert models.User.get_user_by_id(2).is_admin


def test_delete_user_no_admin(client):
    login(client, 'foo', 'mypassword')

    response = client.delete('/users/2')
    assert response.status_code == 401


def test_delete_user_not_existing(client):
    login(client, 'root', 'root')

    response = client.delete('/users/9999', data=dict({ 'password' : 'root'}))
    assert response.status_code == 404


def test_delete_user_admin(client):
    login(client, 'root', 'root')

    response = client.delete('/users/2', data=dict({ 'password' : 'root'}))

    assert response.status_code == 204
    assert models.User.get_user_by_id(2) == None


def test_session_expiry(client):
    app.config['MAX_SESSION_AGE'] = 3

    login(client, 'root', 'root')

    time.sleep(4)
    response = client.post('/', follow_redirects=True)

    assert b'Login' in response.data
