import os
import json
import tempfile
import pytest
from StringIO import StringIO
from app import app, db, models
from werkzeug.datastructures import FileStorage


dir_path = os.path.dirname(os.path.realpath(__file__))


@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = os.path.join(dir_path, tempfile.mkdtemp())
    client = app.test_client()

    with app.app_context():
        db.init_db()
        db.create_user('root', 'root', True)
        db.create_user('foo', 'mypassword', False)
        models.Post.create(1, 'My news', "")
        models.Message.create(2, 1, 'My message', "")

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


def test_database_cascading(client):
    db.create_user('foobar', 'foobar', False)
    u = models.User.get_user_by_name('foobar')
    models.Post.create(u.id, 'foo', '')
    models.Post.create(u.id, 'foo bar', '')

    # Deleting the user needs to delete all depending rows in other tables
    u.delete()

    assert len(models.Post.get_posts_by_user_id(u.id)) == 0


def test_unauthenticated_url_points_to_login(client):
    auth_urls = [
        '/',
        '/logout',
        '/deregister',
        '/messages',
        '/users',
        '/users/1',
    ]

    for url in auth_urls:
        response = client.get(url, follow_redirects=True)
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
    assert b'Invalid Login or password.' in response.data


def test_wrong_password_login(client):
    response = login(client, 'root', 'bar')
    assert b'Invalid Login or password.' in response.data


def test_logut(client):
    login(client, 'root', 'root')
    response = client.get('/logout', follow_redirects=True)
    assert b'Login' in response.data


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


def test_deregister(client):
    login(client, 'root', 'root')

    response = client.get('/deregister')

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


def test_post_content_and_file(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (read_file('test_data/panda.png'), 'panda.png')},
        post_content='My new Post'
    ))

    assert response.status_code == 201
    assert b'My new Post' in response.data
    assert b'/api/files/1.png' in response.data


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
    assert b'/api/files/1.png' in response.data
    assert b'/api/files/2.png' in response.data


def test_post_wrong_file_format(client):
    login(client, 'root', 'root')

    response = client.post('/', data=dict(
        {'attachment': (StringIO('my file'), 'panda.png')},
        post_content='My new Post'
    ))
    assert response.status_code == 200
    assert b'Invalid file type' in response.data


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
    assert messages[1].content == 'My new message'


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


def test_api_unauthorized(client):
    data = [
        {},
        { 'username' : 'foo' },
        { 'password' : 'password' }
    ]
    endpoints = [
        '/api/files',
        '/api/files/panda.jpg',
        '/api/users'
    ]
    for e in endpoints:
        for d in data:
            response = client.get(e, data=d)
            assert response.status_code == 401


def test_api_wrong_credentials(client):
    data = [
        { 'username' : 'foo', 'password' : 'root' },
        { 'username' : 'root', 'password' : 'password' }
    ]
    endpoints = [
        '/api/users',
        '/api/files/panda.jpg',
        '/api/users'
    ]
    for e in endpoints:
        for d in data:
            response = client.get(e, data=d)
            assert response.status_code == 401


def test_api_get_files(client):
    upload_file("panda.png")

    response = client.get('/api/files', data={
        'username' : 'root',
        'password' : 'root'
    })

    assert response.content_type == 'application/json'
    data = json.loads(response.get_data())
    assert len(data) == 1


def test_api_file_access_png(client):
    # TODO: Access all valid files
    upload_file("panda.png")

    response = client.get('/api/files/1.png', data={
        'username' : 'root',
        'password' : 'root'
    })
    assert response.status_code == 200


def test_api_file_access_symlink(client):
    # TODO: Remove that, since we check if the file is a symlink when uploading
    response = client.get('/api/files/symlink', data={
        'username' : 'root',
        'password' : 'root'
    })
    assert response.status_code == 404


def test_api_get_users(client):
    response = client.get('/api/users', data={
        'username' : 'root',
        'password' : 'root'
    })

    assert response.content_type == 'application/json'
    data = json.loads(response.get_data())
    print data
    assert len(data) == 2
    assert data[0]['id'] == 1
    assert data[0]['username'] == 'root'
    assert data[0]['is_admin'] == True

    assert data[1]['id'] == 2
    assert data[1]['username'] == 'foo'
    assert data[1]['is_admin'] == False


def test_api_get_users_no_admin(client):
    response = client.get('/api/users', data={
        'username' : 'root1',
        'password' : 'root1'
    })
    assert response.status_code == 401
