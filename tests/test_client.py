import os
import tempfile
import pytest
from app import app, db


@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        db.init_db()
        db.create_user('root', 'root', True)

    yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)


def logout(client):
    return client.get('/logout', follow_redirects=True)


def test_index_pointer_to_login(client):
    auth_urls = [
        '/',
        '/logout',
        '/deregister',
        '/messages',
        '/messages/1',
        '/users',
        '/users/1',
    ]

    for url in auth_urls:
        rv = client.get(url, follow_redirects=True)
        assert b'Login' in rv.data


def test_successful_login(client):
    rv = login(client, 'root', 'root')
    print rv.data
    assert b'Content' in rv.data


def test_wrong_username_login(client):
    rv = login(client, 'foo', 'root')
    assert b'Invalid Login or password.' in rv.data


def test_wrong_password_login(client):
    rv = login(client, 'root', 'bar')
    assert b'Invalid Login or password.' in rv.data
