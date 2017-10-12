import os
import tempfile
import pytest
from app import app, db, models


@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = "upload_fixtures"
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


def test_database_cascading(client):
    with app.app_context():
        db.create_user('foobar', 'foobar', False)
        u = models.User.get_user_by_name('foobar')
        models.Post.create(u.id, 'foo')
        models.Post.create(u.id, 'foo bar')

        # Deleting the user needs to delete all depending trows in other tables
        u.delete()

        assert len(models.Post.get_posts_by_user_id(u.id)) == 0


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
        response = client.get(url, follow_redirects=True)
        assert b'Login' in response.data


def test_successful_login(client):
    response = login(client, 'root', 'root')
    assert b'Content' in response.data


def test_wrong_username_login(client):
    response = login(client, 'foo', 'root')
    assert b'Invalid Login or password.' in response.data


def test_wrong_password_login(client):
    response = login(client, 'root', 'bar')
    assert b'Invalid Login or password.' in response.data


def test_api_file_access_png(client):
    response = client.get('/api/file/panda.png')
    assert response.status_code == 200


def test_api_file_access_symlink(client):
    response = client.get('/api/file/symlink')
    assert response.status_code == 404
