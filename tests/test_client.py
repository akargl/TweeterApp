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

    yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


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
