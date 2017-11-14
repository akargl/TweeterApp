import sys
import os
from flask import Flask

# Initialize the app
app = Flask(__name__, instance_relative_config=True)

# Load the views
from app import views


def install_secret_key(app, filename='secret_key'):
    filename = os.path.join(app.root_path, filename)
    try:
        app.config['SECRET_KEY'] = open(filename, 'rb').read()
    except IOError:
        app.logger.info('No Secret. Create a new one.')
        with open(filename, 'wb') as f:
            f.write(os.urandom(32))
            app.config['SECRET_KEY'] = open(filename, 'rb').read()


# Load the config file
app.config.from_object('config')
install_secret_key(app)
