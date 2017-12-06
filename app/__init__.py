from flask import Flask
from flask_mail import Mail

# Initialize the app
app = Flask(__name__, instance_relative_config=True)

# Load the config file
app.config.from_object('config')

from helpers import get_or_create_key
app.config['SECRET_KEY'] = get_or_create_key('secret_key')
mail = Mail(app)

# Load the views
from app import views
