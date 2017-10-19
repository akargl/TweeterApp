DEBUG = True
DATABASE = 'database.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['.png', '.jpg', '.jpeg'])
MAX_CONTENT_LENGTH = 20 * 1024 * 1024
# TODO: Is this the right way?
SECRET_KEY = "my secret key"
MAX_CSRF_TOKEN_AGE = 3600
CSRF_METHODS = ['POST', 'PUT', 'DELETE']
