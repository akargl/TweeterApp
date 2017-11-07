DEBUG = True
DATABASE = 'database.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['.png', '.jpg', '.jpeg'])
MAX_CONTENT_LENGTH = 20 * 1024 * 1024
SECRET_KEY = "my secret key"
# 1 hour
MAX_CSRF_TOKEN_AGE = 3600
CSRF_METHODS = ['POST', 'PUT', 'DELETE']
# 7 days
MAX_SESSION_AGE = 60 * 60 * 24 * 7
