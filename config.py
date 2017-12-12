DEBUG = False
DATABASE = 'database.db'
DATABASE_KEY_FILE = 'database.key'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['.png', '.jpg', '.jpeg'])
MAX_CONTENT_LENGTH = 20 * 1024 * 1024
# 1 hour
MAX_CSRF_TOKEN_AGE = 3600
CSRF_METHODS = ['POST', 'PUT', 'DELETE']
# 7 days
MAX_SESSION_AGE = 7 * 60 * 60 * 24
# Recaptcha keys for Google Recaptcha
RECAPTCHA_ENABLED = True
RECAPTCHA_PUBLIC_KEY = "XXXXXXXXXXXXXXXXXXXXX"
RECAPTCHA_SECRET_KEY = "XXXXXXXXXXXXXXXXXXXXX"
# CSP reporting URL on Sentry
CSP_REPORT_URI = "https://sentry.io/api/252244/csp-report/?sentry_key=XXXXXXXXXXXXXXXXXXXXX"
