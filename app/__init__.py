from flask import Flask
from app.models import initialize_db

# Initialize the app
from flask import Flask
app = Flask(__name__, template_folder="../templates")
app.secret_key = 'super_secret_key'

# Initialize the database
initialize_db()

# Import routes
from app import routes