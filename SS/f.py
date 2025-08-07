# reset_db.py

import os
from SS import create_app
from SS.models import db, Product, User  # Import all your models here

# Path to your SQLite database
DB_PATH = os.path.join(os.path.dirname(__file__), 'app.db')

# Delete the existing database
if os.path.exists(DB_PATH):
    print("Deleting existing database...")
    os.remove(DB_PATH)
else:
    print("No database found. Creating new one...")

# Create the app
app = create_app()

# Recreate all tables
with app.app_context():
    db.create_all()
    print("Database tables created.")
