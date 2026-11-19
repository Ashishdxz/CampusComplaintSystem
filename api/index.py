import sys
import os

# Add root directory to sys.path so app.py and database.py are importable on Vercel
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import the Flask application instance
from app import app

# Vercel's Python runtime discovers this WSGI 'app' object automatically
