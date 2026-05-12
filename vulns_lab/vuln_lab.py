from flask import Flask, request, send_from_directory, redirect, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Mock database setup
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, secret TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'FLAG{SQL_INJECTION_MASTER}')")
    return conn

db = init_db()

@app.route('/')
def index():
    # Vulnerable to XSS via the 'name' parameter
    name = request.args.get('name', 'Guest')
    return render_template_string(f"<h1>Welcome, {name}</h1><p>Search for users via /search?id=1</p>")

@app.route('/search')
def search():
    # CRITICAL: Classic SQL Injection vulnerability
    user_id = request.args.get('id', '1')
    query = f"SELECT username, secret FROM users WHERE id = {user_id}"
    try:
        cursor = db.execute(query)
        result = cursor.fetchone()
        return f"User Found: {result}"
    except Exception as e:
        return f"Database Error: {str(e)}", 500

@app.route('/redirect')
def open_redirect():
    # HIGH: Open Redirect vulnerability
    target = request.args.get('to', '/')
    return redirect(target)

@app.route('/.env')
@app.route('/config.php')
def sensitive_files():
    # MEDIUM: Exposed sensitive configuration
    return "DB_PASSWORD=SuperSecret123\nAPI_KEY=vulnerable_key_99", 200

if __name__ == '__main__':
    # Running on port 5001 to avoid conflict with the main scanner
    app.run(port=5001, debug=True)
