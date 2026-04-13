import sqlite3
import os
from flask import Flask, render_template, request, redirect, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Secure key for sessions
app.secret_key = os.urandom(24) 
DATABASE = 'donors.db'

# --- Database Management ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name: donor['name']
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # New Users Table
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        # Donors Table
        db.execute("""
            CREATE TABLE IF NOT EXISTS donors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                blood TEXT NOT NULL,
                phone TEXT NOT NULL,
                pincode TEXT NOT NULL
            )
        """)
        db.commit()

# --- Security: This runs before every request ---
@app.before_request
def check_login():
    # Pages that DON'T require login
    public_routes = ['login', 'signup', 'static']
    if 'user_id' not in session and request.endpoint not in public_routes:
        return redirect("/login")

# --- Authentication Routes ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        user = request.form.get("username").strip()
        pwd = request.form.get("password")
        
        if user and pwd:
            hashed_pwd = generate_password_hash(pwd)
            db = get_db()
            try:
                db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, hashed_pwd))
                db.commit()
                return redirect("/login")
            except sqlite3.IntegrityError:
                return "Username already exists!"
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        
        db = get_db()
        user_data = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
        
        if user_data and check_password_hash(user_data['password'], pwd):
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            return redirect("/")
        else:
            return "Invalid Credentials"
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# --- Donor Routes (Protected) ---

@app.route("/")
def home():
    db = get_db()
    donors = db.execute("SELECT * FROM donors").fetchall()
    return render_template("index.html", donors=donors, total=len(donors))

@app.route("/register", methods=["POST"])
def register():
    db = get_db()
    db.execute(
        "INSERT INTO donors (name, blood, phone, pincode) VALUES (?, ?, ?, ?)",
        (request.form["name"], request.form["blood"], request.form["phone"], request.form["pincode"])
    )
    db.commit()
    return redirect("/")

@app.route("/search", methods=["POST"])
def search():
    pincode = request.form["pincode"]
    blood = request.form["blood"]
    db = get_db()

    if blood:
        res = db.execute("SELECT * FROM donors WHERE pincode=? AND blood=?", (pincode, blood)).fetchall()
    else:
        res = db.execute("SELECT * FROM donors WHERE pincode=?", (pincode,)).fetchall()

    return render_template("index.html", donors=res, total=len(res))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
