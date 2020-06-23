import os

from flask import Flask, session, render_template, flash, jsonify, request, redirect
from flask_session import Session
from sqlalchemy import create_engine
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import scoped_session, sessionmaker

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


@app.route("/")
def index():
    return "To Do"

@app.route("/register", methods=["GET", "POST"])
def register():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        uname = request.form.get("username")
        pw = request.form.get("password")
        re_pw = request.form.get("re_password")

        # Ensure username and password was submitted
        if not uname or not pw:
            return render_template("error.html", error_message="Must Provide Username and/or Password", error_code=403)

        # Ensure re-password was submitted
        elif not re_pw:
            return render_template("error.html", error_message="Must Provide Password Verification", error_code=403)
        
        # Ensure that the password verification is successful
        elif pw != re_pw:
            return render_template("error.html", error_message="Password Verification Failed!", error_code=403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=uname)

        # Ensure that the username is not taken already
        if len(rows) != 0:
            return render_template("error.html", error_message="Sorry! This username is already taken!", error_code=403)

        if len(pw) < 5:
            return render_template("error.html", error_message="Password too short!", error_code=403)

        pw_hash = generate_password_hash(pw)

        db.execute("INSERT INTO users (username, hash) VALUES (:uname, :pw_hash)", uname=uname, pw_hash=pw_hash)

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", error_message="MUST PROVIDE USERNAME", error_code=403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html",error_message="MUST PROVIDE PASSWORD", error_code=403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", error_message="invalid username and/or password", error_code=403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

