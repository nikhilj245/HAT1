# Import Modules
from flask import (
    Flask,
    render_template,
    request,
    make_response,
    redirect,
    url_for,
    jsonify,
    session,
)
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
)
from functools import wraps
import sqlite3
from dotenv import load_dotenv
import os
from email.message import EmailMessage
import smtplib
import certifi
import ssl
import random
import bcrypt
import logging
import re


# Flask App Setup
app = Flask(__name__)
#Required for performing JWT operations like creating and verifying tokens
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
#Required by Flask to run
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
jwt = JWTManager(app)
logging.basicConfig(level=logging.INFO)
load_dotenv()

def jwt_optional_only(fn):
    """
    Decorator to protect endpoints that don't require a valid JWT.
    If no JWT is found, the function proceeds. If a valid JWT is detected,
    the function will not proceed and return an error message.
    Learnt from here: https://www.freecodecamp.org/news/python-decorators-explained-with-examples/
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request(locations=["cookies"])
            return jsonify({"msg": "This is a protected endpoint"})
        except:
            return fn(*args, **kwargs)
    return wrapper

def is_valid_input(text):
    """
    Validates user input using regex to ensure it contains only allowed characters.
    Learnt here: https://www.w3schools.com/python/python_regex.asp
    """
    pattern = r"^[A-Za-z0-9`~!@#$%^&*()\-_{}\[\]\\|;:'\",<.>/?]+$"
    return re.match(pattern, text) is not None

def SendMail(recipient, title, content):
    """
    Sends an email to the specified recipient using SMTP server from gmail.
    Learnt here: https://realpython.com/python-send-email/
    """
    email_sender = os.getenv("EMAIL")
    email_password = os.getenv("EMAILCODE")
    email_reciever = recipient
    em = EmailMessage()
    em["From"] = email_sender
    em["To"] = email_reciever
    em["Subject"] = title
    em.set_content(content)
    context = ssl.create_default_context(cafile=certifi.where())
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_reciever, em.as_string())

def UserNameCheck(user):
    """
    Checks if a username exists in the database and returns user info.
    """
    with sqlite3.connect("database/database.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, email, password FROM users WHERE LOWER(username) = LOWER(?)",
            (user,),
        )
        return cursor.fetchone()

def EmailCheck(email):
    """
    Checks if an email exists in the database and returns user info.
    """
    with sqlite3.connect("database/database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email)= LOWER(?)", (email,))
        return cursor.fetchone()

def PasswordCheck(password):
    """
    Validates if a password meets the required criteria.
    """
    return (
        len(password) >= 8
        and any(char.isdigit() for char in password)
        and any(char.isupper() for char in password)
        and any(not char.isalnum() for char in password)
        and len(password) < 20
    )

def PasswordHash(password):
    """
    Hashes a password using bcrypt.
    Learnt here: https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def PasswordCompare(hashed_password, provided_password):
    """
    Compares a hashed password with a provided password.
    Learnt from here again: https://www.geeksforgeeks.org/hashing-passwords-in-python-with-bcrypt/
    """
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()
    return bcrypt.checkpw(provided_password.encode(), hashed_password)

def AddUser(username, email, password):
    """
    Adds a new user to the database.
    """
    with sqlite3.connect("database/database.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users VALUES (?, ?, ?)",
            (username.lower(), email.lower(), password),
        )
        conn.commit()

@app.route("/")
def home():
    """
    Renders the home/index page.
    """
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
@jwt_optional_only
def login():
    """
    Handles user login. Validates credentials and issues a JWT if successful.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if len(username) > 20 or len(password) > 20:
            logging.warning(f"Login failed: User '{username}' does not exist")
            return render_template("login.html", error="User does not exist.")

        if not is_valid_input(username) or not is_valid_input(password):
            logging.warning(f"Login failed: Invalid characters in username or password")
            return render_template("login.html", error="Invalid characters in input.")

        user_data = UserNameCheck(username)
        if user_data is None:
            logging.warning(f"Login failed: User '{username}' does not exist")
            return render_template("login.html", error="User does not exist.")

        if not PasswordCompare(user_data[2], password):
            logging.warning(f"Login failed: Incorrect password for user '{username}'")
            return render_template("login.html", error="Incorrect password.")
        """
        Creates an access token using JWT's, stores in cookies and redirects to home page
        Learnt here: https://flask-jwt-extended.readthedocs.io/en/3.0.0_release/tokens_in_cookies/
        """
        access_token = create_access_token(identity=username)
        response = make_response(redirect(url_for("home")))
        response.set_cookie(
            "access_token_cookie", access_token, secure=True, samesite="Strict"
        )
        return response

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
@jwt_optional_only
def signup():
    """
    Handles user signup. Validates input, sends a verification email, and adds the user to the database.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        checkPassword = request.form.get("re-enter password", "").strip()

        if not username or len(username) < 5 or len(username) > 20:
            return render_template("signup.html", error="Username must be between 5 and 20 characters.")

        if not is_valid_input(username) or not is_valid_input(email) or not is_valid_input(password):
            return render_template("signup.html", error="Invalid characters in input.")

        if not email or "@" not in email or "." not in email:
            return render_template("signup.html", error="Invalid email address.")

        if not PasswordCheck(password):
            return render_template("signup.html", error="Weak password: Use at least 8 characters, a digit, and a special character.")

        if password != checkPassword:
            return render_template("signup.html", error="Passwords do not match.")

        if UserNameCheck(username) is not None:
            return render_template("signup.html", error="Username already taken.")

        if EmailCheck(email) is not None:
            return render_template("signup.html", error="Email already registered.")

        password_hashed = PasswordHash(password)
        emailCode = str(random.randint(1000, 1000000))
        emailCodeHashed = PasswordHash(emailCode)

        """
        Stores information in session storage (passwords and codes are hashed)
        for later use such as verifying email code and adding users to database.
        """
        session["username"] = username
        session["email"] = email
        session["hashed_password"] = password_hashed
        session["email_code"] = emailCodeHashed

        SendMail(email, "Library activation code", str(emailCode))
        return redirect(url_for("EmailVerificationCode"))

    return render_template("signup.html")

@app.route("/verify_email", methods=["GET", "POST"])
@jwt_optional_only
def EmailVerificationCode():
    """
    Handles email verification during signup.
    """
    if request.method == "GET":
        """
        Accesses the information passed into session storage from
        the signup function.
        """
        username = session.get("username")
        email = session.get("email")
        hashed_password = session.get("hashed_password")
        emailCodeHashed = session.get("email_code")

        if not username or not email or not hashed_password or not emailCodeHashed:
            logging.warning("Signup failed: Incomplete fields")
            return redirect(url_for("signup"))

        return render_template("emailverify.html")

    else:
        entered_code = request.form.get("email code")
        emailCodeHashed = session.get("email_code")

        if not emailCodeHashed or not entered_code:
            logging.warning("Signup Failed: session expired")
            return redirect(url_for("signup"))

        if PasswordCompare(emailCodeHashed, entered_code):
            username = session.get("username")
            email = session.get("email")
            hashed_password = session.get("hashed_password")

            AddUser(username, email, hashed_password)

            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for("home")))
            response.set_cookie(
                "access_token_cookie", access_token, secure=True, samesite="Strict"
            )

            """
            Deletes all information from session storage for security.
            """
            session.pop("username", None)
            session.pop("email", None)
            session.pop("hashed_password", None)
            session.pop("email_code", None)

            return response
        else:
            logging.warning("Signup failed: Incorrect verification code")
            return render_template("index.html")

@app.route("/bookCatalogue", methods=["GET", "POST"])
@jwt_required(locations=["cookies"])
def bookCatalogue():
    """
    Renders the book catalogue page with optional genre filtering.
    """
    if UserNameCheck(get_jwt_identity()) is None:
        return redirect(url_for("home"))

    """
    Check if the request method is POST and retrieve the selected genres from the form.
    If the request method is not POST, set `new_values` to an empty list.
    """
    new_values = request.form.getlist("genre") if request.method == "POST" else []
    with sqlite3.connect("database/database.db") as conn:
        cursor = conn.cursor()
        #Checks if any genres were selected (new_values will not be empty)
        if new_values:
            # The query uses the `LIKE` operator to match genres and the `OR` operator to combine multiple genre filters.
            query = "SELECT * FROM catalogue WHERE " + " OR ".join(["genre LIKE ?" for _ in new_values])
            # Each genre is wrapped in `%` to allow partial matching (e.g., "Fiction" matches "Science Fiction")
            params = [f"%{genre}%" for genre in new_values]
            cursor.execute(query, params)
        else:
            #If no genres were selected, it displays all books in the catalogue
            cursor.execute("SELECT * FROM catalogue")
        book = cursor.fetchall()

    # Extracts the genres from the fetched book data.
    genres = [book[i][5] for i in range(len(book))]
    return render_template("catalogue.html", cataloguedata=book, genres=genres)

@app.route("/bookInfo", methods=["GET", "POST"])
@jwt_required(locations=["cookies"])
def bookInfo():
    """
    Renders the book info page for a specific book.
    """
    if UserNameCheck(get_jwt_identity()) is None:
        return redirect(url_for("home"))

    isbn = request.args.get("isbn")
    with sqlite3.connect("database/database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM catalogue WHERE isbn = ?", (isbn,))
        bookdata = cursor.fetchone()

    return render_template(
        "bookInfo.html",
        isbn=bookdata[0],
        title=bookdata[1],
        image=bookdata[2],
        description=bookdata[3],
        author=bookdata[4],
        genre=bookdata[5],
        rating=bookdata[6],
        publication_year=bookdata[7],
    )

@app.route("/settings")
def settings():
    """
    Renders the settings page.
    """
    return render_template("settings.html")

@app.route("/signout")
def signout():
    """
    Signs out the user by removing the access token cookie.
    """
    response = make_response(render_template("index.html"))
    response.set_cookie("access_token_cookie", "", expires=0)
    return response

if __name__ == "__main__":
    app.run(debug=True)
