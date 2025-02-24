from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_wtf.csrf import CSRFProtect
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
import json


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
jwt = JWTManager(app)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO) 
load_dotenv()


def jwt_optional_only(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request(locations=['cookies'])
            return jsonify({"msg": "This is a protected endpoint"})
        except:
            return fn(*args, **kwargs)
    return wrapper

def is_valid_input(text):
    pattern = r"^[A-Za-z0-9`~!@#$%^&*()\-_{}\[\]\\|;:'\",<.>/?]+$"
    return re.match(pattern, text) is not None


def SendMail(recipient, title, content):
    email_sender = os.getenv('EMAIL')
    email_password = os.getenv('EMAILCODE')
    email_reciever = recipient
    subject = title
    body = content
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_reciever
    em['Subject'] = subject
    em.set_content(body)
    context = ssl.create_default_context(cafile=certifi.where())
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_reciever, em.as_string())


@app.route('/verify_email', methods=['GET', 'POST'])
@jwt_optional_only
def EmailVerificationCode():
    if request.method == 'GET':
        username = session.get("username")
        email = session.get("email")
        hashed_password = session.get("hashed_password")
        emailCodeHashed = session.get("email_code")

        if not username or not email or not hashed_password or not emailCodeHashed:
            logging.warning("Signup failed: Incomplete fields")
            return redirect(url_for('signup'))

        return render_template("emailverify.html")

    else:
        entered_code = request.form.get("email code")
        emailCodeHashed = session.get("email_code")

        if not emailCodeHashed or not entered_code:
            logging.warning(f"Signup Failed: session expired")
            return redirect(url_for('signup'))

        if PasswordCompare(emailCodeHashed, entered_code):
            username = session.get("username")
            email = session.get("email")
            hashed_password = session.get("hashed_password")

            AddUser(username, email, hashed_password)

            access_token = create_access_token(identity=username)
            response = make_response(redirect(url_for('home')))
            response.set_cookie('access_token_cookie', access_token, secure=True, samesite='Strict')

            session.pop("username", None)
            session.pop("email", None)
            session.pop("hashed_password", None)
            session.pop("email_code", None)

            return response
        else:
            logging.warning(f"Signup failed: Incorrect verification code")
            return render_template("emailverify.html")



def UserNameCheck(user):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, password FROM users WHERE LOWER(username) = LOWER(?)", (user,))
        return cursor.fetchone()

def EmailCheck(email):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email)= LOWER(?)", (email,))
        return cursor.fetchone()

def PasswordCheck(password):
    if len(password)>=8 and any(char.isdigit() for char in password) and any(char.isupper() for char in password) and any(not char.isalnum() for char in password) and len(password) < 20:
        return True
    return False

def PasswordHash(password):
    salt = bcrypt.gensalt()
    password = bcrypt.hashpw(password.encode(), salt)
    hashed_password = password.decode()
    return hashed_password

def PasswordCompare(hashed_password, provided_password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()
    return bcrypt.checkpw(provided_password.encode(), hashed_password)

def AddUser(username, email, password):
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username.lower(), email.lower(), password))
        conn.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@jwt_optional_only
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if len(username) > 20 and len(password) > 20:
            logging.warning(f"Login failed: User '{username}' does not exist")
            return render_template('login.html', error="User does not exist.")
        if not is_valid_input(username) or not is_valid_input(password):
            logging.warning(f"Login failed: Invalid characters in username or password")
            return render_template('login.html', error="Invalid characters in username or password.")
        user_data = UserNameCheck(username)
        if user_data is None:
            logging.warning(f"Login failed: User '{username}' does not exist")
            return render_template('login.html', error="User does not exist.")
        if not PasswordCompare(user_data[2], password):
            logging.warning(f"Login failed: Incorrect password for user '{username}'")
            return render_template('login.html', error="Incorrect password.")

        access_token = create_access_token(identity=username)
        response = make_response(redirect(url_for('home'))) 
        response.set_cookie('access_token_cookie', access_token, secure=True, samesite='Strict') 
        return response

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
@jwt_optional_only
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        checkPassword = request.form.get('re-enter password', '').strip()

        if not username or len(username) < 5 or len(username) > 20:
            return render_template('signup.html', error="Username must be between 5 and 20 characters.")

        if not is_valid_input(username) or not is_valid_input(email) or not is_valid_input(password):
            return render_template('signup.html', error="Invalid characters in input.")

        if not email or '@' not in email or '.' not in email:
            return render_template('signup.html', error="Invalid email address.")

        if not PasswordCheck(password):
            return render_template('signup.html', error="Weak password: Use at least 8 characters, a digit, and a special character.")

        if password != checkPassword:
            return render_template('signup.html', error="Passwords do not match.")

        if UserNameCheck(username) is not None:
            return render_template('signup.html', error="Username already taken.")

        if EmailCheck(email) is not None:
            return render_template('signup.html', error="Email already registered.")

        password_hashed = PasswordHash(password)
        emailCode = str(random.randint(1000, 1000000))
        emailCodeHashed = PasswordHash(emailCode)  # Hash the code before storing

        # Store username, password, and hashed code in session (or temporary database)
        session['username'] = username
        session['email'] = email
        session['hashed_password'] = password_hashed
        session['email_code'] = emailCodeHashed

        SendMail(email, "Library activation code", str(emailCode))
        return redirect(url_for('EmailVerificationCode'))

    return render_template('signup.html')

@app.route('/bookCatalogue', methods=['GET', 'POST'])
@jwt_required(locations=['cookies'])
def bookCatalogue():
    if UserNameCheck(get_jwt_identity()) is None:
        return redirect(url_for('home'))
    with sqlite3.connect('database/database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM catalogue")
        return render_template('catalogue.html', cataloguedata=cursor.fetchall())

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/signout')
def signout():
    response = make_response(render_template("index.html"))
    response.set_cookie('access_token_cookie', '', expires=0)
    return response

if __name__ == '__main__':
    app.run(debug=True)