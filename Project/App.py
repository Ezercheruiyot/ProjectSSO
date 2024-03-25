from flask import Flask, render_template, request, session, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from pyotp import TOTP
import sqlite3
import secrets
import smtplib
import base64
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your-secret-key'
bcrypt = Bcrypt(app)

# SMTP server configuration
#SMTP_SERVER="smtp.gmail.com"
#SMTP_PORT=587
# Configure Flask-Mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ezezonline@gmail.com'
app.config['MAIL_PASSWORD'] = "gmnk asmr pyjx ibny"
mail=Mail(app)

# SQLite database file
DATABASE = 'database.db'

# Initialize Flask-Mail
#mail = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)


# Create users table if it doesn't exist
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,     
                otp_secret TEXT,
                otp_enabled INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

init_db()

# Enable OTP for user
def enable_otp(username):
    otp_secret = base64.b32encode(secrets.token_bytes(16)).decode('utf-8')  # Generate a random 16-byte base32 string
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('UPDATE users SET otp_secret = ?, otp_enabled = 1 WHERE username = ?', (otp_secret, username))
        conn.commit()
    return otp_secret

# Check OTP
def check_otp(username, otp):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT otp_secret FROM users WHERE username = ?', (username,))
        otp_secret = cursor.fetchone()[0]

    totp = TOTP(otp_secret, interval=60)  # Set interval to 60 seconds
    return totp.verify(otp)

# Generate OTP token
def generate_otp_token(username):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT otp_secret FROM users WHERE username = ?', (username,))
        otp_secret = cursor.fetchone()[0]

    totp = TOTP(otp_secret, interval=60)  # Set interval to 60 seconds
    return totp.now()

# Send OTP token via email
def send_otp_email(email, otp_token):
    msg = MIMEText(f'Your OTP Token is: {otp_token}')
    msg['Subject'] = 'Your OTP Token'
    msg['From'] = 'ezezonline@gmail.com'
    msg['To'] = email

    mail.sendmail('ezezonline@gmail.com', [email], msg.as_string())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # New field for email address

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()

        if user:
            return "A user with this email address already exists. Please use a different email address."

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
            conn.commit()

        # Enable OTP for the new user
        enable_otp(username)

        # Send OTP token via email
        otp_token = generate_otp_token(username)
        send_otp_email(email, otp_token)

        return redirect(url_for('login'))

    return render_template('register.html', action='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user'] = {'id': user[0], 'username': user[1]}

            if user[4]:
                session['otp_authenticated'] = False
                # Generate and send OTP token every time user logs in
                otp_token = generate_otp_token(username)
                send_otp_email(user[3], otp_token)  # user[3] is the email
                return redirect(url_for('otp'))

            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password'

    return render_template('login.html', action='Login')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']

        # try-except block to handle OTP verification errors
        try:
            if check_otp(session['user']['username'], otp):
                session['otp_authenticated'] = True
                return redirect(url_for('dashboard'))
        except Exception as e:
            return f'Invalid OTP: {str(e)}'  # Return the error message

    return render_template('otp.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    if session.get('otp_authenticated'):
        return render_template('dashboard.html', profile_url=url_for('profile'))
    else:
        return redirect(url_for('otp'))

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    if session.get('otp_authenticated'):
        return render_template('profile.html', dashboard_url=url_for('dashboard'))
    else:
        return redirect(url_for('otp'))
    
# Function to send OTP via email
def send_otp_email(email, otp_token):
    msg = Message('Your OTP Token',
                  sender='ezezonline@gmail.com',
                  recipients=[email])
    msg.body = f'Your OTP Token is: {otp_token}'
    mail.send(msg)  



if __name__ == '__main__':
    app.run(debug=True)
