from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.security import generate_password_hash
import os
import string
import random
import uuid
from authlib.integrations.flask_client import OAuth
from flask_mail import Message, Mail

app = Flask(__name__)

# Flask configuration
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_key')  # Use environment variable
app.config.update({
    "OAUTH2_CLIENT_ID": "crop-reco-app",
    "OAUTH2_CLIENT_SECRET": "2Z6O5vN38oUzHnRAhoYBsShCqzbv9owL",
    "OAUTH2_ISSUER": "http://localhost:8080/realms/Crop-Reco",
    "FLASK_PORT": 3000
})
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
                                        'postgresql://postgres:Munashe056@localhost/crop-recommendation'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kasumbamunashe@gmail.com'
app.config['MAIL_PASSWORD'] = 'xgya hlcv zjzr fjxv'  # Use an app-specific password here
app.config['MAIL_DEFAULT_SENDER'] = 'kasumbamunashe@gmail.com'
mail = Mail(app)



# User model for database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    phoneNumber = db.Column(db.String(80), unique=True, nullable=False)
    farmLocation = db.Column(db.String(120))
    language = db.Column(db.String(100))
    totalLandArea = db.Column(db.String(80))
    soilType = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True)

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    return render_template('welcome.html')

def generate_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        phoneNumber = request.form['phone']
        farmLocation = request.form['location']
        language = request.form['language_preference']
        totalLandArea = request.form['land_area']
        soilType = request.form['soil_type']
        username = request.form['email']  # Ensure you are using the username field from the form
        password = generate_password()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))

        # Create a new user instance
        new_user = User(
            fullname=fullname,
            email=email,
            username=username,  # Use the username from the form
            phoneNumber=phoneNumber,
            farmLocation=farmLocation,
            language=language,
            totalLandArea=totalLandArea,
            soilType=soilType,
            password=hashed_password
        )

        try:
            # Add the user to the database
            db.session.add(new_user)
            db.session.commit()

            # Send email with account details
            subject = "Your Account Information"
            template = f"""
            <p>Dear {fullname},</p>
            <p>Your account has been created with the following details:</p>
            <ul>
                <li>Username: {username}</li>
                <li>Password: {password}</li>
            </ul>
            <p>Please keep this information secure.</p>
            """
            send_email(email, subject, template)

            flash("Registration successful! Check your email for your username and password.", "success")
            return redirect(url_for('login'))  # Redirect to login after successful registration
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating the account. Please try again.', 'danger')
            return redirect(url_for('register'))

    # Render the registration form for GET requests
    return render_template('register.html')



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            token = str(uuid.uuid4())  # Generate a unique token
            # Store the token in the database with an expiration time
            user.reset_token = token
            db.session.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            subject = "Password Reset Request"
            template = f"<p>Dear {username},</p><p>You requested a password reset. Click the link below to reset your password:</p><p><a href='{reset_link}'>Reset Password</a></p><p>If you didn't request this, please ignore this email.</p>"
            send_email(user.email, subject, template)

            flash('A password reset link has been sent to your email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username not found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to log in to access the dashboard.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=3000, debug=True)
