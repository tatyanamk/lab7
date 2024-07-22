from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Home Route
@app.route('/')
def home():
    return render_template('signin.html')

# Sign Up Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate Email
        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(str(e), 'danger')
            return redirect(url_for('signup'))

        # Password Validation
        if not (re.search(r'[a-z]', password) and
                re.search(r'[A-Z]', password) and
                re.search(r'\d$', password) and
                len(password) >= 8):
            flash('Password must contain a lowercase letter, an uppercase letter, end in a number, and be at least 8 characters long.', 'danger')
            return redirect(url_for('signup'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email address already in use.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('thankyou.html')

    return render_template('signup.html')

# Sign In Route
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Query the user from the database
        user = User.query.filter_by(email=email).first()

        # Check password and handle login
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('signin.html')


# Secret Page Route
@app.route('/secret')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return render_template('secretPage.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('signin'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
