from flask import Flask, render_template, redirect, url_for, request, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from model import db, User  # Import db and User model from model.py
import os
import uuid
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Test'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.abspath("instance/app.db")}'
db.init_app(app)  # Initialize the db with the app

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('Please fill out all fields.')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password,client_id=str(uuid.uuid4()))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Please fill out all fields.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            print(f"User ID: {user.id}")
            print(f"Username: {user.username}")
            print(f"Client ID: {user.client_id}")
            login_user(user)
            return redirect(url_for('submit_data'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login')),401
            # return jsonify({"error": "Unauthorized"}), 401

    return render_template('login.html')

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_data():
    if request.method == 'POST':
        date = request.form['date']
        amount = request.form['amount']
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        if not date or not amount:
            flash('Please fill out all fields.')
            return redirect(url_for('submit_data')),422
            # return jsonify({"error": f"Missing field: {field}"}), 422

        if not re.match(r'^\d{2}-\d{2}-\d{4}$', date):
            flash('Invalid date format. Use DD-MM-YYYY.')
            return redirect(url_for('submit_data')),422

        try:
            amount = float(amount)
        except ValueError:
            flash('Amount must be a number.')
            return redirect(url_for('submit_data'))

        # Process the data as needed
        flash('Data submitted successfully.')
        return redirect(url_for('submit_data'))
    return render_template('submit.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))



if __name__ == '__main__':
    
    app.run(debug=True)
    
