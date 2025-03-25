from app import app, db, login_manager
from flask import render_template, redirect, url_for, flash, request
from flask_login import UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import re

if not os.path.exists('app/instance/app.db'):
    open('app/instance/app.db', 'w').close()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    cart = db.Column(db.Text, nullable=False, default="[]")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("/user/home.html", user=current_user)
    return render_template("/public/home.html")

@app.route("/about")
def about():
    if current_user.is_authenticated:
        return render_template("/user/about.html", user=current_user)
    return render_template("/public/about.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')


        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email) or '@' not in email or email[0] == '@' or email[-4:] != ".com" or email == "":
            flash("Invalid email address", "error")
            return redirect(url_for('signup'))
        
        if len(password) > 20:
            flash("Password too long", "error")
            return redirect(url_for('signup'))
        elif len(password) <8:
            flash("Password too short", "error")
            return redirect(url_for('signup'))
        elif password == "":
            flash("Password cannot be empty", "error")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please log in.', 'error')
            return redirect(url_for('login'))

        new_user = User(email=email.strip(), password=hashed_password, cart="[]")
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template("/signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template("/login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/add_to_cart/<color>")
@login_required
def add_to_cart(color):
    try:
        cart = json.loads(current_user.cart)
    except Exception:
        cart = []
    cart.append(color)
    current_user.cart = json.dumps(cart)
    db.session.commit()
    flash(f"{color.capitalize()} added to your cart!", "success")
    return redirect(url_for('index'))

@app.route("/remove_from_cart/<color>", methods=["GET", "POST"])
@login_required
def remove_from_cart(color):
    try:
        cart=json.loads(current_user.cart)
    except Exception:
        cart = []

    if color in cart:
        cart.remove(color)
        current_user.cart = json.dumps(cart)
        db.session.commit()
        flash(f"{color.capitalize()} removed from your cart!", "success")
    else:
        flash(f"{color.capitalize()} is not in your cart!", "warning")
    return redirect(url_for('cart'))

@app.route("/cart")
@login_required
def cart():
    try:
        cart_colors = json.loads(current_user.cart)
    except Exception:
        cart_colors = []
    return render_template("/user/cart.html", user=current_user, cart_colors=cart_colors)


with app.app_context():
    db.create_all()