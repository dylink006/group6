from app import app, db, login_manager
from flask import render_template, redirect, url_for, flash, jsonify, request
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
    with open('app/static/products.json') as f:
        products = json.load(f)

    if current_user.is_authenticated:
        return render_template("/user/home.html", user=current_user, products=products)
    return render_template("/public/home.html", products=products)

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
            return redirect(url_for('login'))

    return render_template("/login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route("/add_to_cart/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    try:
        with open('app/static/products.json') as f:
            products = json.load(f)
        
        if product_id < 0 or product_id >= len(products):
            raise ValueError("Invalid product ID")
            
        cart = json.loads(current_user.cart)
        cart.append(product_id)
        current_user.cart = json.dumps(cart)
        db.session.commit()
        
        message = f"{products[product_id]['title']} added to cart!"
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=True, message=message), 200
        else:
            flash(message, "success")
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message="Error adding to cart"), 500
        else:
            flash("Error adding product to cart", "danger")
    
    return redirect(url_for('index'))

@app.route("/remove_from_cart/<int:product_id>", methods=["POST"])
@login_required
def remove_from_cart(product_id):
    try:
        cart = json.loads(current_user.cart)
        if product_id in cart:
            cart.remove(product_id)
            current_user.cart = json.dumps(cart)
            db.session.commit()

            with open('app/static/products.json') as f:
                products = json.load(f)
            new_total = sum(
                products[pid]['price']
                for pid in cart
                if 0 <= pid < len(products)
            )

            message = "Item removed from cart!"
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(success=True, message=message, new_total=new_total), 200
            flash(message, "success")
        else:
            message = "Item not in cart."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(success=False, message=message), 404
            flash(message, "warning")
    except Exception as e:
        message = "Error removing product: " + str(e)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=message), 500
        flash(message, "danger")
    return redirect(url_for('cart'))


@app.route("/cart")
@login_required
def cart():
    try:
        cart_ids = json.loads(current_user.cart)
    except Exception:
        cart_ids = []

    with open('app/static/products.json') as f:
        all_products = json.load(f)
    
    cart_products = []
    for pid in cart_ids:
        if 0 <= pid < len(all_products):
            product = all_products[pid].copy()
            product['id'] = pid
            cart_products.append(product) 
    
    return render_template("/user/cart.html", 
                         user=current_user,
                         cart_products=cart_products,
                         total_price=sum(p['price'] for p in cart_products))
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    try:
        # Get product IDs from cart
        cart_ids = json.loads(current_user.cart)
    except Exception:
        cart_ids = []

    # Load product data
    with open('app/static/products.json') as f:
        all_products = json.load(f)
    
    # Convert IDs to product objects
    purchased_products = [all_products[pid] for pid in cart_ids if pid < len(all_products)]
    
    # Clear cart
    current_user.cart = json.dumps([])
    db.session.commit()
    
    return render_template('/user/checkout.html',
                         user=current_user,
                         purchased_items=purchased_products)


with app.app_context():
    db.create_all()