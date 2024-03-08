from flask import Flask, render_template, redirect, url_for
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

# Initialize the Flask application
app = Flask(__name__)

# Configure the application
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'

# Initialize the Flask-SQLAlchemy database
db = SQLAlchemy(app)

# Initialize the Flask-Bcrypt password hasher
bcrypt = Bcrypt(app)

# Define the User and Role models
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

# Initialize the Flask-Security extension
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Define the login and register routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Authenticate the user
        user = user_datastore.authenticate(request.form['email'],
                                           request.form['password'])
        if user is not None:
            # Log the user in
            login_user(user)
            return redirect(url_for('home'))
        else:
            # Display an error message
            return 'Invalid email or password'
    else:
        return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Create a new user
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(email=request.form['email'],
                    password=hashed_password)
        # Add the user to the database
        db.session.add(user)
        db.session.commit()
        # Redirect to the login page
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

# Define the home route
@app.route('/')
@login_required
def home():
    return 'Welcome, {}
