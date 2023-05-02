from flask import Flask, render_template,request, session, redirect, abort, flash, url_for, jsonify
from flask_restful import Api, Resource
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, PasswordField,EmailField, SelectField, DateField, RadioField
from wtforms.validators import DataRequired, NumberRange, Length, Email, EqualTo
import os
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from datetime import datetime
from flask_migrate import Migrate
import requests
import json

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mariadb://root:mysqlpassword@localhost/projectthree'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mscd3150'

db = SQLAlchemy(app)
api = Api(app)

class UserType(Enum):
    JobSeeker = "Job seeker"
    Employer = "Employer"

class Gender(Enum):
    Male = 'Male'
    Female = 'Female'

class User(db.Model):
    __tablename__ ='users'
    userid = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(64))
    lastname = db.Column(db.String(64))
    dob=db.Column(db.Date)
    gender = db.Column(db.Enum(Gender))
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(64), index=True)
    password = db.Column(db.String(255))
    user_type = db.Column(db.Enum(UserType))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.firstname}', '{self.lastname}', '{self.dob}', '{self.gender}', '{self.username}', '{self.email}', '{self.user_type}')"

class RegisterForm(FlaskForm):
    firstname = StringField('Firstname', validators=[DataRequired(), Length(min=4, max=15)])
    lastname = StringField('Lastname', validators=[DataRequired(), Length(min=4, max=15)])
    dob = DateField('Dob', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[(member.value, member.name) for member in Gender])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=15)])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    user_type = SelectField('UserType', choices=[(member.value, member.name) for member in UserType])
    submit = SubmitField('Register!')

    
class Registeration(Resource):    
    def post(self):
        if request.headers['Content-Type'] != 'application/json':
            return {'error': 'Invalid Content-Type. Must be application/json.'}, 400
        data = request.json
        firstname = data['firstname']
        lastname = data['lastname']
        dob = str(data['dob'])  # convert date object to string
        gender = data['gender']
        username = data['username']
        email = data['email']
        user_type = data['user_type']
        password = data['password']
        confirm_password = data['confirm_password']

        # Check if the user already exists
        if User.query.filter_by(username=username).first():
            return {'message': 'User with this username already exists'}, 400
        
        if password != confirm_password:
            return {'message': 'Passwords do not match. Please try again.'}, 400
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Create a new user object
        new_user = User(firstname=firstname, lastname=lastname, dob=dob, gender=gender, username=username, email=email, password=hashed_password , user_type = user_type, created_date=datetime.utcnow())
        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User created successfully!'}, 201
    
@app.route('/api/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        dob_str = request.form['dob']
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        gender = request.form['gender']
        username = request.form['username']
        email = request.form['email']
        user_type = request.form['user_type']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        data = {
            'firstname': firstname,
            'lastname': lastname,
            'dob': dob_str,
            'gender': gender,
            'username': username,
            'email': email,
            'user_type': user_type,
            'password': password,
            'confirm_password': confirm_password
        }

        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post('http://localhost:5000/api/register', json=data, headers=headers)
            
            if response.status_code == 201:
                flash('You have successfully registered!', 'success')
                return redirect('/login')
            else:
                flash(response.json()['message'], 'danger')
        except requests.exceptions.RequestException as e:
            flash('Error connecting to API endpoint. Please try again later.', 'danger')
             
    # render the registration form template
    form = RegisterForm(request.form)
    return render_template('register.html', form=form)

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         # Process form data
#         data = {
#             'firstname': form.firstname.data,
#             'lastname': form.lastname.data,
#             'dob': form.dob.data,
#             'gender': form.gender.data,
#             'username': form.username.data,
#             'email': form.email.data,
#             'user_type': form.user_type.data,
#             'password': form.password.data,
#             'confirm_password': form.confirm_password.data,
#         }
#         response, status_code = Registeration().post(data)
#         if status_code == 201:
#             flash('User created successfully!', 'success')
#             return redirect(url_for('login'))
#         else:
#             flash(response['message'], 'danger')
#     return render_template('register.html', form=form)




class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# checking with db
class LoginAuthentication(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        # Find the user with the given email
        user = User.query.filter_by(username=username).first()
        # Check if the user exists and the password is correct
        if not user or not check_password_hash(user.password, password):
            return {'message': 'Invalid email or password'}, 401
        # Store the user ID in the session
        session['user_id'] = user.userid
        return {'message': 'Login successful!'}, 200


    
class Logout(Resource):
    def post(self):
        # Clear the session data
        session.clear()

        return {'message': 'Logout successful!'}, 200
    

# Routes for web interface
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Verify the user's login credentials
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = requests.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', title='Login', form=form)



api.add_resource(Registeration, '/register')
api.add_resource(LoginAuthentication, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    # db.create_all()
    app.run(debug=True)


