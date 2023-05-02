from flask import Flask, render_template,redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user,UserMixin

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField,DateField, SelectField,EmailField,BooleanField,DecimalField,TextAreaField
from wtforms.validators import DataRequired, NumberRange, Length, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource, reqparse
from enum import Enum
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mariadb://root:mysqlpassword@localhost/projectthree'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mscd3150'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
api = Api(app)

# Model
class UserType(Enum):
    JobSeeker = "JobSeeker"
    Employer = "Employer"

class Gender(Enum):
    Male = 'Male'
    Female = 'Female'

class User(db.Model,UserMixin,):
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
    # Define is_active as a property
    @property
    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.userid)

    def __repr__(self):
        return f"User('{self.firstname}', '{self.lastname}', '{self.dob}', '{self.gender}', '{self.username}', '{self.email}', '{self.user_type}')"
    
class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), index=True, unique=True)
    salary_range = db.Column(db.String(20))
    company = db.Column(db.String(120), index=True)
    category = db.Column(db.String(64), index=True)
    description = db.Column(db.String(1000))
    email = db.Column(db.String(120), index=True)
    filled = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<Job {}>'.format(self.title)
    
# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Form

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Define the login resource for the REST API
class LoginResource(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        # Find the user with the given username
        user = User.query.filter_by(username=username).first()
        # Check if the user exists and the password is correct
        if not user or not check_password_hash(user.password, password):
            return {'message': 'Invalid username or password'}, 401
        # Log the user in
        login_user(user)
        return {'message': 'Login successful!'}, 200
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

class UserForm(FlaskForm):
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

class UserResource(Resource):
    def get(self, user_id=None):
        if user_id is not None:
            user = User.query.get(user_id)
            if user:
                return {
                    'id': user.userid,
                    'firstname': user.firstname,
                    'lastname': user.lastname,
                    'dob': user.dob.isoformat(),
                    'gender': user.gender.value,
                    'username': user.username,
                    'email': user.email,
                    'user_type': user.user_type.value,
                    'created_date': user.created_date.strftime('%Y-%m-%d %H:%M:%S')
                }
            else:
                return {'message': 'User not found'}, 404
        else:
            users = User.query.all()
            return [
                {
                    'id': user.userid,
                    'firstname': user.firstname,
                    'lastname': user.lastname,
                    'dob': user.dob.isoformat(),
                    'gender': user.gender.value,
                    'username': user.username,
                    'email': user.email,
                    'user_type': user.user_type.value,
                    'created_date': user.created_date.strftime('%Y-%m-%d %H:%M:%S')
                }
                for user in users
            ]

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('firstname', type=str, required=True)
        parser.add_argument('lastname', type=str, required=True)
        parser.add_argument('dob', type=str, required=True)
        parser.add_argument('gender', type=str, required=True)
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        parser.add_argument('user_type', type=str, required=True)
        args = parser.parse_args()

        # Check if the user already exists
        if User.query.filter_by(username=args['username']).first():
            return {'message': 'User with this username already exists'}, 400

        # Hash the password
        hashed_password = generate_password_hash(args['password'], method='sha256')

        new_user = User(firstname=args['firstname'], lastname=args['lastname'], dob=datetime.strptime(args['dob'], '%Y-%m-%d').date(), gender=args['gender'], username=args['username'], email=args['email'], password=hashed_password, user_type=UserType(args['user_type']))
        db.session.add(new_user)
        db.session.commit()

        return {'id': new_user.userid, 'firstname': new_user.firstname, 'lastname': new_user.lastname, 'dob': new_user.dob.isoformat(), 'gender': new_user.gender.name, 'username': new_user.username, 'email': new_user.email, 'user_type': new_user.user_type.value}

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        firstname=form.firstname.data
        lastname=form.lastname.data
        dob=form.dob.data
        gender=form.gender.data
        username=form.username.data
        email=form.email.data
        password=form.password.data
        confirm_password=form.confirm_password.data
        user_type= form.user_type.data

        # Check if the user already exists
        if User.query.filter_by(username=username).first():
            return {'message': 'User with this username already exists'}, 400
        
        if password != confirm_password:
            return {'message': 'Passwords do not match. Please try again.'}, 400
        
        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(firstname=firstname, lastname=lastname, dob=dob, gender=gender, username=username, email=email, password=hashed_password , user_type=user_type, created_date=datetime.utcnow())
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html', form=form)

# Define the logout resource for the REST API
class LogoutResource(Resource):
    @login_required
    def post(self):
        logout_user()
        flash('Logout successful!', 'success')
        return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', title='Home')
    else:
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if current_user.is_authenticated:
        return render_template('profile.html', title='profile')
    else:
        return redirect(url_for('login'))
    

class JobForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    salary = DecimalField('Salary')
    company = StringField('Company', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    contact = StringField('Contact', validators=[DataRequired()])
    submit = SubmitField('AddPost')

    
@app.route('/addpost')
def addpost():
    form = JobForm()
    render_template('addpost.html',form=form)

# api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(UserResource, '/register')
api.add_resource(LoginResource, '/login')
api.add_resource(LogoutResource, '/logout')

if __name__ == '__main__':
    app.run(debug=True)


