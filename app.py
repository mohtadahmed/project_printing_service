from unicodedata import name
from bcrypt import *
from distutils.log import debug
from enum import unique
from tokenize import String
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from fileinput import filename
from http.client import OK
from importlib.resources import path
import os
from werkzeug.utils import secure_filename
import PyPDF2


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasceretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exist. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                # return render_template('dashboard.html', username=user.username)
                return redirect(url_for('uploadfile', username=user.username))
    return render_template('login.html', form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route("/uploadfile", methods=['GET', 'POST'])
def uploadfile():
    if request.method == 'POST':
        # Handle POST Request here

        if request.files:
            f = request.files['file']
            # name = str(request.form['person'])
            name = request.args['username']
            filename = secure_filename(f.filename)
            path = 'upload/file/' + name
           # x = os.mkdir(path)

           # IF Else loop for checking the directory exists or not
            if os.path.isdir(path) == True:
                print(path)
            else:
                os.mkdir(path)

            # If Else Loop Ends

            print(path)
            filePath = os.path.join(path, filename)

            # IF Else loop for checking the same name file exists in the directory
            if os.path.isfile(filePath) == True:
                os.remove(filePath)
                print('work on IF')
                f.save(filePath)
            else:
                f.save(filePath)
                print('Work on Else')
            print(filePath)
            # IF Else loop for checking the same name file exists in the directory

            # Code for PDF Page Counter
            sample_pdf = open(filePath, mode='rb')
            pdfdoc = PyPDF2.PdfFileReader(sample_pdf)
            print(pdfdoc.numPages)
            pageNumber = pdfdoc.numPages
            # Code for PDF Page Counter

            return render_template('upload_print.html', pageNumber=pageNumber)
    return render_template('dashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('registration.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
