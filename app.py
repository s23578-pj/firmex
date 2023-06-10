from flask import Flask, render_template, redirect, url_for, flash, Markup, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import desc
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import Email, InputRequired, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, LoginManager, logout_user
import time

app = Flask(__name__)
app.secret_key = "firmex"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///firmex.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    number_of_opinions = db.Column(db.Integer, nullable=False)
    opinions = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String, nullable=False)
    category = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    opinionId = db.Column(db.Integer, nullable=False)


class Opinion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String, nullable=False)
    userId = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    nickName = db.Column(db.String, nullable=False)

    is_active = True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    surname = StringField('Surname', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirmPassword = PasswordField('Confirm Password', validators=[InputRequired()])
    nickName = StringField('Nickname', validators=[InputRequired()])
    checkbox = BooleanField(Markup('Oświadczam, że znam i akceptuję treść <a href="#">Regulaminu Firmex</a>'),
                            validators=[validators.DataRequired()])

    def validate_email(self, field):
        if Users.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_name(self, field):
        if len(field.data) < 3 or len(field.data) > 20:
            raise ValidationError('Name must be between 3 and 20 characters.')

    def validate_surname(self, field):
        if len(field.data) < 3 or len(field.data) > 20:
            raise ValidationError('Surname must be between 3 and 20 characters.')

    def validate_password(self, field):
        password = field.data

        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')

        if not any(char.isdigit() for char in password):
            raise ValidationError('Password must contain at least one digit.')

        if not any(char.islower() for char in password):
            raise ValidationError('Password must contain at least one lowercase letter.')

        if not any(char.isupper() for char in password):
            raise ValidationError('Password must contain at least one uppercase letter.')

        special_characters = "!@#$%^&*()-_=+[]{};:'\"|\\<>,./?`~"
        if not any(char in special_characters for char in password):
            raise ValidationError('Password must contain at least one special character.')

        if len(password) > 50:
            raise ValidationError('Password must not exceed 50 characters.')

        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')

    def validate_confirmPassword(self, field):
        if field.data != self.password.data:
            raise ValidationError('Passwords must match.')

    def validate_nickName(self, field):
        if len(field.data) < 5 or len(field.data) > 15:
            raise ValidationError('Nickname must be between 5 and 15 characters.')

    def validate_checkbox(self, field):
        if not field.data:
            error_message = 'Musisz zaakceptować regulamin.'
            field.errors.append(error_message)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember Me')

    def validate_login(self):
        email = self.email.data
        password = self.password.data

        user = Users.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            raise ValidationError('Invalid email or password.')

        # Ustawienie aktualnie zalogowanego użytkownika
        login_user(user)


@app.route('/')
def main_page():
    companies = Company.query.order_by(desc(Company.opinions / Company.number_of_opinions)).limit(5).all()

    return render_template('index.html', companies=companies, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            form.validate_login()
            user = Users.query.filter_by(email=form.email.data).first()
            login_user(user)
            flash('Login successful!', 'success')
            session['flash_message'] = {'message': 'Login successful!', 'category': 'success'}
            return redirect(request.referrer or url_for('main_page'))
        except ValidationError as e:
            flash(str(e), 'error')
            session['flash_message'] = {'message': str(e), 'category': 'error'}

    return render_template('login.html', form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    # flash('Wylogowano pomyślnie!', 'success')
    # session['flash_message'] = {'message': 'Wylogowano pomyślnie!', 'category': 'success'}
    return redirect(request.referrer or url_for('main_page'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Tworzenie nowego użytkownika na podstawie formularza

        hashed_password = generate_password_hash(form.password.data)
        new_user = Users(name=form.name.data,
                         surname=form.surname.data,
                         email=form.email.data,
                         password=hashed_password,
                         nickName=form.nickName.data)

        # Dodanie użytkownika do bazy danych
        db.session.add(new_user)
        db.session.commit()

        flash('Rejestracja zakończona pomyślnie!', 'success')
        session['flash_message'] = {'message': 'Rejestracja zakończona pomyślnie!', 'category': 'success'}
        return redirect(request.referrer or url_for('login'))

    return render_template('register.html', form=form, current_user=current_user)


if __name__ == '__main__':
    app.run(debug=True)
