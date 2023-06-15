import random
import string
import os
import mail as mail

from flask import Flask, render_template, redirect, url_for, flash, Markup, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, form
from sqlalchemy import desc
from wtforms import StringField, PasswordField, BooleanField, validators, SubmitField
from wtforms.validators import Email, InputRequired, ValidationError, DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user, LoginManager, logout_user
from flask_mail import Message, Mail
from datetime import datetime
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

csrf.init_app(app)
app.secret_key = "firmex"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///firmex.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # or the appropriate port number
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'polskiorzel19@gmail.com'
app.config['MAIL_PASSWORD'] = 'qagcltdvijdehxso'
app.config['SECRET_KEY'] = os.urandom(24)

mail = Mail(app)




class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    number_of_opinions = db.Column(db.Integer, nullable=False)
    opinions = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String, nullable=False)
    categoryId = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String, nullable=False)
    opinionId = db.Column(db.Integer, nullable=False)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String, nullable=False)
    companyId = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    companyName = db.Column(db.String, nullable=False)


class Opinion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String, nullable=False)
    userId = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)
    value = db.Column(db.Float, nullable=False)
    category = db.Column(db.String, nullable=False)
    companyId = db.Column(db.Integer, nullable=False)
    companyName = db.Column(db.String, nullable=False)


class Searches(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.String, nullable=False)
    companyName = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    nickName = db.Column(db.String, nullable=False)
    resetCode = db.Column(db.String, nullable=False)

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

    def validate_login(self):
        email = self.email.data
        password = self.password.data

        user = Users.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            raise ValidationError('Invalid email or password.')

        # Ustawienie aktualnie zalogowanego użytkownika
        login_user(user)


class ForgetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Submit')

    def validate_email(self, field):
        email = field.data

        user = Users.query.filter_by(email=email).first()
        if not user:
            raise ValidationError('Email address not found.')


class ResetPasswordForm(FlaskForm):
    code = StringField('Kod resetujący hasło', validators=[InputRequired()])
    submit = SubmitField('Zresetuj hasło')

    def validate_code(self, field):
        code = field.data

        user = Users.query.filter_by(resetCode=code).first()
        if not user:
            raise ValidationError('Nieprawidłowy kod resetujący hasło.')


class NewPasswordForm(FlaskForm):
    new_password = PasswordField('Nowe hasło', validators=[InputRequired()])
    confirmNewPassword = PasswordField('Confirm Password', validators=[InputRequired()])
    submit = SubmitField('Zapisz')

    def validate_new_password(self, field):
        new_password = field.data

        if len(new_password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')

        if not any(char.isdigit() for char in new_password):
            raise ValidationError('Password must contain at least one digit.')

        if not any(char.islower() for char in new_password):
            raise ValidationError('Password must contain at least one lowercase letter.')

        if not any(char.isupper() for char in new_password):
            raise ValidationError('Password must contain at least one uppercase letter.')

        special_characters = "!@#$%^&*()-_=+[]{};:'\"|\\<>,./?`~"
        if not any(char in special_characters for char in new_password):
            raise ValidationError('Password must contain at least one special character.')

        if len(new_password) > 50:
            raise ValidationError('Password must not exceed 50 characters.')

        if len(new_password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')

    def validate_confirmNewPassword(self, field):
        if field.data != self.new_password.data:
            raise ValidationError('Passwords must match.')


class DeleteAccountForm(FlaskForm):
    password = PasswordField('Hasło', validators=[DataRequired()])

    def validate_password(self, field):
        user = Users.query.get(current_user.id)
        if not check_password_hash(user.password_hash, field.data):
            raise ValidationError('Niepoprawne hasło.')


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


@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = ForgetPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()
        if user:
            # Generate a random password reset code
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

            # Update the password reset code in the database
            user.resetCode = code
            db.session.commit()  # Save the changes to the database

            # Send the password reset code via email
            msg = Message('Reset Password', sender='your_email@example.com', recipients=[email])
            msg.body = f'Your password reset code is: {code}'
            mail.send(msg)

            flash('Reset password code has been sent to your email.', 'success')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email address not found.', 'error')

    return render_template('forget_password.html', form=form)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        code = form.code.data
        user = Users.query.filter_by(resetCode=code).first()
        if user:
            return redirect(url_for('new_password', code=code))
        else:
            flash('Nieprawidłowy kod resetujący hasło.', 'error')

    return render_template('reset_password.html', form=form)


@app.route('/new_password/<code>', methods=['GET', 'POST'])
def new_password(code):
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))
    form = NewPasswordForm()
    user = Users.query.filter_by(resetCode=code).first()

    if not user:
        flash('Nieprawidłowy kod resetujący hasło.', 'error')
        return redirect(url_for('reset_password'))

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.new_password.data)
        new_password = hashed_password
        # Zaktualizuj hasło użytkownika w bazie danych
        user.password = new_password
        db.session.commit()

        # Usuń kod resetujący hasło
        user.resetCode = None
        db.session.commit()

        flash('Hasło zostało zresetowane.', 'success')
        return redirect(url_for('login'))

    return render_template('new_password.html', form=form)


@app.route('/search_companies', methods=['GET', 'POST'])
def search_companies():
    query = request.args.get('query', '').lower()

    # Zapisz wyszukiwanie użytkownika do tabeli Searches
    if current_user.is_authenticated and query.strip() != '':
        companies = Company.query.filter(Company.name.ilike(f'{query}%')).all()
        search = Searches(
            userId=current_user.id,
            companyName=query,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        db.session.add(search)
        db.session.commit()
        return render_template('search_results.html', companies=companies, query=query)
    if not current_user.is_authenticated and query.strip() != '':
        companies = Company.query.filter(Company.name.ilike(f'{query}%')).all()
        return render_template('search_results.html', companies=companies, query=query)

    return redirect(url_for('main_page'))


@app.route('/account', methods=['GET', 'POST'])
def account():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('account.html', form=form, current_user=current_user)


@app.route('/last_searches')
def last_searches():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    userId = request.args.get('userId')
    # Pobierz ostatnie wyszukiwania dla danego user_id
    searches = Searches.query.filter_by(userId=userId).order_by(Searches.date.desc()).limit(10).all()

    # Pobierz nazwy wszystkich firm
    company_names = [search.companyName.lower() for search in searches]

    # Pobierz obiekty company na podstawie companyName
    companies = Company.query.all()

    return render_template('last_searches.html', searches=searches, companies=companies, company_names=company_names)


@app.route('/company/<company_id>')
def company(company_id):
    company = Company.query.get(company_id)
    if not company:
        return "Company not found"

    opinions = Opinion.query.filter_by(companyId=company_id).all()

    return render_template('company.html', company=company, opinions=opinions)


@app.route('/company/add_opinion/<company_id>', methods=['GET', 'POST'])
def add_opinion(company_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Pobierz dane z zapytania
        userName = current_user.nickName
        userId = current_user.id
        content = request.form.get('content')
        category1 = float(request.form.get('category1')) if request.form.get('category1') else 0.0
        category2 = float(request.form.get('category2')) if request.form.get('category2') else 0.0
        category3 = float(request.form.get('category3')) if request.form.get('category3') else 0.0
        category4 = float(request.form.get('category4')) if request.form.get('category4') else 0.0

        # Oblicz średnią ocenę
        total_value = category1 + category2 + category3 + category4
        value = total_value / 4

        if value >= 4.0:
            category = 'pozytywna'
        elif value >= 3.0:
            category = 'neutralna'
        else:
            category = 'negatywna'

        company = Company.query.get(company_id)
        # Utwórz nową opinię
        new_opinion = Opinion(
            userName=userName,
            userId=userId,
            content=content,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            value=value,
            category=category,
            companyId=company_id,
            companyName=company.name
        )

        # Zwiększ liczbę opinii w firmie
        company.number_of_opinions += 1

        # Dodaj wartość opinii do opinions
        company.opinions += value

        # Zapisz zmiany w bazie danych
        db.session.add(new_opinion)
        db.session.commit()
        db.session.commit()

    return render_template('add_opinion.html', company_id=company_id, current_user=current_user)


@app.route('/your_opinions')
def your_opinions():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    # Pobierz 10 najnowszych opinii dla aktualnie zalogowanego użytkownika
    opinions = Opinion.query.filter_by(userId=current_user.id).order_by(Opinion.date.desc()).limit(10).all()

    companies = Company.query.all()

    return render_template('your_opinions.html', opinions=opinions, companies=companies)


@app.route('/category')
def category():
    # Pobierz wszystkie unikalne kategorie
    categories = Category.query.distinct(Category.category).all()

    category_dict = {}  # Słownik przechowujący kategorie i przypisane do nich firmy

    for category in categories:
        # Pobierz firmy przypisane do danej kategorii
        companies = Company.query.filter_by(categoryId=category.id).all()

        if category.category not in category_dict:
            category_dict[category.category] = []  # Utwórz pustą listę dla danej kategorii

        # Dodaj firmy do listy przypisanej do danej kategorii w słowniku
        category_dict[category.category].extend(companies)

    return render_template('category.html', category_dict=category_dict)


@app.route('/delete_account', methods=['POST'])
@csrf.exempt  # Wyłącz ochronę CSRF dla tej trasy
def delete_account():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            user = current_user

            db.session.delete(user)
            db.session.commit()
            logout_user()
            flash('Twoje konto zostało usunięte.', 'success')
            return redirect(url_for('main_page'))
        except Exception as e:
            flash(str(e), 'error')
            return redirect(url_for('account'))

    return render_template('account.html')


if __name__ == '__main__':
    app.run(debug=True)
