from flask_sqlalchemy import SQLAlchemy

from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = "firmex"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///firmex.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    number_of_opinions = db.Column(db.Integer, nullable=False)
    opinions = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String, nullable=False)


@app.route('/')
def hello_world():
    companies = Company.query.all()

    return render_template('index.html', companies=companies)


if __name__ == '__main__':
    app.run(debug=True)
