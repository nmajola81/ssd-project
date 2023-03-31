from flask_login import UserMixin
from App import app, db

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    surname_prefix = db.Column(db.String)
    surname = db.Column(db.String)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    phone_number = db.Column(db.String)
    role = db.Column(db.String, default=False)
    is_deleted = db.Column(db.Boolean, default=False)