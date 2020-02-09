import random
import string
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()




class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    salt = db.Column(db.String(100))
    last_login_time = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
