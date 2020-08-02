from flask_security import UserMixin
from user import DB
import datetime


class User(DB.Model, UserMixin):
    __tablename__ = 'users'

    id = DB.Column(DB.Integer, primary_key=True, autoincrement=True)
    user_name = DB.Column(DB.String(30))
    user_email = DB.Column(DB.String(100), nullable=False, unique=True)
    user_password = DB.Column(DB.String(255), nullable=False)
    user_first_name = DB.Column(DB.String(30))
    user_last_name = DB.Column(DB.String(30))
    user_confirmed = DB.Column(DB.Boolean, nullable=False, default=False)
    user_registration_date = DB.Column(DB.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'User: {self.user_name}'

    @classmethod
    def find_user(cls, **kwargs):
        return cls.query.filter_by(**kwargs).first()
