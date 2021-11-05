from flask_restx import abort
import jwt
from flask import request
from constants import JWT_SECRET, JWT_ALGORITHM
from dao import user
from dao.model.user import User
from implemented import user_service
from setup_db import db

"""
def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)
        data = request.headers['Authorization']
        token = data.split('Bearer')[-1]

        try:
            jwt.decode(token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception as e:
            print('JWT Decode exception', e)
            abort(401)
        return func(*args, **kwargs)
    return wrapper
"""

def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]
        try:
            jwt.decode(jwt=token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except Exception as e:
            print('JWT Decode Exception', e)
            abort(401)
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]
        role = None
        try:
            jwt.decode(jwt=token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])
            role = user.get('role', 'user')
        except Exception as e:
            print('JWT Decode Exception', e)
            abort(401)
        if role != "admin":
            abort(403)
        return func(*args, **kwargs)
    return wrapper


def make_user(id, email, password, username, surname, favorite):
    u = User(id="id", email='email', password=user_service.make_user_password_hash("password"),
             username="username",  surname="surname", favorite="favorite")
    with db.session.begin():
        db.session.add_all(u)
    return u