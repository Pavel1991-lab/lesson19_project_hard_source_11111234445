from flask import jsonify, request

from dao.model.user import User
from setup_db import db


class AuDAO:
    def __init__(self, session):
        self.session = session

    def get_one(self, uid):
        return self.session.query(User).get(uid)

    def get_all(self):
        return self.session.query(User).all()

    def get_by_username(self, username):
        return self.session.query(User).filter(User.username == username).first()

    def create(self, user_d):
        ent = User(**user_d)
        self.session.add(ent)
        self.session.commit()
        return ent

    def delete(self, uid):
        user = self.get_one(uid)
        self.session.delete(user)
        self.session.commit()

    def update(self, user_d):
        user = self.get_one(user_d.get("id"))
        user.email = user_d.get("email")
        user.password  = user_d.get("password")
        user.username = user_d.get("username")
        user.surname = user_d.get("surname")
        user.favorite_genre = user_d.get("favorite_genre")

        self.session.add(user)
        self.session.commit()

    def register(self):
        data = request.get_json()
        email = data['email']
        password = data['password']
        # проверяем, есть ли уже пользователь с таким email
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"message": "User already exists"}), 400
        # создаем нового пользователя и сохраняем в базу данных
        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        # возвращаем идентификатор нового пользователя
        return jsonify({"id": new_user.id}), 201
