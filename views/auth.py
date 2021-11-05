from flask import request
from flask_restx import Resource, Namespace

from implemented import auth_service

auth_ns = Namespace('auth')


@auth_ns.route('/login')
class AuthView(Resource):
    def post(self):
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not all([email, password]):
           return "", 400

        token = auth_service.generate_tokens(email, password)

        return token, 201

    def put(self):
        data = request.json
        token = data.get('refresh_token')
        tokens = auth_service.approve_refresh_token(token)
        return tokens, 201


