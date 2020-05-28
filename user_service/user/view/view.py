from flask import jsonify, request, sessions, make_response
from flask_restful import Resource
from flask_api import status
from marshmallow import ValidationError
from user import DB, API, BCRYPT
from user.models.user_model import User
from user.schema.user_schema import UserSchema
from common_lib.response_utils import response

USER_SCHEMA = UserSchema(exclude=['id', 'user_registration_date'])


class UserResource(Resource):
    def post(self):
        try:
            new_user = USER_SCHEMA.load(request.json)
        except ValidationError as err:
            return response(err=err.messages, status=status.HTTP_400_BAD_REQUEST)
        try:
            is_exist = DB.session.query(User.id).filter_by(user_name=new_user.user_name).scalar() is not None
        except ValueError as err:
            return make_response(jsonify({err}),
                                 status.HTTP_409_CONFLICT)
        DB.session.add(new_user)
        DB.session.commit()
        return make_response(jsonify({'haha': 'correct benis'}),
                             status.HTTP_201_CREATED)


API.add_resource(UserResource, '/user')
