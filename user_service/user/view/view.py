from flask import jsonify, request, session, make_response
from flask_restful import Resource
from flask_jwt_extended import decode_token, create_access_token
from flask_api import status
from marshmallow import ValidationError
from user import DB, API, BCRYPT
from user.models.user_model import User
from user.schema.user_schema import UserSchema
from common_lib.response_utils import response
from sqlalchemy.exc import IntegrityError

USER_SCHEMA = UserSchema(exclude=['id', 'user_registration_date'])
JWT_TOKEN = 'jwt_token'


class UserResource(Resource):

    def post(self):

        try:
            new_user = USER_SCHEMA.load(request.json)
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            is_exist = DB.session.query(User.id).filter_by(user_name=new_user.user_email).scalar() is not None
            if is_exist:
                raise ValueError
        except ValueError as err:
            return response(err='User with this email already exists.',
                            status=status.HTTP_409_CONFLICT)

        try:
            new_user.user_password = BCRYPT.generate_password_hash(new_user.user_password, round(10)).decode('utf-8')
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            DB.session.add(new_user)
            DB.session.commit()
            session.permanent = True
            access_token = create_access_token(new_user.id, expires_delta=False)
            session[JWT_TOKEN] = access_token
            return response(msg='New user successfully created.',
                            status=status.HTTP_201_CREATED)
        except IntegrityError:
            DB.session.rollback()
            return response(err='Failed to create new user. Database error.',
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


API.add_resource(UserResource, '/user')
