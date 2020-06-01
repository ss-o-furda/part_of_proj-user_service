from functools import wraps

from common_lib.response_utils import response
from flask import request, session
from flask_api import status
from flask_jwt_extended import decode_token, create_access_token
from flask_restful import Resource
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from user import DB, API, BCRYPT
from user.models.user_model import User
from user.schema.user_schema import UserSchema

USER_SCHEMA = UserSchema(exclude=['id'])
JWT_TOKEN = 'jwt_token'


def check_access(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            session[JWT_TOKEN]
        except KeyError:
            return response(err='You are unauthorized.',
                            status=status.HTTP_401_UNAUTHORIZED)
        return func(*args, **kwargs)
    return wrapper


class UserProfileResource(Resource):
    @check_access
    def get(self):
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                try:
                    user_get_schema = UserSchema(exclude=['id', 'user_password'])
                    user_data = user_get_schema.dump(user)
                    return response(msg='success',
                                    data=user_data,
                                    status=status.HTTP_200_OK)
                except ValidationError as err:
                    return response(err=err.messages,
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                raise ValueError
        except ValueError:
            return response(err=f'User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)

    def post(self):
        try:
            if session[JWT_TOKEN]:
                return response(err='You cannot register while you are logged in.',
                                status=status.HTTP_403_FORBIDDEN)
        except KeyError:
            pass
        try:
            new_user = USER_SCHEMA.load(request.json)
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            is_exist = DB.session.query(User.id).filter_by(user_email=new_user.user_email).first() is not None
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

    @check_access
    def put(self):
        try:
            user_put_schema = UserSchema(exclude=['id', 'user_email', 'user_password', 'user_registration_date'])
            new_user_data = user_put_schema.load(request.json)
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                user.user_name = new_user_data.user_name if new_user_data.user_name is not None else user.user_name
                user.user_first_name = new_user_data.user_first_name if new_user_data.user_first_name is not None \
                    else user.user_first_name
                user.user_last_name = new_user_data.user_last_name if new_user_data.user_last_name is not None \
                    else user.user_last_name
            else:
                raise ValueError
        except ValueError:
            return response(err=f'User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)
        try:
            DB.session.commit()
            return response(msg='User data successfully updated.',
                            data=user_put_schema.dump(user),
                            status=status.HTTP_200_OK)
        except IntegrityError:
            DB.session.rollback()
            return response(err='Failed to update user data. Database error.',
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @check_access
    def delete(self):
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                try:
                    DB.session.delete(user)
                    DB.session.commit()
                    session.clear()
                    return response(msg='User successfully deleted.',
                                    status=status.HTTP_200_OK)
                except IntegrityError:
                    DB.session.rollback()
                    return response(err='Failed to delete user data. Database error.',
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                raise ValueError
        except ValueError:
            return response(err=f'User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)


class ChangeEmailResource(Resource):
    @check_access
    def post(self):
        pass

    @check_access
    def put(self):
        pass


class ChangePasswordResource(Resource):
    @check_access
    def put(self):
        pass


API.add_resource(UserProfileResource, '/user')
API.add_resource(ChangeEmailResource, '/user/change_email')
API.add_resource(ChangePasswordResource, '/user/change_password')
