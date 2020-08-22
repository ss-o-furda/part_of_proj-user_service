from datetime import timedelta
from functools import wraps

from common_lib.email_utils import send_mail
from common_lib.response_utils import response
from flask import request, session, render_template
from flask_api import status
from flask_jwt_extended import decode_token, create_access_token
from flask_restful import Resource
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from user import DB, API, BCRYPT, APP
from user.models.user_model import User
from user.schema.user_schema import UserSchema, ChangePassSchema, ChangeEmailSchema, UserLoginSchema
from user.utils.token_utils import get_user_token, verify_user_token

USER_SCHEMA = UserSchema(exclude=['id'])
USER_GET_SCHEMA = UserSchema(exclude=['id', 'user_password'])
USER_PUT_SCHEMA = UserSchema(exclude=['id', 'user_email', 'user_password', 'user_confirmed', 'user_registration_date'])
PASS_CHANGE_SCHEMA = ChangePassSchema()
EMAIL_CHANGE_SCHEMA = ChangeEmailSchema()
USER_LOGIN_SCHEMA = UserLoginSchema()
JWT_TOKEN = 'jwt_token'


def send_confirmation_mail(user):
    new_user_token = get_user_token(user)
    confirmation_link = API.url_for(ConfirmEmailResource,
                                    token=new_user_token,
                                    _external=True)
    html = render_template('EmailAddressConfirmationMail.html',
                           user_name=user.user_name,
                           confirmation_link=confirmation_link)
    send_mail(
        subject='Please confirm your email address',
        receiver=user.user_email,
        body=html
    )


def send_mail_for_email_change(user, new_user_email):
    change_email_token = get_user_token(user)
    confirmation_link = API.url_for(ChangeEmailConfirmResource,
                                    token=change_email_token,
                                    email=new_user_email,
                                    _external=True)
    html = render_template('EmailChangeConfirmationMail.html',
                           user_name=user.user_name,
                           confirmation_link=confirmation_link)
    send_mail(
        subject='Please confirm the email change',
        receiver=new_user_email,
        body=html
    )


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


class UserLogoutResource(Resource):
    """
    Resource for user logout.
    :method:
        get:
            :request params: empty
            :responses:
                status: 200
                    {
                        "message": "Logout successful.",
                        "error": "",
                        "data": ""
                    }
                status: 401
                    {
                        "message": "",
                        "error": "You are unauthorized.",
                        "data": ""
                    }
    """

    @check_access
    def get(self):
        """Method for logout"""
        session.clear()
        return response(msg='Logout successful.',
                        status=status.HTTP_200_OK)


class UserLoginResource(Resource):
    """
    Resource for user login.
    :method:
        post:
            :request params:
                {
                    user_login: string,
                    user_password: string
                }
            :responses:
                status: 200
                    {
                        "message": "Login successful.",
                        "error": "",
                        "data": ""
                    }
                status: 400
                    {
                        "message": "",
                        "error": "Invalid password.",
                        "data": ""
                    }
                status: 401
                    {
                        "message": "",
                        "error": "You are unauthorized.",
                        "data": ""
                    }
                status: 404
                    {
                        "message": "",
                        "error": "User with this email does not exist.",
                        "data": ""
                    }
    """

    def post(self):
        """Method for login"""
        try:
            input_data = USER_LOGIN_SCHEMA.load(request.json)
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.find_user(user_email=input_data['user_email'])
            if user:
                try:
                    check_password = BCRYPT.check_password_hash(user.user_password, input_data['user_password'])
                    if not check_password:
                        raise AttributeError
                except AttributeError:
                    return response(err='Invalid password.',
                                    status=status.HTTP_400_BAD_REQUEST)
                session.permanent = True
                APP.permanent_session_lifetime = timedelta(minutes=30)
                session[JWT_TOKEN] = create_access_token(user.id)
                return response(msg='Login successful.',
                                status=status.HTTP_200_OK)
            else:
                raise ValueError
        except ValueError:
            return response(err='User with this email does not exist.',
                            status=status.HTTP_404_NOT_FOUND)


class UserProfileResource(Resource):
    """
    Resource for interaction with user.
    :method:
        get:
            :request param: empty
            :responses:
                status: 200
                    {
                        "message": "Successful receipt.",
                        "error": "",
                        "data": {
                                    "user_name": string,
                                    "user_email": string,
                                    "user_first_name": string,
                                    "user_last_name": string,
                                    "user_confirmed": boolean,
                                    "user_registration_date": string
                                  }
                    }
                status: 400
                    {
                        "message": "",
                        "error": string,
                        "data": ""
                    }
                status: 401
                    {
                        "message": "",
                        "error": "You are unauthorized.",
                        "data": ""
                    }
                status: 404
                    {
                        "message": "",
                        "error": "User with this id does not exist.",
                        "data": ""
                    }
        post:
            :request param:
                {
                    "user_name": string,
                    "user_email": string,
                    "user_password": string,
                    "user_first_name": string,
                    "user_last_name": string,
                    "user_confirmed": boolean,
                    "user_registration_date": string
                }
            :responses:
                status: 201
                    {
                        "message": "New user successfully created.",
                        "error": "",
                        "data": ""
                    }
                status: 400
                    {
                        "message": "",
                        "error": string,
                        "data": ""
                    }
                status: 403
                    {
                        "message": "",
                        "error": "You cannot register while you are logged in.",
                        "data": ""
                    }
                status: 409
                    {
                        "message": "",
                        "error": "User with this email already exists.",
                        "data": ""
                    }
                status: 500
                    {
                        "message": "",
                        "error": "Failed to create new user. Database error.",
                        "data": ""
                    }
        put:
            :request param:
                {
                    "user_name": string,
                    "user_first_name": string,
                    "user_last_name": string
                }
            :responses:
                status: 200
                    {
                        "message": "User data successfully updated.",
                        "error": "",
                        "data": {
                                    "user_name": string,
                                    "user_first_name": string,
                                    "user_last_name": string
                                }
                    }
                status: 400
                    {
                        "message": "",
                        "error": string,
                        "data": ""
                    }
                status: 401
                    {
                        "message": "",
                        "error": "You are unauthorized.",
                        "data": ""
                    }
                status: 404
                    {
                        "message": "",
                        "error": "User with this id does not exists.",
                        "data": ""
                    }
                status: 500
                    {
                        "message": "",
                        "error": "Failed to update user data. Database error.",
                        "data": ""
                    }
        delete:
            :request params: empty
            :responses:
                status: 200
                    {
                        "message": "User successfully deleted.",
                        "error": "",
                        "data": ""
                    }
                status: 401
                    {
                        "message": "",
                        "error": "You are unauthorized.",
                        "data": ""
                    }
                status: 404
                    {
                        "message": "",
                        "error": "User with this id does not exists.",
                        "data": ""
                    }
                status: 500
                    {
                        "message": "",
                        "error": "Failed to delete user data. Database error.",
                        "data": ""
                    }
    """

    @check_access
    def get(self):
        """Method return information about user"""
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                try:
                    user_data = USER_GET_SCHEMA.dump(user)
                    return response(msg='Successful receipt.',
                                    data=user_data,
                                    status=status.HTTP_200_OK)
                except ValidationError as err:
                    return response(err=err.messages,
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                raise ValueError
        except ValueError:
            return response(err='User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)

    def post(self):
        """Method to create new user"""
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
        except ValueError:
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
            APP.permanent_session_lifetime = timedelta(minutes=30)
            session[JWT_TOKEN] = create_access_token(new_user.id)
            send_confirmation_mail(new_user)
            return response(msg='New user successfully created.',
                            status=status.HTTP_201_CREATED)
        except IntegrityError:
            DB.session.rollback()
            return response(err='Failed to create new user. Database error.',
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @check_access
    def put(self):
        """Method to update user data"""
        try:
            new_user_data = USER_PUT_SCHEMA.load(request.json)
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
            return response(err='User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)
        try:
            DB.session.commit()
            return response(msg='User data successfully updated.',
                            data=USER_PUT_SCHEMA.dump(user),
                            status=status.HTTP_200_OK)
        except IntegrityError:
            DB.session.rollback()
            return response(err='Failed to update user data. Database error.',
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @check_access
    def delete(self):
        """Method to delete user from system/db"""
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
            return response(err='User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)


class ConfirmEmailResource(Resource):
    """
    Resource allows to confirm user email address
    :method:
        get:
            :request params:
                in: "query"
                name: "token"
                description: "JSONWebSignatureSerializer token"
            :responses:
                status: 200
                    {
                        "message": "Email confirmed.",
                        "error": "",
                        "data": ""
                    }
                status: 400
                    {
                        "message": "",
                        "error": "Your token has expired.",
                        "data": ""
                    }
                status: 400
                    {
                        "message": "",
                        "error": "Invalid token.",
                        "data": ""
                    }
                status: 500
                    {
                        "message": "",
                        "error": "Failed to confirm email address. Database error.",
                        "data": ""
                    }
    """
    def get(self, token):
        """Method to confirm user email"""
        try:
            verified_user = verify_user_token(token)
            if verified_user:
                try:
                    verified_user.user_confirmed = True
                    DB.session.commit()
                    return response(msg='Email confirmed.',
                                    status=status.HTTP_200_OK)
                except IntegrityError:
                    DB.session.rollback()
                    return response(msg='Failed to confirm email address. Database error.',
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                raise ValueError
        except TimeoutError:
            return response(err='Your token has expired.',
                            status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            return response(err='Invalid token.',
                            status=status.HTTP_400_BAD_REQUEST)


class ChangeEmailConfirmResource(Resource):
    def get(self, token, email):
        try:
            verified_user = verify_user_token(token)
            if verified_user:
                try:
                    verified_user.user_email = email
                    DB.session.commit()
                    return response(msg='Email changed successfully.',
                                    status=status.HTTP_200_OK)
                except IntegrityError:
                    DB.session.rollback()
                    return response(msg='Failed to change email address. Database error.',
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except TimeoutError:
            return response(err='Your token has expired.',
                            status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            return response(err='Invalid token',
                            status=status.HTTP_400_BAD_REQUEST)


class ChangeEmailQueryResource(Resource):
    @check_access
    def post(self):
        try:
            json_with_new_email = EMAIL_CHANGE_SCHEMA.load(request.json)
            new_user_email = json_with_new_email['new_user_email']
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                send_mail_for_email_change(user, new_user_email)
                return response(msg='A confirmation email has been sent to your new email.',
                                status=status.HTTP_200_OK)
            else:
                raise ValueError
        except ValueError:
            return response(err='User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)


class ChangePasswordResource(Resource):
    @check_access
    def put(self):
        try:
            pass_change_data = PASS_CHANGE_SCHEMA.load(request.json)
        except ValidationError as err:
            return response(err=err.messages,
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                compare_passwords = BCRYPT.check_password_hash(user.user_password, pass_change_data['old_user_pass'])
                if not compare_passwords:
                    return response(err='Invalid password.',
                                    status=status.HTTP_400_BAD_REQUEST)
                else:
                    try:
                        user.user_password = BCRYPT.generate_password_hash(pass_change_data['new_user_pass'],
                                                                           round(10)).decode('utf-8')
                        DB.session.commit()
                        return response(msg='Password changed successfully.',
                                        status=status.HTTP_200_OK)
                    except IntegrityError:
                        DB.session.rollback()
                        return response(err='Failed to change password. Database error.',
                                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                raise ValueError
        except ValueError:
            return response(err='User with this id does not exists.',
                            status=status.HTTP_404_NOT_FOUND)


API.add_resource(UserProfileResource, '/user')
API.add_resource(ConfirmEmailResource, '/user/confirm_email/<token>')
API.add_resource(ChangeEmailQueryResource, '/user/change_email')
API.add_resource(ChangeEmailConfirmResource, '/user/change_email/<token>/<email>')
API.add_resource(ChangePasswordResource, '/user/change_password')
API.add_resource(UserLoginResource, '/login')
API.add_resource(UserLogoutResource, '/logout')
