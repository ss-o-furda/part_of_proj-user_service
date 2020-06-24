from functools import wraps

from common_lib.response_utils import response
from common_lib.email_utils import send_mail
from flask import request, session, render_template
from flask_api import status
from flask_jwt_extended import decode_token, create_access_token
from flask_restful import Resource
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from user import DB, API, BCRYPT
from user.models.user_model import User
from user.schema.user_schema import UserSchema, ChangePassSchema, ChangeEmailSchema
from user.utils.token_utils import get_user_token, verify_user_token

USER_SCHEMA = UserSchema(exclude=['id'])
USER_GET_SCHEMA = UserSchema(exclude=['id', 'user_password'])
USER_PUT_SCHEMA = UserSchema(exclude=['id', 'user_email', 'user_password', 'user_registration_date'])
PASS_CHANGE_SCHEMA = ChangePassSchema()
EMAIL_CHANGE_SCHEMA = ChangeEmailSchema()
JWT_TOKEN = 'jwt_token'


def send_confirmation_mail(receiver, user_name, link):
    html = render_template('EmailAddressConfirmationMail.html',
                           user_name=user_name,
                           confirmation_link=link)
    send_mail(
        subject='Please confirm your email address',
        receiver=receiver,
        body=html
    )


def send_mail_for_email_change(receiver, user_name, link):
    html = render_template('EmailChangeConfirmationMail.html',
                           user_name=user_name,
                           confirmation_link=link)
    send_mail(
        subject='Please confirm the email change',
        receiver=receiver,
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


class UserProfileResource(Resource):
    @check_access
    def get(self):
        try:
            user_info = decode_token(session[JWT_TOKEN])
            user_id = user_info['identity']
            user = User.find_user(id=user_id)
            if user:
                try:
                    user_data = USER_GET_SCHEMA.dump(user)
                    return response(msg='success',
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
            session.permanent = False
            access_token = create_access_token(new_user.id, expires_delta=False)
            session[JWT_TOKEN] = access_token
            new_user_token = get_user_token(new_user)
            confirmation_link = API.url_for(ConfirmEmailResource, token=new_user_token, _external=True)
            send_confirmation_mail(new_user.user_email, new_user.user_name, confirmation_link)
            return response(msg='New user successfully created.',
                            status=status.HTTP_201_CREATED)
        except IntegrityError:
            DB.session.rollback()
            return response(err='Failed to create new user. Database error.',
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @check_access
    def put(self):
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
    def get(self, token):
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
            return response(err='Invalid token',
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
                change_email_token = get_user_token(user)
                confirmation_link = API.url_for(ChangeEmailConfirmResource,
                                                token=change_email_token,
                                                email=new_user_email,
                                                _external=True)
                send_mail_for_email_change(new_user_email, user.user_name, confirmation_link)
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
