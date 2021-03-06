from marshmallow import fields, validate, validates_schema, ValidationError
from user import MARSHMALLOW
from user.models.user_model import User


class UserSchema(MARSHMALLOW.ModelSchema):
    user_password = fields.Str(validate=validate.Length(6, 255))
    user_email = fields.Str(validate=validate.Email())

    class Meta:
        model = User


class ChangePassSchema(MARSHMALLOW.Schema):
    old_user_pass = fields.Str(validate=validate.Length(6, 255))
    new_user_pass = fields.Str(validate=validate.Length(6, 255))
    new_user_pass_confirm = fields.Str(validate=validate.Length(6, 255))

    @validates_schema
    def confirm_password(self, data, **kwargs):
        if data['new_user_pass'] != data['new_user_pass_confirm']:
            raise ValidationError('Incorrect password confirmation.')


class ChangeEmailSchema(MARSHMALLOW.Schema):
    new_user_email = fields.Str(validate=validate.Email())


class UserLoginSchema(MARSHMALLOW.Schema):
    user_email = fields.Str(validate=validate.Email())
    user_password = fields.Str(validate=validate.Length(6, 255))
