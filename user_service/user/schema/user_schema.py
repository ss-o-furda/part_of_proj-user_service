from marshmallow import fields, validate
from user import MARSHMALLOW
from user.models.user_model import User


class UserSchema(MARSHMALLOW.ModelSchema):
    user_password = fields.Str(validate=validate.Length(6, 255))
    user_email = fields.Str(validate=validate.Email())

    class Meta:
        model = User
