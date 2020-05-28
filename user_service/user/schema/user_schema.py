from marshmallow import fields
from user import MARSHMALLOW
from user.models.user_model import User


class UserSchema(MARSHMALLOW.ModelSchema):
    class Meta:
        model = User
