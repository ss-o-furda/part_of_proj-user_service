from itsdangerous import TimedJSONWebSignatureSerializer, SignatureExpired
from user import APP
from user.models.user_model import User


def get_user_token(user, expires_sec=3600):
    hash_token = TimedJSONWebSignatureSerializer(APP.config['SECRET_KEY'], expires_sec)
    return hash_token.dumps({
        'user_email': user.user_email
    }).decode('utf-8')


def verify_user_token(token):
    hash_token = TimedJSONWebSignatureSerializer(APP.config['SECRET_KEY'])
    try:
        user_email = hash_token.loads(token)['user_email']
    except SignatureExpired:
        raise TimeoutError
    return User.find_user(user_email=user_email)
