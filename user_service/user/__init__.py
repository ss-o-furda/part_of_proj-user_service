from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate, MigrateCommand
from flask_restful import Api
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy

APP = Flask(__name__)
API = Api(APP)
CORS(APP, supports_credentials=True)
BCRYPT = Bcrypt(APP)
JWT = JWTManager(APP)

POSTGRES = {
    'user': 'postgres',
    'pass': '',
    'db': 'userdb',
    'host': 'localhost',
    'port': '5432'
}

APP.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
APP.config['SQLALCHEMY_DATABASE_URI'] = f"postgres+psycopg2://{POSTGRES['user']}:{POSTGRES['pass']}@" \
                                        f"{POSTGRES['host']}:{POSTGRES['port']}/{POSTGRES['db']}"
APP.config['SECRET_KEY'] = 'my_secret_key'
APP.config['JWT_TOKEN_LOCATION'] = ['cookies']

DB = SQLAlchemy(APP)
MARSHMALLOW = Marshmallow(APP)
MIGRATE = Migrate(APP, DB)
MANAGER = Manager(APP)
MANAGER.add_command('db', MigrateCommand)

from user.models.user_model import User
