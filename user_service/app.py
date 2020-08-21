from user import APP
from user.view.view import (UserProfileResource,
                            ChangePasswordResource,
                            ConfirmEmailResource,
                            ChangeEmailQueryResource,
                            ChangeEmailConfirmResource,)


if __name__ == '__main__':
    APP.run(host='0.0.0.0',
            port='8000',
            debug=True)
