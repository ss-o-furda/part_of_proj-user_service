from user import APP
from user.view.view import (UserProfileResource,
                            ChangePasswordResource,
                            ConfirmEmailResource,
                            ChangeEmailQueryResource,
                            ChangeEmailConfirmResource,)


if __name__ == '__main__':
    APP.run(debug=True)
