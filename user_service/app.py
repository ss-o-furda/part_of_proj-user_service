from user import APP
from user.view.view import UserProfileResource, ChangeEmailResource, ChangePasswordResource

if __name__ == '__main__':
    APP.run(debug=True)
