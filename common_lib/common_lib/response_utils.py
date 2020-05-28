from flask import jsonify, make_response
from flask_api.status import HTTP_200_OK


def response(msg=None, err=None, status=HTTP_200_OK):
    if msg is None:
        msg = ''
    if err is None:
        err = ''

    return make_response(
        jsonify(
            {
                'message': msg,
                'error': err
            }
        ),
        status
    )
