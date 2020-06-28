from flask import jsonify, make_response


def response(status, msg=None, err=None, data=None):
    if msg is None:
        msg = ''
    if err is None:
        err = ''
    if data is None:
        data = ''

    return make_response(
        jsonify(
            {
                'message': msg,
                'error': err,
                'data': data
            }
        ),
        status
    )
