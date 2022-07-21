import hashlib
import hmac
from http import HTTPStatus

from flask import Flask, request
from werkzeug.exceptions import Forbidden


app = Flask(__name__)

YOUR_SECRET_KEY = b'YOUR_SECRET_KEY'


@app.route('/your-webhook-callback', methods=['POST'])
def your_webhook_callback():

    # construct expected HMAC signature
    base_string = ''.join([
        request.headers['X-Innotescus-Version'],
        request.headers['X-Innotescus-Timestamp'],
        request.data,
    ])
    expected = hmac.new(YOUR_SECRET_KEY, base_string.encode(), hashlib.sha256).hexdigest()

    # verify signature or fail request 
    actual = request.headers['X-Innotescus-Signature']
    if not hmac.compare_digest(expected, actual):
        raise Forbidden('HMAC Signature Validation Failed')

    # TODO: place whatever code you like here to handle the webhook

    # return an HTTP 200 response -- the response body and type DO NOT matter
    # if a 200 response is not received, innotescus will try to call your
    # webhook again at a later point
    return '', HTTPStatus.OK


if __name__ == '__main__':
    app.run()
