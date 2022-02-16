import hashlib
import hmac
from http import HTTPStatus

from flask import Flask, request
from innotescus import client_factory
from werkzeug.exceptions import Forbidden


app = Flask(__name__)

YOUR_SECRET_KEY = b'YOUR_SECRET_KEY'


@app.route('/job', methods=['POST'])
def export_ready():
    """ Example handler for the innotescus "EXPORT READY" webhook.
    """

    # construct expected HMAC signature
    base_string = ':'.join([
        request.headers['X-Innotescus-Version'],
        request.headers['X-Innotescus-Timestamp'],
        request.data,
    ])
    expected = hmac.new(YOUR_SECRET_KEY, base_string.encode(), hashlib.sha256).hexdigest()

    # verify signature or fail request
    actual = request.headers['X-Innotescus-Signature']
    if not hmac.compare_digest(expected, actual):
        raise Forbidden('HMAC Signature Validation Failed')

    # read the job_id from the request payload
    job_id = request.json['job_id']
    job_type = request.json['type']
    job_status = request.json['status']

    if job_type == 'export' and job_status == 'ready':
        # use the innotescus client to download the export
        # WARNING: your download MUST be completed within 5
        # minutes or Innotescus will time out.
        c = client_factory()
        c.download_export(
            job_id=job_id,
            download_path='/some/path'
        )

    # return an HTTP 200 response -- the response body and type DO NOT matter
    # if a 200 response is not received, innotescus will try to call your
    # webhook again at a later point
    return '', HTTPStatus.OK


if __name__ == '__main__':
    app.run()
