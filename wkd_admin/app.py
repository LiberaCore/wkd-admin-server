import os
from flask import Flask, request, render_template, redirect, Response
from flask_restplus import Api, Resource, fields, errors
from config import WKD_KEY_STORE, GPG_TEMP, ADMIN_TOKEN, ALLOWED_DOMAINS, RATE_LIMIT
from key_backend import KeyInspector, HKPTools, WKDFileStore, Utils
import base64
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
from werkzeug.contrib.fixers import ProxyFix


# Authorization configuration
authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-Key'
    }
}

# Initialize Flask App
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
api = Api(app = app,
          version = "0.1",
          title = "WKD Admin API",
          description = "API to manage OpenPGP public keys in a Web Key Directory",
          security='apikey',
          authorizations=authorizations,
          doc='/docs')



# Configure Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=RATE_LIMIT,
)

# Create required directories

if not os.path.exists(WKD_KEY_STORE):
    print('%s does not exist. Creating...' % WKD_KEY_STORE)
    os.makedirs(WKD_KEY_STORE, 0o700)

if not os.path.exists(GPG_TEMP):
    print('%s does not exist. Creating...' % GPG_TEMP)
    os.makedirs(GPG_TEMP, 0o700)

# //TODO: create folder for each domain
for allowed_domain in ALLOWED_DOMAINS:
    if not os.path.exists(os.path.join(os.path.abspath(WKD_KEY_STORE), allowed_domain)):
        print('%s does not exist. Creating...' % os.path.join(os.path.abspath(WKD_KEY_STORE), allowed_domain))
        os.makedirs(os.path.join(os.path.abspath(WKD_KEY_STORE), allowed_domain), 0o700)


key_model = api.model('Key Model',
          {'key':   fields.String(required = True,
                    description="key of the person",
                    help="Key cannot be blank.")})


# Add admin namespace
admin_ns = api.namespace('admin', description='Admin APIs')

# load wkd-store
wkd_store = WKDFileStore(WKD_KEY_STORE)

# token_required decorator for Token check
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None
        if 'X-API-Key' in request.headers:
            token = request.headers['X-API-KEY']

        if not token:
            return {'message': 'Token is missing.'}, 401

        if token != ADMIN_TOKEN:
            return {'message': 'Invalid token.'}, 401

        return f(*args, **kwargs)
    return decorated

# Admin API Endpoint and methods
@admin_ns.route("/key/<string:email>")
class AdminKeyClass(Resource):
    @token_required
    @api.doc(responses={ 200: 'OK', 400: 'Invalid Argument', 500: 'Mapping Key Error' },
    params={'email': 'email to lookup'})
    def get(self, email):
        #wkd_store = WKDFileStore(WKD_KEY_STORE)

        if wkd_store.is_key_available(email):
            return {
                "status": True
            }
        else:
            return {
                "status": False
            }

    @api.doc(responses={ 200: 'OK', 400: 'Invalid Argument', 500: 'Mapping Key Error' },
    params={
     'email': 'email to lookup'
     }
    )
    @api.expect(key_model)
    @token_required
    def post(self, email):
        try:
            if Utils.is_email_allowed(email, ALLOWED_DOMAINS) is False:
                admin_ns.abort(500, e.__doc__, status = "Could not save information. Email and key uid do not match or domain is not allowed.", statusCode = "500")
            wkd_store = WKDFileStore(WKD_KEY_STORE)
            wkd_store.add(email, base64.b64decode(request.json['key']))
            return {
            "status": True
            }

        except KeyError as e:
            admin_ns.abort(500, e.__doc__, status = "Could not save information", statusCode = "500")
        except ValueError as e:
            admin_ns.abort(500, e.__doc__, status = "Could not save information. Email and key uid do not match or domain is not allowed.", statusCode = "500")
        except Exception as e:
            admin_ns.abort(400, e.__doc__, status = "Could not save information", statusCode = "400")


    @api.doc(responses={ 200: 'OK', 400: 'Invalid Argument', 500: 'Mapping Key Error' },
    params={'email': 'email to lookup'})
    @token_required
    def delete(self, email):
        try:
            #wkd_store = WKDFileStore(WKD_KEY_STORE)
            _status = wkd_store.delete(email)
            return {
                "status": _status
            }
        except KeyError as e:
            admin_ns.abort(500, e.__doc__, status = "Could not save information", statusCode = "500")
        except ValueError as e:
            admin_ns.abort(500, e.__doc__, status = "Could not save information. Email and key uid do not match.", statusCode = "500")
        except Exception as e:
            admin_ns.abort(400, e.__doc__, status = "Could not save information", statusCode = "400")


if __name__ == '__main__':
    app.run(debug=True)
