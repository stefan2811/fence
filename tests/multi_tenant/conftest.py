import multiprocessing
import os

from addict import Dict
from authutils.oauth2.client import OAuthClient
import bcrypt
import flask
import pytest

from fence import models
from fence import app_init
import fence.blueprints.login

from tests import test_settings


@pytest.fixture(scope='function')
def fence_oauth_client(app, db_session, oauth_user):
    """
    Register an OAuth client for a new fence instance to use as an oauth client
    of another fence instance.
    """
    url = 'https://fence-test-client.net'
    client_id = 'fence_instance'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=oauth_user.user_id)
        .first()
    )
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user'], _redirect_uris=url, description='',
        is_confidential=True, name='fence_oauth_client'
    ))
    db_session.commit()
    return Dict(client_id=client_id, client_secret=client_secret, url=url)


@pytest.fixture(scope='function')
def fence_client_app(app, fence_oauth_client, db_session):
    """
    A Flask application fixture which acts as a client of the original ``app``
    in a multi-tenant configuration.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    client_app = flask.Flask('client_app')
    app_init(client_app, test_settings, root_dir=root_dir)
    client_app.register_blueprint(
        fence.blueprints.oauth2.blueprint, url_prefix='/oauth2'
    )
    client_app.register_blueprint(
        fence.blueprints.login.blueprint, url_prefix='/login'
    )
    client_app.jwt_public_keys['/'] = client_app.jwt_public_keys.pop(
        client_app.config['BASE_URL']
    )
    client_app.config['BASE_URL'] = '/'
    client_app.config['MOCK_AUTH'] = False
    client_app.config['DEFAULT_LOGIN_URL'] = '/login/fence'
    client_app.config['DEFAULT_LOGIN_URL_REDIRECT_PARAM'] = 'redirect_uri'
    client_app.db.Session = lambda: db_session
    client_app.config['OPENID_CONNECT'] = {
        'fence': {
            'client_id': fence_oauth_client.client_id,
            'client_secret': fence_oauth_client.client_secret,
            'api_base_url': 'http://localhost:50000',
            'authorize_url': 'http://localhost:50000/oauth2/authorize',
            'access_token_url': 'http://localhost:50000/oauth2/token',
            'refresh_token_url': 'http://localhost:50000/oauth2/token',
            'client_kwargs': {
                'scope': 'openid user',
                'redirect_uri': '/client',
            }
        }
    }
    client_app.fence_client = OAuthClient(
        **client_app.config['OPENID_CONNECT']['fence']
    )
    return client_app


@pytest.fixture(scope='function')
def fence_idp_server(request, app, monkeypatch):
    """
    Run an instance of the original fence app in the background to test the
    multi-tenant client code against.
    """

    def target():
        app.run(port=50000, use_reloader=False)

    app_process = multiprocessing.Process(target=target)
    app_process.start()
    request.addfinalizer(app_process.terminate)
    return


@pytest.fixture(scope='session')
def example_keys_response(public_key):
    """
    Return an example response JSON returned from the ``/jwt/keys`` endpoint in
    fence.
    """
    return {
        'keys': [
            ['key-test', public_key],
        ]
    }
