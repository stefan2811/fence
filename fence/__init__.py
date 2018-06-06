from collections import OrderedDict
import os
from yaml import safe_load as yaml_load

from authutils.oauth2.client import OAuthClient
import flask
from flask.ext.cors import CORS
from flask_sqlalchemy_session import flask_scoped_session, current_session
import urlparse
from userdatamodel.driver import SQLAlchemyDriver

import cirrus
from fence.auth import logout, build_redirect_url
from fence.errors import UserError
from fence.jwt import keys
from fence.models import migrate
from fence.oidc.server import server
from fence.resources.aws.boto_manager import BotoManager
from fence.resources.openid.google_oauth2 import Oauth2Client as GoogleClient
from fence.resources.storage import StorageManager
from fence.resources.user.user_session import UserSessionInterface
from fence.restful import handle_error
from fence.utils import random_str
import fence.blueprints.admin
import fence.blueprints.data
import fence.blueprints.login
import fence.blueprints.oauth2
import fence.blueprints.storage_creds
import fence.blueprints.user
import fence.blueprints.well_known
import fence.blueprints.link
import fence.client


app = flask.Flask(__name__)
CORS(app=app, headers=['content-type', 'accept'], expose_headers='*')


def app_config(
        app, settings='fence.settings', root_dir=None, config_path=None,
        file_name=None):
    """
    Set up the config for the Flask app.
    """
    if root_dir is None:
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

    app.config.from_object(settings)

    search_folders = app.config.get('CONFIG_SEARCH_FOLDERS', [])
    file_name = file_name or 'config.yaml'
    config_path = config_path or get_config_path(search_folders, file_name)
    app.logger.info('Using configuration: {}'.format(config_path))
    data = yaml_load(open(config_path))

    app.config.update(data)

    if 'ROOT_URL' not in app.config:
        url = urlparse.urlparse(app.config['BASE_URL'])
        app.config['ROOT_URL'] = '{}://{}'.format(url.scheme, url.netloc)

    app.keypairs = []
    if 'AWS_CREDENTIALS' in app.config and len(app.config['AWS_CREDENTIALS']) > 0:
        value = app.config['AWS_CREDENTIALS'].values()[0]
        app.boto = BotoManager(value, logger=app.logger)
        app.register_blueprint(
            fence.blueprints.data.blueprint, url_prefix='/data'
        )

    for kid, (public, private) in OrderedDict(app.config['JWT_KEYPAIR_FILES']).iteritems():
        public_filepath = os.path.join(root_dir, public)
        private_filepath = os.path.join(root_dir, private)
        with open(public_filepath, 'r') as f:
            public_key = f.read()
        with open(private_filepath, 'r') as f:
            private_key = f.read()
        app.keypairs.append(keys.Keypair(
            kid=kid, public_key=public_key, private_key=private_key
        ))

    app.jwt_public_keys = {
        app.config['BASE_URL']: OrderedDict([
            (str(keypair.kid), str(keypair.public_key))
            for keypair in app.keypairs
        ])
    }

    # allow authlib traffic on http for development if enabled. By default
    # it requires https.
    #
    # NOTE: use when fence will be deployed in such a way that fence will
    #       only receive traffic from internal clients, and can safely use HTTP
    if app.config.get('AUTHLIB_INSECURE_TRANSPORT'):
        os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'

    # TODO should we do generic template replacing or use a template engine?

    # BASE_URL replacement
    server_name = app.config.get('SERVER_NAME')
    if server_name:
        provided_value = app.config['SERVER_NAME']
        app.config['SERVER_NAME'] = (
            provided_value.replace('{{BASE_URL}}', app.config['BASE_URL'])
        )

    google_redirect = (
        app.config.get('OPENID_CONNECT', {})
        .get('google', {})
        .get('redirect_url')
    )
    if google_redirect:
        provided_value = app.config['OPENID_CONNECT']['google']['redirect_url']
        app.config['OPENID_CONNECT']['google']['redirect_url'] = (
            provided_value.replace('{{BASE_URL}}', app.config['BASE_URL'])
        )

    default_logout = app.config.get('DEFAULT_LOGIN_URL')
    if default_logout:
        provided_value = app.config['DEFAULT_LOGIN_URL']
        app.config['DEFAULT_LOGIN_URL'] = (
            provided_value.replace('{{BASE_URL}}', app.config['BASE_URL'])
        )

    shib_url = app.config.get('SSO_URL')
    if shib_url:
        provided_value = app.config['SSO_URL']
        app.config['SSO_URL'] = (
            provided_value.replace('{{BASE_URL}}', app.config['BASE_URL'])
        )

    access_token_url = (
        app.config.get('OPENID_CONNECT', {})
        .get('fence', {})
        .get('client_kwargs', {})
        .get('redirect_uri')
    )
    if access_token_url:
        provided_value = (
            app.config['OPENID_CONNECT']['fence']['client_kwargs']['redirect_uri']
        )
        app.config['OPENID_CONNECT']['fence']['client_kwargs']['redirect_uri'] = (
            provided_value.replace('{{BASE_URL}}', app.config['BASE_URL'])
        )

    # api_base_url replacing
    api_base_url = (
        app.config.get('OPENID_CONNECT', {})
        .get('fence', {})
        .get('api_base_url')
    )
    if api_base_url is not None:
        authorize_url = (
            app.config.get('OPENID_CONNECT', {})
            .get('fence', {})
            .get('authorize_url')
        )
        if authorize_url:
            provided_value = (
                app.config['OPENID_CONNECT']['fence']['authorize_url']
            )
            app.config['OPENID_CONNECT']['fence']['authorize_url'] = (
                provided_value.replace('{{api_base_url}}', api_base_url)
            )

        access_token_url = (
            app.config.get('OPENID_CONNECT', {})
            .get('fence', {})
            .get('access_token_url')
        )
        if access_token_url:
            provided_value = (
                app.config['OPENID_CONNECT']['fence']['access_token_url']
            )
            app.config['OPENID_CONNECT']['fence']['access_token_url'] = (
                provided_value.replace('{{api_base_url}}', api_base_url)
            )

        refresh_token_url = (
            app.config.get('OPENID_CONNECT', {})
            .get('fence', {})
            .get('refresh_token_url')
        )
        if refresh_token_url:
            provided_value = (
                app.config['OPENID_CONNECT']['fence']['refresh_token_url']
            )
            app.config['OPENID_CONNECT']['fence']['refresh_token_url'] = (
                provided_value.replace('{{api_base_url}}', api_base_url)
            )

    cirrus.config.config.update(**app.config.get('CIRRUS_CFG', {}))


def get_config_path(search_folders, file_name='config.yaml'):
    for folder in search_folders:
        config_path = os.path.join(folder, file_name)
        if os.path.exists(config_path):
            return config_path

    # if we haven't returned a path by now, fence couldn't find the config
    raise IOError(
        'Could not find config.yaml. Searched in the following locations: '
        '{}'.format(str(search_folders)))


def app_register_blueprints(app):
    app.register_blueprint(fence.blueprints.oauth2.blueprint, url_prefix='/oauth2')
    app.register_blueprint(fence.blueprints.user.blueprint, url_prefix='/user')

    creds_blueprint = fence.blueprints.storage_creds.make_creds_blueprint()
    app.register_blueprint(creds_blueprint, url_prefix='/credentials')

    app.register_blueprint(fence.blueprints.admin.blueprint, url_prefix='/admin')
    app.register_blueprint(fence.blueprints.well_known.blueprint, url_prefix='/.well-known')

    login_blueprint = fence.blueprints.login.make_login_blueprint(app)
    app.register_blueprint(login_blueprint, url_prefix='/login')
    link_blueprint = fence.blueprints.link.make_link_blueprint()
    app.register_blueprint(link_blueprint, url_prefix='/link')

    @app.route('/')
    def root():
        """
        Register the root URL.
        """
        endpoints = {
            'oauth2 endpoint': '/oauth2',
            'user endpoint': '/user',
            'keypair endpoint': '/credentials'
        }
        return flask.jsonify(endpoints)

    @app.route('/logout')
    def logout_endpoint():
        root = app.config.get('BASE_URL', '')
        request_next = flask.request.args.get('next', root)
        if request_next.startswith('https') or request_next.startswith('http'):
            next_url = request_next
        else:
            next_url = build_redirect_url(app.config.get('ROOT_URL', ''), request_next)
        return logout(next_url=next_url)

    @app.route('/jwt/keys')
    def public_keys():
        """
        Return the public keys which can be used to verify JWTs signed by fence.

        The return value should look like this:

            {
                "keys": [
                    {
                        "key-01": " ... [public key here] ... "
                    }
                ]
            }
        """
        return flask.jsonify({
            'keys': [
                (keypair.kid, keypair.public_key)
                for keypair in app.keypairs
            ]
        })


def app_sessions(app):
    app.url_map.strict_slashes = False
    app.db = SQLAlchemyDriver(app.config['DB'])
    migrate(app.db)
    session = flask_scoped_session(app.db.Session, app)  # noqa
    app.storage_manager = StorageManager(
        app.config['STORAGE_CREDENTIALS'],
        logger=app.logger
    )
    enabled_idp_ids = (
        app.config['ENABLED_IDENTITY_PROVIDERS']['providers'].keys()
    )
    # Add OIDC client for Google if configured.
    configured_google = (
        'OPENID_CONNECT' in app.config
        and 'google' in app.config['OPENID_CONNECT']
        and 'google' in enabled_idp_ids
    )
    if configured_google:
        app.google_client = GoogleClient(
            app.config['OPENID_CONNECT']['google'],
            HTTP_PROXY=app.config.get('HTTP_PROXY'),
            logger=app.logger
        )
    # Add OIDC client for multi-tenant fence if configured.
    configured_fence = (
        'OPENID_CONNECT' in app.config
        and 'fence' in app.config['OPENID_CONNECT']
        and 'fence' in enabled_idp_ids
    )
    if configured_fence:
        app.fence_client = OAuthClient(**app.config['OPENID_CONNECT']['fence'])
    app.session_interface = UserSessionInterface()


def app_init(app, settings='fence.settings', root_dir=None):
    app_config(app, settings=settings, root_dir=root_dir)
    app_sessions(app)
    app_register_blueprints(app)
    server.init_app(app)


@app.errorhandler(Exception)
def user_error(error):
    """
    Register an error handler for general exceptions.
    """
    return handle_error(error)


@app.before_request
def check_csrf():
    has_auth = 'Authorization' in flask.request.headers
    no_username = not flask.session.get('username')
    if has_auth or no_username:
        return
    if not app.config.get('ENABLE_CSRF_PROTECTION', True):
        return
    # cookie based authentication
    if flask.request.method != 'GET':
        csrf_header = flask.request.headers.get('x-csrf-token')
        csrf_cookie = flask.request.cookies.get('csrftoken')
        referer = flask.request.headers.get('referer')
        flask.current_app.logger.debug('HTTP REFERER ' + referer)
        if not all([csrf_cookie, csrf_header, csrf_cookie == csrf_header, referer]):
            raise UserError("CSRF verification failed. Request aborted")


@app.after_request
def set_csrf(response):
    """
    Create a cookie for CSRF protection if one does not yet exist.
    """
    if not flask.request.cookies.get('csrftoken'):
        secure = app.config.get('SESSION_COOKIE_SECURE', True)
        response.set_cookie('csrftoken', random_str(40), secure=secure)

    if flask.request.method in ['POST', 'PUT', 'DELETE']:
        current_session.commit()
    return response
