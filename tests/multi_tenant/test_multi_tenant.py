"""
It is very recommended to look at the multi-tenant flow diagram before looking
at this code; otherwise it is likely for none of this to make any sense.
"""

import urllib

import fence


def test_redirect_from_oauth(fence_client_app, oauth_client):
    """
    Test that the ``/oauth2/authorize`` endpoint on the client redirects to the
    ``/login/fence`` endpoint, also on the client.
    """
    with fence_client_app.test_client() as client:
        data = {
            'client_id': oauth_client.client_id,
            'redirect_uri': oauth_client.url,
            'response_type': 'code',
            'scope': 'openid user',
            'state': fence.utils.random_str(10),
            'confirm': 'yes',
        }
        response_oauth_authorize = client.post('/oauth2/authorize', data=data)
        assert response_oauth_authorize.status_code == 302
        assert '/login/fence' in response_oauth_authorize.location


def test_login(
        fence_client_app, fence_idp_server, mock_get, example_keys_response):
    """
    Test that:
        - the ``/login/fence`` client endpoint redirects to the
          ``/oauth2/authorize`` endpoint on the IDP fence,
    """
    mock_get({
        '/jwt/keys': example_keys_response
    })
    with fence_client_app.test_client() as client:
        redirect_url_quote = urllib.quote('/login/fence/login')
        path = '/login/fence?redirect_uri={}'.format(redirect_url_quote)
        response_login_fence = client.get(path)
        # This should be pointing at ``/oauth2/authorize`` of the IDP fence.
        assert '/oauth2/authorize' in response_login_fence.location
        print response_login_fence.location
