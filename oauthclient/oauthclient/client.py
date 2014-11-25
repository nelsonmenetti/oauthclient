import json
import requests
from base64 import b64encode


CLIENT_KEY = 'H02o3XvC4vXsZp6oivPc6tje5K50YVsw'
CLIENT_SECRET = '1Rj1v7dRy0Rii9Tnd8REKrX3jwU2LOlA'

AUTHORIZATION_ENDPOINT = 'http://homolog.passaporte.nossodom.com.br/oauth.html#/authorize?client_id='+CLIENT_KEY+'&response_type=code'
TOKEN_ENDPOINT = 'http://homolog.passaporte.nossodom.com.br/giul/api/oauth2/token?grant_type=authorization_code'
REFRESH_TOKEN_ENDPOINT = 'http://homolog.passaporte.nossodom.com.br/giul/api/oauth2/token?grant_type=refresh_token&refresh_token='
USER_INFO_ENDPOINT = 'http://homolog.passaporte.nossodom.com.br/giul/api/me'
LOGOUT_URL= 'http://homolog.passaporte.nossodom.com.br/giul/api/oauth2/token/invalidate'
AUTH_HEADERS = {'Authorization': 'Basic {}'.format(	b64encode('{}:{}'.format(CLIENT_KEY, CLIENT_SECRET)))}
CLIENT_REDIRECT_URI = 'http://localhost:8000/lms/oauth'


def getCode():
	return True

def getToken(code):
	# Exchange the authorization code for an access token.
	data = {
		'code': code,
		'grant_type': 'authorization_code',
	}
	print ('')

	token_response = requests.post(
			TOKEN_ENDPOINT,
			data=data,
			headers=AUTH_HEADERS)
	assert_200(token_response)

	token_data = json.loads(token_response.content)
	print ('')
	print ('Received access token information:')
	print ('	 access token:', token_data['access_token'])
	print ('	refresh token:', token_data.get('refresh_token', ''))
	print ('	 lifetime (s):', token_data['expires_in'])
	print ('')
	return token_data

def refreshToken(refresh_token):
	if refresh_token:
		data = {
			'refresh_token' : refresh_token,
			'grant_type' : 'refresh_token',
		}
		token_response = requests.post(
				REFRESH_TOKEN_ENDPOINT+refresh_token,
				data=data,
				headers=AUTH_HEADERS,
				verify=False)
		assert_200(token_response)
		token_data = json.loads(token_response.content)

		print ('')
		print ('Exchanged refresh token for access token:')
		print ('	 access token:', token_data['access_token'])
		print ('	refresh token:', token_data.get('refresh_token', ''))
		print ('	 lifetime (s):', token_data['expires_in'])
		print ('')
	return token_data

def invalidateToken(token):
	api_resp_logout = requests.post(
		LOGOUT_URL,
		headers={
			'Authorization': 'Bearer {}'.format(token['access_token'])
		},
		data={},
		verify=False)

	assert_200(api_resp_logout)
	print ('')
	print ('Authenticated API request succeeded (Token Invalidated)! Returned the following content:')
	print (api_resp_logout.content)
	print ('')
	return api_resp_logout.content

def getUserInfo(token):
	api_resp = requests.get(
		USER_INFO_ENDPOINT,
		headers={
			'Authorization': 'Bearer {}'.format(token['access_token'])
		},
		data={},
		verify=False)

	assert_200(api_resp)

	print ('')
	print ('Authenticated API request succeeded! Returned the following content:')
	print (api_resp.content)
	print ('')
	return api_resp.content


def assert_200(response, max_len=500):
	""" Check that a HTTP response returned 200. """
	if response.status_code == 200:
		return

	raise ValueError(
			"Response was {}, not 200:\n{}\n{}".format(
					response.status_code,
					json.dumps(dict(response.headers), indent=2),
					response.content[:max_len]))

def main():
	

	scopes = ['user_info']
	scope_string = ' '.join(scopes)

	auth_url = '{}?scope={}&client_id={}&response_type=code'.format(AUTHORIZATION_ENDPOINT,	scope_string,CLIENT_KEY)

	print ('')
	print ('Log in via the admin page (username: exampleuser, password: password)')
	print ('')
	print ('http://localhost:8080/admin/')
	print ('')
	raw_input('press return to continue...')

	print ('')
	print ('Open the following URL in your browser:')
	print ('')
	print (auth_url)
	print ('')
	print ('Click the "Accept" button to grant this client access to your data. ')
	print ('Your browser will be redirected to a URL with a "code" parameter; copy ')
	print ('that value and paste it in below.')
	print ('')

	auth_code = raw_input('code=').strip()

	# Exchange the authorization code for an access token.
	token_data = getToken(auth_code)
	raw_input('press return to continue...')
	# Exchange the refresh token for a new access token, if we received one.
	refresh_token = token_data.get('refresh_token')
	token_data=refreshToken(refresh_token)
	raw_input('press return to continue...')
	# Make an API request, authenticating with our recently received access token.
	getUserInfo(token_data)  
	raw_input('press return to continue...')
	# Make an API request to logout the user
	invalidateToken(token_data)

if __name__ == '__main__':
		main()