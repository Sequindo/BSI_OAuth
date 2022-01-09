# -*- coding: utf-8 -*-

import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from werkzeug.utils import redirect

#Handling the client credentials in accordance with the best practice (eg. JSON file, as opposed to hardcoding in plain text) - 1 point
CLIENT_SECRETS_FILE = "client_secret.json"

# using incremental authorization
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']

app = flask.Flask(__name__)
# Based on https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'cc1ea1e24cfe1913c32d9d17252ec97f263024fa13f16065d6eea1cad3215f1d'

@app.route('/')
def index():
  userInfo = dict(flask.session).get('userinfo', None)
  if(userInfo==None):
    return f'Hello, None!'
  else:
    email = userInfo.get['email']
    return f'Hello, {email}!'

@app.route('/login')
def login():
    redirect_uri = flask.url_for('authorize', _external=True)
    return flask.redirect(redirect_uri)

@app.route('/authorize')
def authorize():
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true')

  flask.session['state'] = state

  return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)
  return flask.redirect(flask.url_for('getInfo'))

@app.route('/getInfo')
def getInfo():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  user_info_service = googleapiclient.discovery.build(
      serviceName='oauth2', version='v2', credentials=credentials)

  user_info = user_info_service.userinfo().get().execute()
  flask.session['userinfo'] = user_info
  return flask.redirect('/')


@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to authorize before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://oauth2.googleapis.com/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.' + redirect('/'))
  else:
    return('An error occurred.' + redirect('/'))


@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>' +
          redirect('/'))


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

if __name__ == '__main__':
  #allow insecure http
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
  #allow incremental authorization
  os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

  app.run('localhost', 5000, debug=True)