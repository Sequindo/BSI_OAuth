from flask import Flask, session
from authlib.integrations.flask_client import OAuth
from flask.helpers import url_for
from werkzeug.utils import redirect

app = Flask(__name__)
app.secret_key = 'random_secret_key'

#oauth config
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='824282840327-4d9etrejbf10hm5je1qj3rmim3gsnogu.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile phone address'},
)


@app.route('/')
def hello_world():
    email = dict(session).get('email', None)
    return f'Hello, {email}!'

@app.route('/login')
def login():
    _google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return _google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    _google = oauth.create_client('google')
    token = _google.authorize_access_token()
    resp = _google.get('userinfo', token=token)
    userInfo = resp.json()
    #do something with token, and profile
    session['email'] = userInfo['email']
    return redirect('/')

@app.route('/logout')
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')