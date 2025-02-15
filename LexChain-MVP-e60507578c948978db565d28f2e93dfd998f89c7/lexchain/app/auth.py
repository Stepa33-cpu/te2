import msal
import requests
from flask import session, redirect, url_for, current_app

# ----------------- Microsoft App Credentials -----------------
APPLICATION_ID = '969255ff-912a-4f81-b038-4a7ff47f44f1'  # Replace with your app ID
CLIENT_SECRET = 'xwl8Q~jdqAIYYazJrdPIakmRcOJv0eg0HVsXxaKQ'   # Replace with your app secret
AUTHORITY_URL = 'https://login.microsoftonline.com/consumers/'
SCOPES = ['Files.ReadWrite', 'User.Read']
REDIRECT_URI = "http://localhost:5000/api/auth/callback"

def get_msal_app():
    return msal.ConfidentialClientApplication(
        client_id,
        client_credential=client_secret,
        authority=authority
    )

def get_access_token():
    token = session.get('access_token')
    if not token:
        return None

    # Validate token expiration and refresh if necessary
    msal_app = get_msal_app()
    result = msal_app.acquire_token_silent(scopes, account=None)
    if not result:
        return None
    return result.get('access_token')

def login():
    msal_app = get_msal_app()
    auth_url = msal_app.get_authorization_request_url(scopes)
    return redirect(auth_url)

def authorized():
    msal_app = get_msal_app()
    token_response = msal_app.acquire_token_by_authorization_code(
        request.args['code'],
        scopes=scopes,
        redirect_uri=redirect_uri
    )
    session['access_token'] = token_response.get('access_token')
    return redirect(url_for('upload_page'))

def logout():
    session.clear()
    return redirect(url_for('login'))
