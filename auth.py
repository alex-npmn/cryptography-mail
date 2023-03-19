import os

from googleapiclient.discovery import build

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
from flask import request, redirect, url_for, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

def get_google_auth_flow():
    flow = InstalledAppFlow.from_client_secrets_file(
        "client_secrets.json",
        scopes=[
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
    )
    flow.redirect_uri = "http://localhost:5003/oauth2callback"
    return flow

def authorize():
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(prompt='consent', access_type='offline',
                                                      include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

def logout():
    # Clear the user's session data
    session.clear()
    # Redirect the user back to the index page
    return redirect(url_for('index'))

def oauth2callback():
    state = session.get("state")
    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.url, include_granted_scopes='true')

    creds = flow.credentials
    session["credentials"] = creds_to_dict(creds)

    # Fetch the user's email address
    service = build("oauth2", "v2", credentials=creds)
    user_info = service.userinfo().get().execute()
    session["email"] = user_info["email"]

    return redirect(url_for("index"))

def creds_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

def dict_to_creds(creds_dict):
    return Credentials.from_authorized_user_info(info=creds_dict)
