import os
import base64
from flask import Flask, redirect, request, url_for, session, render_template, flash
import requests
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Retrieve credentials and configuration from environment variables
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = 'http://localhost:8999/oauth2callback'
app.secret_key = os.getenv('SECRET_KEY')

# OAuth 2.0 endpoints
AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'

# Grant Scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.readonly",
]


@app.route('/')
def index():
    logged_in = 'credentials' in session
    return render_template('index.html', logged_in=logged_in)


@app.route('/login')
def login():
    # Construct the Google OAuth 2.0 authorization URL.
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ' '.join(SCOPES),
        'response_type': 'code',
        'access_type': 'offline',  # Request refresh token
        'include_granted_scopes': 'true',
        'prompt': 'consent'
    }
    authorization_url = requests.Request(
        'GET', AUTHORIZATION_ENDPOINT, params=params).prepare().url
    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    error = request.args.get('error')
    if error:
        return f"Error encountered: {error}"
    code = request.args.get('code')
    if not code:
        return "Missing code parameter.", 400

    token_data = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_response = requests.post(TOKEN_ENDPOINT, data=token_data)
    token_json = token_response.json()

    if 'error' in token_json:
        return f"Error retrieving token: {token_json.get('error_description')}", 400

    # Store only the necessary fields in the session for recreating Credentials
    session['credentials'] = {
        'token': token_json.get('access_token'),
        'refresh_token': token_json.get('refresh_token'),
        'token_uri': TOKEN_ENDPOINT,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scopes': SCOPES
    }
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/list-emails')
def list_emails():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    try:
        creds = Credentials.from_authorized_user_info(session['credentials'])
        service = build('gmail', 'v1', credentials=creds)
        # Retrieve a list of messages (limit to 10 for demo purposes)
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        subjects = []
        for message in messages:
            msg = service.users().messages().get(
                userId='me', id=message['id'], format='metadata', metadataHeaders=['Subject']
            ).execute()
            headers = msg.get('payload', {}).get('headers', [])
            subject = next(
                (header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
            subjects.append(subject)
        return render_template('list_emails.html', subjects=subjects)
    except Exception as e:
        return f"Error fetching emails: {str(e)}", 500


def create_message(sender, to, subject, message_text):
    """Create a message for an email."""
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw}


@app.route('/send-email', methods=['GET', 'POST'])
def send_email():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('send_email.html')
    elif request.method == 'POST':
        to = request.form.get('to')
        subject_line = request.form.get('subject')
        body_text = request.form.get('body')
        if not to or not subject_line or not body_text:
            flash("All fields are required.", "error")
            return redirect(url_for('send_email'))
        try:
            creds = Credentials.from_authorized_user_info(
                session['credentials'])
            service = build('gmail', 'v1', credentials=creds)
            # The authenticated user's email is represented by "me"
            message = create_message("me", to, subject_line, body_text)
            service.users().messages().send(userId='me', body=message).execute()
            flash("Email sent successfully!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            return f"Error sending email: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=True, port=8999)
