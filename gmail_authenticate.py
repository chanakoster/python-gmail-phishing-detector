import os
from config import SCOPES, TOKEN_FILE, CREDENTIALS_FILE
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.exceptions import GoogleAuthError

def gmail_authenticate():
    print("📧Connecting to your Gmail account")
    creds = None
    try:
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(CREDENTIALS_FILE):
                    raise FileNotFoundError(f"Missing credentials file: {CREDENTIALS_FILE}")
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)

            with open(TOKEN_FILE, "w") as token:
                token.write(creds.to_json())
        print ("✅Connected")
        return creds

    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
    except GoogleAuthError as e:
        print(f"❌ Google Auth Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    return None