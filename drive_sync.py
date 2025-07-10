# drive_sync.py

import os
import io
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseUpload, MediaIoBaseDownload

# Paths & constants
APPDATA        = os.getenv("APPDATA") or os.path.expanduser("~")
VAULT_DIR      = os.path.join(APPDATA, "SecureVault")
CRED_PATH      = os.path.join(VAULT_DIR, "credentials.json")
TOKEN_PATH     = os.path.join(VAULT_DIR, "token.json")
SCOPES         = ["https://www.googleapis.com/auth/drive.file"]
VAULT_FILENAME = "vault.json"
SIG_FILENAME   = "vault.json.sig"

def _authenticate() -> Credentials:
    if os.path.exists(TOKEN_PATH):
        return Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    flow = InstalledAppFlow.from_client_secrets_file(CRED_PATH, SCOPES)
    creds = flow.run_local_server(port=0)
    with open(TOKEN_PATH, "w", encoding="utf-8") as f:
        f.write(creds.to_json())
    return creds

def _get_drive_service():
    creds = _authenticate()
    return build("drive", "v3", credentials=creds)

def upload_bytes(name: str, data: bytes, mimetype: str, drive_folder_id: str = None) -> None:
    """
    Create or update a file named `name` on Drive with raw bytes.
    """
    service = _get_drive_service()
    bio = io.BytesIO(data)
    media = MediaIoBaseUpload(bio, mimetype=mimetype, resumable=True)

    query = f"name = '{name}' and trashed = false"
    files = service.files().list(q=query, fields="files(id)").execute().get("files", [])
    if files:
        file_id = files[0]["id"]
        service.files().update(fileId=file_id, media_body=media).execute()
    else:
        metadata = {"name": name}
        if drive_folder_id:
            metadata["parents"] = [drive_folder_id]
        service.files().create(body=metadata, media_body=media).execute()

def download_bytes(name: str) -> bytes:
    """
    Download a file named `name` from Drive into memory and return its bytes.
    """
    service = _get_drive_service()
    query = f"name = '{name}' and trashed = false"
    files = service.files().list(q=query, fields="files(id)").execute().get("files", [])
    if not files:
        raise FileNotFoundError(f"{name} not found on Drive.")

    file_id = files[0]["id"]
    request = service.files().get_media(fileId=file_id)

    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return fh.getvalue()
