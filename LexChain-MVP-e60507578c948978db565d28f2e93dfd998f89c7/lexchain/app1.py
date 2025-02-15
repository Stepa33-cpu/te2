import os
import json
import requests
import secrets
import mimetypes
import hashlib
import zipfile
import uuid
import math
import base64
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, redirect, jsonify, make_response, send_file
from flask_cors import CORS
from msal import ConfidentialClientApplication
import aiohttp
import asyncio
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.urls import quote

# Load environment variables from .env file
load_dotenv()

# ----------------- Microsoft App Credentials -----------------
APPLICATION_ID = os.getenv('MS_APPLICATION_ID')
CLIENT_SECRET = os.getenv('MS_CLIENT_SECRET')
AUTHORITY_URL = os.getenv('MS_AUTHORITY_URL', 'https://login.microsoftonline.com/common')

# Separate scopes
API_SCOPES = os.getenv('MS_SCOPES', 'Files.ReadWrite.All User.Read').split(' ')
DEFAULT_SCOPES = ['openid', 'profile', 'offline_access']  # These are handled automatically by MSAL
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/api/auth/callback')

# Debug logging for environment variables
print("Loaded environment variables:")
print(f"APPLICATION_ID: {APPLICATION_ID is not None}")
print(f"CLIENT_SECRET: {CLIENT_SECRET is not None}")
print(f"AUTHORITY_URL: {AUTHORITY_URL}")
print(f"API_SCOPES: {API_SCOPES}")
print(f"REDIRECT_URI: {REDIRECT_URI}")

# ----------------- Flask App & CORS Configuration -----------------
app = Flask(__name__)
CORS(app,
     resources={
         r"/*": {
             "origins": ["https://dashboard.lexchain.net"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True
         }
     })

# Update the after_request handler
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    
    # Only add CORS headers for requests from your frontend
    origin = request.headers.get('Origin')
    if origin and origin == "https://dashboard.lexchain.net":
        response.headers.add('Access-Control-Allow-Origin', origin)
    
    return response

# Add production configurations
if os.getenv('PRODUCTION') == 'true':
    # Set secure cookie settings
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
    )

# ----------------- Storage Paths Setup -----------------
STORAGE_PATH = Path("secure_storage")
BLOCKCHAIN_DIR = STORAGE_PATH / "blockchain"
BLOCKCHAIN_METADATA_PATH = BLOCKCHAIN_DIR / "metadata"
BLOCKCHAIN_LOGS_PATH = BLOCKCHAIN_DIR / "logs"
FRAGMENTS_PATH = STORAGE_PATH / "fragments"

for d in [STORAGE_PATH, BLOCKCHAIN_DIR, BLOCKCHAIN_METADATA_PATH, BLOCKCHAIN_LOGS_PATH, FRAGMENTS_PATH]:
    d.mkdir(parents=True, exist_ok=True)

# ----------------- Encryption Helpers -----------------
def derive_key(password: str) -> bytes:
    """Derive an encryption key from a password"""
    salt = b"FixedSaltValue"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_dict(aesgcm: AESGCM, data: dict) -> dict:
    """Encrypt a dictionary"""
    json_data = json.dumps(data).encode('utf-8')
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json_data, None)
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_dict(aesgcm: AESGCM, encrypted_data: dict) -> dict:
    """Decrypt an encrypted dictionary"""
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode('utf-8'))

# ----------------- Blockchain Logging -----------------
def store_metadata_to_blockchain(metadata: Dict) -> None:
    tx_id = f"tx_{metadata['file_id']}_{int(datetime.now().timestamp())}.json"
    tx_file = BLOCKCHAIN_METADATA_PATH / tx_id
    with open(tx_file, 'w') as f:
        json.dump(metadata, f, indent=2)

def store_log_to_blockchain(log: Dict) -> None:
    tx_id = f"log_{log['timestamp'].replace(':', '-')}_{log['action']}.json"
    tx_file = BLOCKCHAIN_LOGS_PATH / tx_id
    with open(tx_file, 'w') as f:
        json.dump(log, f, indent=2)

def log_action(action: str, details: Dict, session_id: str = None) -> None:
    user_info = None
    if session_id and session_id in sessions:
        user_info = {
            "id": sessions[session_id].get("user_id"),
            "name": sessions[session_id].get("name")
        }

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details,
        "user": user_info
    }
    store_log_to_blockchain(log_entry)

# ----------------- Session Management -----------------
sessions = {}

def create_session(access_token, user_info):
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        'access_token': access_token,
        'user_info': user_info,
        'created_at': datetime.utcnow()
    }
    return session_id

# ----------------- OneDrive Helper Functions -----------------
def upload_to_onedrive(access_token: str, file_path: Path, destination_path: str) -> str:
    """Upload a file to OneDrive and return the item ID"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/octet-stream'
    }
    
    with open(file_path, 'rb') as f:
        data = f.read()
        
    # Create the LexchainFragments folder if it doesn't exist
    folder_url = 'https://graph.microsoft.com/v1.0/me/drive/root/children'
    folder_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    folder_data = {
        "name": destination_path,
        "folder": {},
        "@microsoft.graph.conflictBehavior": "replace"
    }
    requests.post(folder_url, headers=folder_headers, json=folder_data)
    
    # Upload the file
    upload_url = f'https://graph.microsoft.com/v1.0/me/drive/root:/{destination_path}/{file_path.name}:/content'
    response = requests.put(upload_url, headers=headers, data=data)
    response.raise_for_status()
    return response.json().get('id')

def download_from_onedrive(access_token: str, file_id: str, output_path: Path) -> bool:
    """Download a file from OneDrive using its ID"""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    download_url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content'
    response = requests.get(download_url, headers=headers, stream=True)
    
    if response.status_code == 200:
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    return False

def delete_from_onedrive(access_token: str, file_id: str) -> bool:
    """Delete a file from OneDrive using its ID"""
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    delete_url = f'https://graph.microsoft.com/v1.0/me/drive/items/{file_id}'
    response = requests.delete(delete_url, headers=headers)
    return response.status_code == 204

# ----------------- Secure File Manager -----------------
class SecureFileManager:
    MAX_CONCURRENT_UPLOADS = 3  # Maximum parallel uploads
    UPLOAD_DELAY = 0.5  # Delay between uploads in seconds

    def __init__(self, derived_key: bytes, access_token: str, session_id: str):
        self.derived_key = derived_key
        self.aesgcm = AESGCM(derived_key)
        self.access_token = access_token
        self.session_id = session_id  # Store session_id
        print(f"SecureFileManager initialized with token: {access_token[:10]}...")
        mimetypes.init()

    def encrypt_chunk(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt_chunk(self, encrypted_data: bytes) -> bytes:
        """Decrypt a chunk of data"""
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        # Decrypt using the AESGCM instance
        return self.aesgcm.decrypt(nonce, ciphertext, None)

    def detect_mime_type(self, file_path: str) -> str:
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type is None:
            with open(file_path, 'rb') as f:
                header = f.read(2048)
                if header.startswith(b'%PDF'):
                    return 'application/pdf'
                if header.startswith(b'\x89PNG\r\n\x1a\n'):
                    return 'image/png'
                if header.startswith(b'\xff\xd8'):
                    return 'image/jpeg'
        return mime_type or 'application/octet-stream'

    async def upload_fragment_to_onedrive(self, session, fragment_path: str, fragment_name: str) -> str:
        """Upload a single fragment to OneDrive"""
        try:
            # Check if token needs refresh before each fragment upload
            if not refresh_token_if_needed(sessions[self.session_id]):
                raise Exception("Token expired during upload")

            headers = {
                'Authorization': f'Bearer {sessions[self.session_id]["access_token"]}',  # Get fresh token
                'Content-Type': 'application/octet-stream'
            }

            # Create upload session
            create_url = f"https://graph.microsoft.com/v1.0/me/drive/root:/fragments/{fragment_name}:/createUploadSession"
            print(f"Creating upload session for {fragment_name}")
            async with session.post(create_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    print(f"Failed to create upload session: Status {response.status}, Error: {error_text}")
                    raise Exception(f"Failed to create upload session: {response.status}")
                upload_session = await response.json()
                upload_url = upload_session['uploadUrl']

            # Upload the fragment
            print(f"Uploading fragment {fragment_name}")
            with open(fragment_path, 'rb') as f:
                data = f.read()
                async with session.put(upload_url, data=data, headers=headers) as response:
                    if response.status not in (200, 201):
                        error_text = await response.text()
                        print(f"Fragment upload failed: Status {response.status}, Error: {error_text}")
                        raise Exception(f"Fragment upload failed: {response.status}")
                    result = await response.json()
                    print(f"Successfully uploaded fragment {fragment_name}")
                    return result['id']

        except Exception as e:
            print(f"Error in upload_fragment_to_onedrive: {str(e)}")
            raise

    async def upload_fragments_with_rate_limit(self, fragments: List[Dict]) -> List[Dict]:
        """Upload fragments with rate limiting"""
        async with aiohttp.ClientSession() as session:
            uploaded_fragments = []
            for i in range(0, len(fragments), self.MAX_CONCURRENT_UPLOADS):
                batch = fragments[i:i + self.MAX_CONCURRENT_UPLOADS]
                tasks = []
                
                for fragment in batch:
                    fragment_name = f"fragment_{fragment['index']}_{fragment['file_id']}.lexchain"
                    task = asyncio.create_task(
                        self.upload_fragment_to_onedrive(session, fragment['path'], fragment_name)
                    )
                    tasks.append(task)

                # Wait for current batch to complete
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for fragment, result in zip(batch, results):
                    if isinstance(result, Exception):
                        print(f"Failed to upload fragment {fragment['index']}: {str(result)}")
                        raise result
                    
                    fragment['onedrive_id'] = result
                    uploaded_fragments.append(fragment)

                # Add delay between batches
                if i + self.MAX_CONCURRENT_UPLOADS < len(fragments):
                    await asyncio.sleep(self.UPLOAD_DELAY)

            return uploaded_fragments

    def fragment_file(self, file_path: str) -> str:
        """Fragment and upload a file"""
        try:
            print(f"Starting file fragmentation for {file_path}")
            file_id = hashlib.sha256(f"{file_path}{datetime.now()}".encode()).hexdigest()[:12]
            
            # Read and fragment the file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            total_size = len(data)
            fragment_size = 1024 * 1024  # 1MB fragments
            num_fragments = math.ceil(total_size / fragment_size)
            
            fragments = []
            temp_dir = Path("temp_fragments")
            temp_dir.mkdir(exist_ok=True)

            try:
                # Create fragments
                for i in range(num_fragments):
                    start = i * fragment_size
                    end = min(start + fragment_size, total_size)
                    fragment_data = data[start:end]
                    
                    # Encrypt fragment
                    encrypted_fragment = self.encrypt_chunk(fragment_data)
                    fragment_path = temp_dir / f"fragment_{i}_{file_id}.lexchain"
                    
                    with open(fragment_path, 'wb') as f:
                        f.write(encrypted_fragment)
                    
                    fragments.append({
                        'index': i,
                        'path': str(fragment_path),
                        'size': len(encrypted_fragment),
                        'file_id': file_id,
                        'fingerprint': hashlib.sha256(fragment_data).hexdigest()
                    })

                # Upload fragments with rate limiting
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    uploaded_fragments = loop.run_until_complete(
                        self.upload_fragments_with_rate_limit(fragments)
                    )
                finally:
                    loop.close()

                # Create metadata
                metadata = {
                    'file_id': file_id,
                    'original_filename': Path(file_path).name,
                    'creation_date': datetime.now().isoformat(),
                    'total_size': total_size,
                    'mime_type': self.detect_mime_type(file_path),
                    'num_fragments': num_fragments,
                    'fragments': [
                        {
                            'index': f['index'],
                            'size': f['size'],
                            'onedrive_id': f['onedrive_id'],
                            'fingerprint': f['fingerprint']
                        }
                        for f in uploaded_fragments
                    ]
                }

                # Save metadata
                self.save_metadata(file_id, metadata)
                return file_id

            finally:
                # Clean up temporary fragments
                for fragment in fragments:
                    try:
                        Path(fragment['path']).unlink()
                    except Exception:
                        pass
                if temp_dir.exists() and not any(temp_dir.iterdir()):
                    temp_dir.rmdir()

        except Exception as e:
            print(f"Error in fragment_file: {str(e)}")
            raise

    def rebuild_file(self, file_id: str, output_path: Optional[str] = None) -> str:
        """Rebuild file from fragments stored in OneDrive"""
        try:
            # Create temporary directory if needed
            temp_dir = Path("temp_rebuild")
            temp_dir.mkdir(exist_ok=True)

            # Find and load metadata
            metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
            if not metadata_files:
                raise ValueError(f"No metadata found for file ID: {file_id}")

            # Load and decrypt metadata
            with open(metadata_files[0], 'r') as f:
                stored_metadata = json.load(f)
                encrypted_data = stored_metadata.get('encrypted', {})
                
                # Decrypt metadata
                nonce = base64.b64decode(encrypted_data.get('nonce', ''))
                ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
                decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)
                metadata = json.loads(decrypted_data.decode())

            if metadata.get("deleted", False):
                raise ValueError("File has been deleted")

            # Prepare output path
            if output_path is None:
                output_path = temp_dir / metadata['original_filename']
            output_path = Path(output_path)

            fragments = []
            # Download and decrypt all fragments
            for fragment_info in metadata.get('fragments', []):
                # Download fragment from OneDrive
                headers = {
                    'Authorization': f'Bearer {self.access_token}'
                }
                
                download_url = f'https://graph.microsoft.com/v1.0/me/drive/items/{fragment_info["onedrive_id"]}/content'
                response = requests.get(download_url, headers=headers)
                
                if response.status_code != 200:
                    raise ValueError(f"Failed to download fragment {fragment_info['index']}")

                # Decrypt fragment
                encrypted_fragment = response.content
                fragment = self.decrypt_chunk(encrypted_fragment)

                # Verify fragment integrity
                if hashlib.sha256(fragment).hexdigest() != fragment_info['fingerprint']:
                    raise ValueError(f"Fragment {fragment_info['index']} integrity check failed")

                fragments.append((fragment_info['index'], fragment))

            # Sort fragments by index and combine
            fragments.sort(key=lambda x: x[0])
            with open(output_path, 'wb') as f:
                for _, fragment in fragments:
                    f.write(fragment)

            return str(output_path)

        except Exception as e:
            print(f"Error rebuilding file: {str(e)}")
            raise

        finally:
            # Clean up any temporary files except the output file
            if temp_dir.exists():
                for file in temp_dir.glob("*"):
                    if file != output_path:
                        try:
                            file.unlink()
                        except Exception:
                            pass

    def delete_file(self, file_id: str) -> bool:
        """Delete a file and its fragments"""
        try:
            # Find and load metadata
            metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
            if not metadata_files:
                print(f"No metadata found for file ID: {file_id}")
                return False

            # Load and decrypt metadata
            with open(metadata_files[0], 'r') as f:
                stored_metadata = json.load(f)
                encrypted_data = stored_metadata.get('encrypted', {})
                
                # Decrypt metadata
                nonce = base64.b64decode(encrypted_data.get('nonce', ''))
                ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
                decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)
                metadata = json.loads(decrypted_data.decode())

            # Try to delete fragments from OneDrive, but continue if they're already gone
            deletion_errors = []
            for fragment in metadata.get('fragments', []):
                onedrive_id = fragment.get('onedrive_id')
                if onedrive_id:
                    try:
                        if not delete_from_onedrive(self.access_token, onedrive_id):
                            deletion_errors.append(f"Failed to delete fragment with ID: {onedrive_id}")
                    except Exception as e:
                        print(f"Error deleting fragment {onedrive_id}: {str(e)}")
                        # Continue even if fragment deletion fails
                        pass

            # Mark metadata as deleted regardless of fragment deletion status
            metadata['deleted'] = True
            encrypted_metadata = encrypt_dict(self.aesgcm, metadata)
            stored_metadata['encrypted'] = encrypted_metadata
            
            with open(metadata_files[0], 'w') as f:
                json.dump(stored_metadata, f, indent=2)

            # If there were deletion errors but we updated the metadata, log a warning
            if deletion_errors:
                print("Warning: Some fragments could not be deleted but file was marked as deleted")
                print("\n".join(deletion_errors))

            return True

        except Exception as e:
            print(f"Error in delete_file: {str(e)}")
            return False

    def save_metadata(self, file_id: str, metadata: Dict) -> None:
        """Save encrypted metadata to blockchain directory"""
        # Create public metadata (non-sensitive info)
        public_metadata = {
            "original_filename": f"Encrypted File ({file_id[:4]})",
            "creation_date": "Encrypted",
            "total_size": "Encrypted",
            "mime_type": "Encrypted",
            "num_fragments": None,
            "fragments": None,
            "deleted": None
        }

        # Encrypt the sensitive metadata
        encrypted_metadata = self.encrypt_dict(metadata)

        # Combine public and encrypted data
        metadata_to_store = {
            "file_id": file_id,
            "public": public_metadata,
            "encrypted": encrypted_metadata
        }

        # Save to blockchain directory
        metadata_path = BLOCKCHAIN_METADATA_PATH / f"tx_{file_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata_to_store, f, indent=2)

        # Log the action
        self.log_action("upload", {"file_id": file_id, "filename": metadata["original_filename"]})

    def encrypt_dict(self, data: Dict) -> Dict:
        """Encrypt a dictionary"""
        # Convert dict to JSON string
        json_data = json.dumps(data)
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Encrypt the data
        ciphertext = self.aesgcm.encrypt(nonce, json_data.encode(), None)
        
        # Return base64 encoded values
        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def log_action(self, action_type: str, details: Dict) -> None:
        """Log an action to the blockchain logs"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action_type,
            "details": details
        }
        
        log_path = BLOCKCHAIN_LOGS_PATH / f"log_{datetime.now().strftime('%Y%m%d')}.json"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing logs or create new log file
        if log_path.exists():
            with open(log_path, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        # Add new log entry
        logs.append(log_entry)
        
        # Save updated logs
        with open(log_path, 'w') as f:
            json.dump(logs, f, indent=2)

# ----------------- Auth Routes -----------------
@app.route('/api/user', methods=['GET'])
def get_user():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({"authenticated": False}), 401

    session_data = sessions[session_id]
    print("Session data:", session_data)  # Add this debug line

    return jsonify({
        "authenticated": True,
        "user": {
            "name": session_data.get("name"),
            "id": session_data.get("user_id")
        }
    })

@app.route("/auth/url", methods=["GET"])
def get_auth_url():
    try:
        msal_app = ConfidentialClientApplication(
            client_id=APPLICATION_ID,
            client_credential=CLIENT_SECRET,
            authority=AUTHORITY_URL
        )
        
        state = secrets.token_urlsafe(32)
        auth_url = msal_app.get_authorization_request_url(
            scopes=API_SCOPES,  # Only use API scopes
            state=state,
            redirect_uri=REDIRECT_URI,
            prompt='select_account',
            response_mode='query',
            domain_hint='consumers'
        )
        
        if 'organizations' in auth_url:
            auth_url = auth_url.replace('/organizations/', '/common/')
        
        print(f"Generated auth URL with client_id: {APPLICATION_ID}")
        print(f"Auth URL: {auth_url}")
        
        return jsonify({
            "url": auth_url,
            "state": state
        })
    except Exception as e:
        print(f"Error generating auth URL: {str(e)}")
        error_details = {
            "error": str(e),
            "application_id": APPLICATION_ID is not None,
            "scopes": API_SCOPES,
            "redirect_uri": REDIRECT_URI,
            "authority": AUTHORITY_URL
        }
        return jsonify(error_details), 500

@app.route('/api/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Authorization code is missing"}), 400

    try:
        # Create MSAL app with consumers endpoint for personal accounts
        authority_url = "https://login.microsoftonline.com/consumers"
        msal_app = ConfidentialClientApplication(
            client_id=APPLICATION_ID,
            client_credential=CLIENT_SECRET,
            authority=authority_url
        )
        
        print(f"Attempting to acquire token with code: {code[:10]}...")
        
        # Get token using updated URL encoding
        result = msal_app.acquire_token_by_authorization_code(
            code=quote(code),
            scopes=API_SCOPES,
            redirect_uri=REDIRECT_URI
        )
        
        if "error" in result:
            print(f"Token acquisition error: {result.get('error_description')}")
            # If first attempt fails, try with common endpoint
            if "AADSTS70000121" in result.get("error_description", ""):
                msal_app = ConfidentialClientApplication(
                    client_id=APPLICATION_ID,
                    client_credential=CLIENT_SECRET,
                    authority="https://login.microsoftonline.com/common"
                )
                result = msal_app.acquire_token_by_authorization_code(
                    code=quote(code),
                    scopes=API_SCOPES,
                    redirect_uri=REDIRECT_URI
                )
            
            if "error" in result:
                return jsonify({"error": result.get("error_description")}), 400

        # Clear any existing session for this user
        user_id = result.get("id_token_claims", {}).get("sub")
        if user_id:
            # Remove old sessions for this user
            for sid in list(sessions.keys()):
                if sessions[sid].get("user_id") == user_id:
                    sessions.pop(sid)

        # Create new session
        session_id = secrets.token_urlsafe(32)
        sessions[session_id] = {
            "access_token": result["access_token"],
            "refresh_token": result.get("refresh_token"),
            "user_id": user_id,
            "name": result.get("id_token_claims", {}).get("name"),
            "expires_at": datetime.now() + timedelta(seconds=result.get("expires_in", 3600))
        }

        print(f"Successfully created session for user: {sessions[session_id].get('name')}")

        # Redirect to frontend with session cookie
        response = make_response(redirect(FRONTEND_URL))
        response.set_cookie(
            'session_id',
            session_id,
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=3600  # 1 hour
        )
        
        return response

    except Exception as e:
        print(f"Error in auth callback: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/auth/logout", methods=["POST"])
def logout():
    session_id = request.cookies.get('session_id')
    if session_id:
        sessions.pop(session_id, None)
    
    response = jsonify({"success": True})
    response.delete_cookie('session_id')
    return response

@app.route('/login')
def login():
    client_instance = ConfidentialClientApplication(
        client_id=APPLICATION_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY_URL
    )
    
    print(f"Generating login URL with client_id: {APPLICATION_ID}")
    
    authorization_request_url = client_instance.get_authorization_request_url(
        API_SCOPES,  # Only use API scopes
        redirect_uri=REDIRECT_URI,
        prompt='select_account',
        response_mode='query',
        domain_hint='consumers'
    )
    
    if 'organizations' in authorization_request_url:
        authorization_request_url = authorization_request_url.replace('/organizations/', '/common/')
    
    print(f"Login URL: {authorization_request_url}")
    return redirect(authorization_request_url)

# Update the token refresh middleware
def refresh_token_if_needed(session_data):
    try:
        # Check if token is expired or about to expire (within 5 minutes)
        if datetime.now() + timedelta(minutes=5) >= session_data.get("expires_at", datetime.now()):
            print("Token needs refresh, attempting...")
            
            msal_app = ConfidentialClientApplication(
                client_id=APPLICATION_ID,
                client_credential=CLIENT_SECRET,
                authority=AUTHORITY_URL
            )
            
            # Try to get a new token silently first
            accounts = msal_app.get_accounts(username=session_data.get("user_id"))
            if accounts:
                result = msal_app.acquire_token_silent(
                    scopes=API_SCOPES,
                    account=accounts[0]
                )
                
                if result:
                    print("Token refreshed silently")
                    session_data["access_token"] = result["access_token"]
                    session_data["expires_at"] = datetime.now() + timedelta(seconds=result.get("expires_in", 3600))
                    return True
            
            # If silent refresh fails, try refresh token
            if session_data.get("refresh_token"):
                result = msal_app.acquire_token_by_refresh_token(
                    session_data["refresh_token"],
                    scopes=API_SCOPES
                )
                
                if "error" not in result:
                    print("Token refreshed using refresh token")
                    session_data["access_token"] = result["access_token"]
                    session_data["refresh_token"] = result.get("refresh_token")
                    session_data["expires_at"] = datetime.now() + timedelta(seconds=result.get("expires_in", 3600))
                    return True
                else:
                    print(f"Refresh token error: {result.get('error')}")
            
            print("Token refresh failed")
            return False
        
        return True  # Token is still valid
        
    except Exception as e:
        print(f"Error in refresh_token_if_needed: {str(e)}")
        return False

# ----------------- File Operation Routes -----------------
@app.route("/upload", methods=["POST"])
def upload_file():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        print("No valid session found")
        return jsonify({"error": "Not authenticated"}), 401

    try:
        session_data = sessions[session_id]
        print(f"Processing upload for user: {session_data.get('name')}")
        
        # Initial token refresh
        if not refresh_token_if_needed(session_data):
            print("Token refresh failed, redirecting to login")
            return jsonify({"error": "Session expired", "redirect": True}), 401

        print(f"Using access token: {session_data['access_token'][:10]}...")

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        master_password = request.form.get("password")
        if not master_password:
            return jsonify({"error": "Master password required"}), 400

        temp_dir = Path("temp_uploads")
        temp_dir.mkdir(exist_ok=True)
        file_path = temp_dir / file.filename
        file.save(file_path)

        try:
            derived_key = derive_key(master_password)
            manager = SecureFileManager(
                derived_key=derived_key,
                access_token=session_data['access_token'],
                session_id=session_id  # Pass session_id
            )
            file_id = manager.fragment_file(str(file_path))
            return jsonify({"message": "File uploaded and encrypted successfully!", "file_id": file_id})
        except Exception as e:
            print(f"Error during file processing: {str(e)}")
            return jsonify({"error": str(e)}), 500
        finally:
            if file_path.exists():
                file_path.unlink()
            if temp_dir.exists() and not any(temp_dir.iterdir()):
                temp_dir.rmdir()

    except Exception as e:
        print(f"Error in upload_file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/download", methods=["POST"])
def download_file():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = request.get_json()
        file_id = data.get("file_id")
        password = data.get("password")

        if not file_id or not password:
            return jsonify({"error": "File ID and password required"}), 400

        # Create file manager instance
        derived_key = derive_key(password)
        file_manager = SecureFileManager(
            derived_key=derived_key,
            access_token=sessions[session_id]["access_token"],
            session_id=session_id
        )

        # Create temp directory for output
        temp_dir = Path("temp_downloads")
        temp_dir.mkdir(exist_ok=True)
        output_path = temp_dir / f"download_{file_id}"

        # Attempt to download and rebuild the file
        rebuilt_file_path = file_manager.rebuild_file(file_id, str(output_path))

        # Get metadata for filename and mime type
        metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
        if not metadata_files:
            return jsonify({"error": "File not found"}), 404

        with open(metadata_files[0], 'r') as f:
            stored_metadata = json.load(f)
            encrypted_data = stored_metadata.get('encrypted', {})
            nonce = base64.b64decode(encrypted_data.get('nonce', ''))
            ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
            decrypted_data = file_manager.aesgcm.decrypt(nonce, ciphertext, None)
            metadata = json.loads(decrypted_data.decode())

        # Log the download action
        log_action(
            "download",
            {
                "file_id": file_id,
                "filename": metadata.get("original_filename"),
                "timestamp": datetime.now().isoformat(),
                "success": True
            },
            session_id
        )

        return send_file(
            rebuilt_file_path,
            as_attachment=True,
            download_name=metadata.get("original_filename", "downloaded_file"),
            mimetype=metadata.get("mime_type", "application/octet-stream")
        )

    except Exception as e:
        # Log failed download attempt
        if 'file_id' in locals():
            log_action(
                "download_failed",
                {
                    "file_id": file_id,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                },
                session_id
            )
        print(f"Error in download_file: {str(e)}")
        return jsonify({"error": str(e)}), 500

    finally:
        # Clean up temporary files
        if 'rebuilt_file_path' in locals():
            try:
                os.remove(rebuilt_file_path)
            except Exception:
                pass
        if 'temp_dir' in locals() and temp_dir.exists():
            try:
                temp_dir.rmdir()
            except Exception:
                pass

@app.route("/delete", methods=["POST"])
def delete_file():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        data = request.get_json()
        if not data:
            print("No data received in request")
            return jsonify({"error": "No data provided"}), 400

        file_id = data.get("file_id")
        master_password = data.get("password")

        print(f"Attempting to delete file with ID: {file_id}")

        if not all([file_id, master_password]):
            return jsonify({"error": "File ID and master password required"}), 400

        # Create encryption key from master password
        derived_key = derive_key(master_password)
        aesgcm = AESGCM(derived_key)

        # Get file metadata before deletion
        metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
        if not metadata_files:
            print(f"No metadata found for file ID: {file_id}")
            return jsonify({"error": "File not found"}), 404

        metadata_file = metadata_files[0]
        print(f"Found metadata file: {metadata_file}")

        try:
            with open(metadata_file, 'r') as f:
                stored_metadata = json.load(f)
                encrypted_data = stored_metadata.get('encrypted', {})
                
                if not encrypted_data:
                    print("No encrypted data found in metadata")
                    return jsonify({"error": "Invalid metadata format"}), 400

                try:
                    # Decrypt metadata to get file details
                    nonce = base64.b64decode(encrypted_data.get('nonce', ''))
                    ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    decrypted_metadata = json.loads(decrypted_data.decode())

                    print(f"Successfully decrypted metadata for file: {decrypted_metadata.get('original_filename')}")

                    # Create SecureFileManager instance
                    manager = SecureFileManager(
                        derived_key=derived_key,
                        access_token=sessions[session_id]['access_token'],
                        session_id=session_id
                    )

                    # Delete the file
                    success = manager.delete_file(file_id)
                    if not success:
                        print("Failed to delete file using SecureFileManager")
                        return jsonify({"error": "Failed to delete file"}), 500

                    # Create a deletion log entry
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "action": "delete",
                        "details": {
                            "file_id": file_id,
                            "filename": decrypted_metadata.get('original_filename'),
                            "deletion_date": datetime.now().isoformat(),
                            "size": decrypted_metadata.get('total_size'),
                            "mime_type": decrypted_metadata.get('mime_type'),
                            "fragment_count": len(decrypted_metadata.get('fragments', []))
                        }
                    }

                    # Store the log
                    log_file = BLOCKCHAIN_LOGS_PATH / f"log_{datetime.now().strftime('%Y%m%d')}.json"
                    
                    try:
                        with open(log_file, 'r') as f:
                            logs = json.load(f)
                    except (FileNotFoundError, json.JSONDecodeError):
                        logs = []
                    
                    if not isinstance(logs, list):
                        logs = []
                    
                    logs.append(log_entry)
                    
                    with open(log_file, 'w') as f:
                        json.dump(logs, f, indent=2)

                    print(f"Successfully deleted file and created log entry")
                    return jsonify({"message": "File deleted successfully"})

                except Exception as decrypt_error:
                    print(f"Error decrypting metadata: {str(decrypt_error)}")
                    return jsonify({"error": "Invalid password or corrupted metadata"}), 400

        except Exception as read_error:
            print(f"Error reading metadata file: {str(read_error)}")
            return jsonify({"error": "Failed to read metadata"}), 500

    except Exception as e:
        print(f"Error in delete_file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/files", methods=["GET"])
def get_files():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({"error": "Not authenticated"}), 401

    # Get all metadata files
    metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob("tx_*.json"))
    files_list = []

    for metadata_file in metadata_files:
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
            if not metadata.get('encrypted', {}).get('deleted', False):  # Only include non-deleted files
                files_list.append({
                    "id": metadata.get('file_id'),
                    "name": metadata.get('public', {}).get('original_filename'),
                    "date": metadata.get('encrypted', {}).get('creation_date', '').split('T')[0],
                    "size": metadata.get('encrypted', {}).get('total_size', 0),
                    "status": "Verified"
                })

    return jsonify({"files": files_list})

@app.route("/api/files/filtered", methods=["POST"])
def get_filtered_files():
    try:
        # Authentication checks
        session_id = request.cookies.get('session_id')
        if not session_id:
            return jsonify({"error": "No session cookie found"}), 401
        
        if session_id not in sessions:
            return jsonify({"error": "Invalid or expired session"}), 401

        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        master_password = data.get('password')
        if not master_password:
            return jsonify({"error": "Master password required"}), 400

        # Create encryption key from master password
        try:
            derived_key = derive_key(master_password)
            aesgcm = AESGCM(derived_key)
        except Exception as e:
            print(f"Error creating encryption key: {str(e)}")
            return jsonify({"error": "Invalid password format"}), 400

        files_list = []
        metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob("tx_*.json"))
        print(f"Found {len(metadata_files)} metadata files")

        for metadata_file in metadata_files:
            try:
                with open(metadata_file, 'r') as f:
                    stored_metadata = json.load(f)
                    encrypted_data = stored_metadata.get('encrypted', {})
                    
                    if not encrypted_data:
                        print(f"No encrypted data in {metadata_file}")
                        continue

                    try:
                        # Decrypt metadata
                        nonce = base64.b64decode(encrypted_data.get('nonce', ''))
                        ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
                        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                        metadata = json.loads(decrypted_data.decode())

                        # Skip deleted files
                        if metadata.get('deleted', False):
                            continue

                        # Add file to list if decryption succeeded
                        files_list.append({
                            "id": stored_metadata.get('file_id'),
                            "name": metadata.get('original_filename'),
                            "date": metadata.get('creation_date', '').split('T')[0],
                            "size": metadata.get('total_size', 0),
                            "status": "Available",
                            "mime_type": metadata.get('mime_type')
                        })
                        print(f"Successfully processed file: {metadata.get('original_filename')}")

                    except Exception as decrypt_error:
                        print(f"Decryption failed for {metadata_file}: {str(decrypt_error)}")
                        continue

            except Exception as file_error:
                print(f"Error processing {metadata_file}: {str(file_error)}")
                continue

        # Sort files by date
        files_list.sort(key=lambda x: x['date'], reverse=True)
        
        print(f"Returning {len(files_list)} files")
        return jsonify({
            "files": files_list,
            "total_count": len(files_list)
        })

    except Exception as e:
        print(f"Error in get_filtered_files: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/blockchain/logs", methods=["GET", "POST"])
def get_blockchain_logs():
    session_id = request.cookies.get('session_id')
    if not session_id or session_id not in sessions:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        if request.method == "POST":
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400
                
            master_password = data.get('password')
            if not master_password:
                return jsonify({"error": "Master password required"}), 400

            # Create encryption key from master password to identify files
            derived_key = derive_key(master_password)
            aesgcm = AESGCM(derived_key)

            # First get all file IDs that are encrypted with this password
            valid_file_ids = set()
            metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob("tx_*.json"))
            
            print("Processing metadata files...")  # Debug log
            
            for metadata_file in metadata_files:
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        encrypted_data = metadata.get('encrypted', {})
                        
                        try:
                            # Try to decrypt the metadata
                            nonce = base64.b64decode(encrypted_data.get('nonce', ''))
                            ciphertext = base64.b64decode(encrypted_data.get('ciphertext', ''))
                            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                            decrypted_metadata = json.loads(decrypted_data.decode())
                            
                            # If we can decrypt it, add the file_id to valid_file_ids
                            file_id = metadata.get('file_id')
                            if file_id:
                                valid_file_ids.add(file_id)
                                print(f"Added file_id: {file_id}")  # Debug log
                                
                        except Exception as e:
                            print(f"Decryption failed for {metadata_file}: {str(e)}")  # Debug log
                            continue
                except Exception as e:
                    print(f"Error reading metadata file {metadata_file}: {str(e)}")
                    continue

            print(f"Found {len(valid_file_ids)} valid file IDs")  # Debug log

            # Filter criteria for logs
            filter_ids = valid_file_ids
        else:  # GET request
            # No filtering for GET requests
            filter_ids = None

        # Now read all logs from the logs directory
        all_logs = []
        log_files = sorted(BLOCKCHAIN_LOGS_PATH.glob("log_*.json"), reverse=True)
        
        print("Processing log files...")  # Debug log
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    file_logs = json.load(f)
                    if isinstance(file_logs, list):
                        all_logs.extend(file_logs)
                    else:
                        all_logs.append(file_logs)
            except Exception as e:
                print(f"Error reading log file {log_file}: {str(e)}")
                continue

        # Filter logs if needed
        if filter_ids is not None:
            filtered_logs = [
                log for log in all_logs
                if log.get('details', {}).get('file_id') in filter_ids
            ]
        else:
            filtered_logs = all_logs

        # Sort logs by timestamp, newest first
        filtered_logs.sort(key=lambda x: x['timestamp'], reverse=True)

        print(f"Returning {len(filtered_logs)} filtered logs")  # Debug log
        
        return jsonify({
            "logs": filtered_logs,
            "total_count": len(filtered_logs)
        })

    except Exception as e:
        print(f"Error in get_blockchain_logs: {str(e)}")  # Debug log
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
