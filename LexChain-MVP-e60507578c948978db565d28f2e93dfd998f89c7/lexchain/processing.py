import os
import json
import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path
import uuid
import math
from typing import Dict, List, Optional
import base64
import zipfile  # Used for archiving the shards

# Crypto / KDF imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Blockchain Directories Setup ---
BLOCKCHAIN_DIR = Path("secure_storage") / "blockchain"
BLOCKCHAIN_METADATA_PATH = BLOCKCHAIN_DIR / "metadata"
BLOCKCHAIN_LOGS_PATH = BLOCKCHAIN_DIR / "logs"

for d in [BLOCKCHAIN_DIR, BLOCKCHAIN_METADATA_PATH, BLOCKCHAIN_LOGS_PATH]:
    d.mkdir(parents=True, exist_ok=True)

# --- Helper Functions for Metadata Encryption ---
def encrypt_dict(aesgcm: AESGCM, data: dict) -> dict:
    """
    Encrypt a dictionary by first converting it to JSON.
    Returns a dict containing base64-encoded nonce and ciphertext.
    """
    json_data = json.dumps(data).encode('utf-8')
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json_data, None)
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_dict(aesgcm: AESGCM, encrypted_data: dict) -> dict:
    """
    Decrypt an encrypted dict (with keys "nonce" and "ciphertext")
    and return the original dictionary.
    """
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode('utf-8'))

# --- Blockchain Logging Helpers ---
def store_metadata_to_blockchain(metadata: Dict) -> None:
    """
    Simulate sending the metadata to a blockchain by writing a JSON file
    into the 'secure_storage/blockchain/metadata' folder.
    The metadata here contains both a public (fallback) section and an encrypted section.
    """
    tx_id = f"tx_{metadata['file_id']}_{int(datetime.now().timestamp())}.json"
    tx_file = BLOCKCHAIN_METADATA_PATH / tx_id
    with open(tx_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata stored on blockchain as transaction {tx_id}")

def store_log_to_blockchain(log: Dict) -> None:
    """
    Simulate sending a log entry to a blockchain by writing a JSON file
    into the 'secure_storage/blockchain/logs' folder.
    """
    tx_id = f"log_{log['timestamp'].replace(':', '-')}_{log['action']}.json"
    tx_file = BLOCKCHAIN_LOGS_PATH / tx_id
    with open(tx_file, 'w') as f:
        json.dump(log, f, indent=2)
    print(f"Log stored on blockchain as {tx_id}")

def log_action(action: str, details: Dict) -> None:
    """
    Create a log entry with a timestamp, action, and details.
    Then store it on the blockchain.
    """
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details
    }
    store_log_to_blockchain(log_entry)

# --- Main SecureFileManager Class (Fragmentation without Reed–Solomon) ---
class SecureFileManager:
    def __init__(self, derived_key: bytes, storage_path: str = "secure_storage"):
        """
        Initialize the file manager with an in‑memory derived key (AES‑256).
        No key is read/written to disk.
        """
        self.storage_path = Path(storage_path)
        self.fragments_path = self.storage_path / "fragments"
        self.fragments_path.mkdir(parents=True, exist_ok=True)
        mimetypes.init()
        self.key = derived_key
        self.aesgcm = AESGCM(self.key)

    def encrypt_chunk(self, data: bytes) -> bytes:
        """Encrypt data using AES‑GCM (prepend a random 12‑byte nonce)."""
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt_chunk(self, data: bytes) -> bytes:
        """Decrypt data previously encrypted with encrypt_chunk()."""
        nonce = data[:12]
        ct = data[12:]
        return self.aesgcm.decrypt(nonce, ct, None)

    def detect_mime_type(self, file_path: str) -> str:
        """Heuristic to detect a file's MIME type."""
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

    def fragment_file(self, file_path: str, progress_callback=None) -> str:
        """
        Split and encrypt a file into fragments.
        The clear metadata (including the original filename, size, etc.)
        is encrypted and stored along with a public fallback.
        An extra field "deleted" is included to allow chaincode‐like metadata updates.
        All fragments for the file are saved into the same archive (with a .lexchain extension)
        using a random archive name. Within that archive each shard is saved with a random filename.
        """
        file_path = Path(file_path)
        file_id = hashlib.sha256(f"{file_path.name}{datetime.now()}".encode()).hexdigest()[:12]
        with open(file_path, 'rb') as f:
            data = f.read()
        total_size = len(data)
        target_fragment_size = 1024 * 1024  # 1 MB fragments (adjust as needed)
        k = math.ceil(total_size / target_fragment_size)

        shard_metadata = []  # To store per-shard metadata
        encrypted_fragments = []  # To store each encrypted shard

        # For each shard, generate a randomized name (to be used inside the archive)
        for index in range(k):
            start = index * target_fragment_size
            end = start + target_fragment_size
            fragment = data[start:end]
            encrypted_fragment = self.encrypt_chunk(fragment)
            shard_fingerprint = hashlib.sha256(fragment).hexdigest()
            # Generate a random filename for this shard inside the archive
            shard_inside_name = f"{uuid.uuid4().hex}.dat"
            encrypted_fragments.append((shard_inside_name, encrypted_fragment))
            shard_metadata.append({
                "index": index,
                "shard_name": shard_inside_name,  # Save the randomized name for this shard
                "fingerprint": shard_fingerprint,
                "size": len(fragment)
            })
            if progress_callback:
                progress_callback((index + 1) / k * 100)

        # Create a single archive that will contain all shards for this file.
        archive_name = f"{uuid.uuid4().hex}.lexchain"
        archive_path = self.fragments_path / archive_name

        # Write each encrypted fragment into the archive with its randomized filename.
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for shard_name, encrypted_fragment in encrypted_fragments:
                archive.writestr(shard_name, encrypted_fragment)

        # Update each shard metadata to record the archive name.
        for shard in shard_metadata:
            shard["archive"] = archive_name

        mime_type = self.detect_mime_type(str(file_path))
        clear_metadata = {
            "file_id": file_id,
            "original_filename": file_path.name,
            "creation_date": datetime.now().isoformat(),
            "total_size": total_size,
            "mime_type": mime_type,
            "k": k,
            "shards": shard_metadata,
            "deleted": False
        }
        public_metadata = {
            "original_filename": f"Encrypted File ({file_id[:4]})",
            "creation_date": "Encrypted",
            "total_size": "Encrypted",
            "mime_type": "Encrypted",
            "k": None,
            "shards": None,
            "deleted": None
        }
        encrypted_metadata = encrypt_dict(self.aesgcm, clear_metadata)
        metadata_to_store = {
            "file_id": file_id,
            "public": public_metadata,
            "encrypted": encrypted_metadata
        }
        store_metadata_to_blockchain(metadata_to_store)
        log_action("upload", {"file_id": file_id, "filename": file_path.name, "size": total_size})
        return file_id

    def rebuild_file(self, file_id: str, output_path: Optional[str] = None) -> str:
        """
        Reassemble the file by reading, decrypting, and concatenating its fragments.
        If the metadata indicates that the file has been deleted, reconstruction fails.
        """
        metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
        if not metadata_files:
            raise ValueError(f"No metadata found for file ID: {file_id}")
        with open(metadata_files[0], 'r') as f:
            stored_metadata = json.load(f)
        try:
            clear_metadata = decrypt_dict(self.aesgcm, stored_metadata["encrypted"])
        except Exception as e:
            raise ValueError("Failed to decrypt metadata. Possibly wrong master password.")
        if clear_metadata.get("deleted", False):
            raise ValueError("File has been deleted.")

        # All shards are in the same archive.
        archive_name = clear_metadata["shards"][0]["archive"]
        archive_path = self.fragments_path / archive_name
        if not archive_path.exists():
            raise ValueError(f"Fragment archive {archive_name} missing.")

        shards = []
        with zipfile.ZipFile(archive_path, 'r') as archive:
            for shard_info in clear_metadata["shards"]:
                shard_inside_name = shard_info["shard_name"]
                try:
                    encrypted_fragment = archive.read(shard_inside_name)
                    fragment = self.decrypt_chunk(encrypted_fragment)
                except Exception as e:
                    raise ValueError(f"Decryption failed for shard {shard_inside_name}: {e}")
                if hashlib.sha256(fragment).hexdigest() != shard_info["fingerprint"]:
                    raise ValueError(f"Integrity check failed for shard {shard_inside_name}.")
                shards.append((shard_info["index"], fragment))
        shards.sort(key=lambda x: x[0])
        original_data = b"".join(fragment for idx, fragment in shards)
        original_data = original_data[:clear_metadata["total_size"]]
        if output_path is None:
            output_path = clear_metadata["original_filename"]
        output_path = Path(output_path)
        orig_ext = Path(clear_metadata["original_filename"]).suffix
        if output_path.suffix != orig_ext:
            output_path = output_path.with_suffix(orig_ext)
        with open(output_path, "wb") as out:
            out.write(original_data)
        log_action("download", {"file_id": file_id, "output": str(output_path)})
        return str(output_path)

    def list_files(self) -> List[Dict]:
        """
        Return files (by reading on‑chain metadata) that have not been marked as deleted.
        """
        files = []
        for metadata_file in BLOCKCHAIN_METADATA_PATH.glob("tx_*.json"):
            try:
                with open(metadata_file, 'r') as f:
                    stored_metadata = json.load(f)
            except Exception:
                continue
            try:
                clear_metadata = decrypt_dict(self.aesgcm, stored_metadata["encrypted"])
            except Exception:
                clear_metadata = stored_metadata.get("public", {})
            if clear_metadata.get("deleted", False):
                continue
            files.append({
                "file_id": stored_metadata.get("file_id"),
                "filename": clear_metadata.get("original_filename", "Encrypted File"),
                "creation_date": clear_metadata.get("creation_date", "Encrypted"),
                "size": clear_metadata.get("total_size", 0),
                "mime_type": clear_metadata.get("mime_type", "Encrypted"),
            })
        return files

    def delete_file(self, file_id: str) -> bool:
        """
        "Delete" a file by removing its local fragments and updating its on‑chain metadata.
        The metadata is updated (chaincode style) by marking the file as deleted.
        As a result, the file will no longer appear in the dashboard.
        """
        metadata_files = list(BLOCKCHAIN_METADATA_PATH.glob(f"tx_{file_id}_*.json"))
        if not metadata_files:
            raise ValueError(f"No metadata found for file ID: {file_id}")
        metadata_path = metadata_files[0]
        with open(metadata_path, 'r') as f:
            stored_metadata = json.load(f)
        try:
            clear_metadata = decrypt_dict(self.aesgcm, stored_metadata["encrypted"])
        except Exception as e:
            raise ValueError("Failed to decrypt metadata. Possibly wrong master password. Cannot delete file.")
        # Remove the archive containing all fragments.
        archive_name = clear_metadata["shards"][0]["archive"]
        archive_path = self.fragments_path / archive_name
        if archive_path.exists():
            archive_path.unlink()
        clear_metadata["deleted"] = True
        updated_encrypted_metadata = encrypt_dict(self.aesgcm, clear_metadata)
        stored_metadata["encrypted"] = updated_encrypted_metadata
        with open(metadata_path, "w") as f:
            json.dump(stored_metadata, f, indent=2)
        log_action("delete", {"file_id": file_id, "filename": clear_metadata["original_filename"]})
        return True

# --- Console-based Main App with Retry Master Password Option ---
import argparse
import getpass

class ConsoleApp:
    def __init__(self):
        self.derived_key = None
        self.manager = None

    def prompt_for_password(self) -> bytes:
        password = getpass.getpass("Enter Master Password: ")
        salt = b"FixedSaltValue"
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            return kdf.derive(password.encode("utf-8"))
        except Exception as e:
            print(f"Failed to derive key: {e}")
            return None

    def retry_master_password(self):
        print("Retrying master password...")
        self.derived_key = self.prompt_for_password()
        if self.derived_key:
            self.manager = SecureFileManager(self.derived_key)
        else:
            print("Could not derive key. Exiting.")
            exit(1)

    def run(self):
        parser = argparse.ArgumentParser(description="Secure File Manager (Console Version)")
        parser.add_argument("--password", "-p", help="Master password (if not provided, will prompt)")
        subparsers = parser.add_subparsers(dest="command", help="Commands")

        parser_upload = subparsers.add_parser("upload", help="Upload one or more files")
        parser_upload.add_argument("files", nargs="+", help="File paths to upload")

        parser_download = subparsers.add_parser("download", help="Download a file")
        parser_download.add_argument("file_id", help="File ID to download")
        parser_download.add_argument("output", help="Output file path")

        parser_list = subparsers.add_parser("list", help="List files")

        parser_delete = subparsers.add_parser("delete", help="Delete a file")
        parser_delete.add_argument("file_id", help="File ID to delete")

        parser_retry = subparsers.add_parser("retry", help="Retry master password")

        args = parser.parse_args()

        if args.password:
            salt = b"FixedSaltValue"
            try:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100_000,
                )
                self.derived_key = kdf.derive(args.password.encode("utf-8"))
            except Exception as e:
                print(f"Failed to derive key: {e}")
                exit(1)
        else:
            self.derived_key = self.prompt_for_password()

        if not self.derived_key:
            print("Master password required.")
            exit(1)

        self.manager = SecureFileManager(self.derived_key)

        if args.command == "upload":
            for file_path in args.files:
                try:
                    file_id = self.manager.fragment_file(file_path)
                    print(f"Uploaded {file_path} with File ID: {file_id}")
                except Exception as e:
                    print(f"Error uploading {file_path}: {e}")
        elif args.command == "download":
            try:
                output_file = self.manager.rebuild_file(args.file_id, args.output)
                print(f"Downloaded file saved as: {output_file}")
            except Exception as e:
                print(f"Error downloading file {args.file_id}: {e}")
        elif args.command == "list":
            try:
                files = self.manager.list_files()
                print(json.dumps(files, indent=2))
            except Exception as e:
                print(f"Error listing files: {e}")
        elif args.command == "delete":
            try:
                self.manager.delete_file(args.file_id)
                print(f"Deleted file {args.file_id}")
            except Exception as e:
                print(f"Error deleting file {args.file_id}: {e}")
        elif args.command == "retry":
            self.retry_master_password()
            print("Master password has been retried. New key set.")
        else:
            parser.print_help()

if __name__ == "__main__":
    ConsoleApp().run()
