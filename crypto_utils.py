import os
import json
import uuid
from datetime import datetime
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Generator, Optional, Dict, Any

# Cryptography Constants
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 64 * 1024  # 64 KB
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

# File names
SALT_FILE = "salt.bin"
VAULT_KEY_FILE = "vault.key.enc"
MANIFEST_FILE = "manifest.enc"
FILES_DIR = "files"

def derive_mek(password: str, salt: bytes) -> bytes:
    """Derives the Master Encryption Key (MEK) using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )

def _encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypts small data chunks entirely in memory using AES-256-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def _decrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Decrypts small data chunks entirely in memory using AES-256-GCM."""
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Data too short")
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def init_vault(password: str, data_dir: str) -> bool:
    """Initializes the vault if it doesn't exist."""
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, FILES_DIR), exist_ok=True)
    
    salt_path = os.path.join(data_dir, SALT_FILE)
    if os.path.exists(salt_path):
        return False  # Already initialized

    # 1. Generate new Salt
    salt = os.urandom(SALT_SIZE)
    with open(salt_path, "wb") as f:
        f.write(salt)

    # 2. Derive MEK
    mek = derive_mek(password, salt)

    # 3. Generate Random Vault Key (VK)
    vk = os.urandom(32)

    # 4. Encrypt VK with MEK
    vk_enc = _encrypt_bytes(vk, mek)
    with open(os.path.join(data_dir, VAULT_KEY_FILE), "wb") as f:
        f.write(vk_enc)

    # 5. Create and encrypt empty manifest
    manifest_data = {
        "created_at": datetime.utcnow().isoformat(),
        "files": {},      # id -> { name, size, type, uuid, created_at, folder_id }
        "folders": {}     # id -> { name, parent_id, created_at }
    }
    write_manifest(manifest_data, vk, data_dir)
    return True

def unlock_vault(password: str, data_dir: str) -> Optional[bytes]:
    """Attempts to unlock vault and returns Vault Key (VK)."""
    salt_path = os.path.join(data_dir, SALT_FILE)
    vk_path = os.path.join(data_dir, VAULT_KEY_FILE)
    
    if not os.path.exists(salt_path) or not os.path.exists(vk_path):
        return None

    with open(salt_path, "rb") as f:
        salt = f.read()
        
    mek = derive_mek(password, salt)
    
    with open(vk_path, "rb") as f:
        vk_enc = f.read()
        
    try:
        vk = _decrypt_bytes(vk_enc, mek)
        return vk
    except Exception:
        return None

def write_manifest(manifest_data: dict, vk: bytes, data_dir: str):
    """Encrypts and writes the manifest to disk."""
    data = json.dumps(manifest_data).encode("utf-8")
    enc_data = _encrypt_bytes(data, vk)
    
    manifest_path = os.path.join(data_dir, MANIFEST_FILE)
    temp_path = manifest_path + ".tmp"
    with open(temp_path, "wb") as f:
        f.write(enc_data)
    os.replace(temp_path, manifest_path)

def read_manifest(vk: bytes, data_dir: str) -> dict:
    """Reads and decrypts the manifest."""
    manifest_path = os.path.join(data_dir, MANIFEST_FILE)
    if not os.path.exists(manifest_path):
        return {"files": {}, "folders": {}}
        
    with open(manifest_path, "rb") as f:
        enc_data = f.read()
        
    try:
        data = _decrypt_bytes(enc_data, vk)
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {"files": {}, "folders": {}}

# --- Streaming File Operations ---

def encrypt_stream(vk: bytes, data_stream: Generator[bytes, None, None], dest_path: str) -> int:
    """Streams data from generator, chunk encrypts it, and writes to dest_path."""
    aesgcm = AESGCM(vk)
    total_size = 0
    with open(dest_path, "wb") as f:
        for chunk in data_stream:
            total_size += len(chunk)
            nonce = os.urandom(NONCE_SIZE)
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            
            # Format: [4 bytes chunk_size][12 bytes nonce][ciphertext + 16 bytes tag]
            chunk_len = len(ciphertext)
            f.write(chunk_len.to_bytes(4, byteorder='big'))
            f.write(nonce)
            f.write(ciphertext)
    return total_size

def decrypt_stream(vk: bytes, src_path: str) -> Generator[bytes, None, None]:
    """Reads chunk encrypted file and yields decrypted chunks."""
    aesgcm = AESGCM(vk)
    with open(src_path, "rb") as f:
        while True:
            len_bytes = f.read(4)
            if not len_bytes:
                break
            chunk_len = int.from_bytes(len_bytes, byteorder='big')
            nonce = f.read(NONCE_SIZE)
            ciphertext = f.read(chunk_len)
            
            if len(nonce) != NONCE_SIZE or len(ciphertext) != chunk_len:
                raise ValueError("Corrupt file or incomplete chunk")
                
            yield aesgcm.decrypt(nonce, ciphertext, None)

# --- Security Operations ---

def execute_shuffle(data_dir: str, vk: bytes):
    """Dynamic Shuffling: Re-maps UUID file paths and re-encrypts manifest."""
    manifest = read_manifest(vk, data_dir)
    files_dir = os.path.join(data_dir, FILES_DIR)
    
    changes_made = False
    for file_id, file_meta in manifest.get("files", {}).items():
        old_uuid = file_meta.get("uuid")
        if old_uuid:
            old_path = os.path.join(files_dir, old_uuid)
            if os.path.exists(old_path):
                new_uuid = str(uuid.uuid4())
                new_path = os.path.join(files_dir, new_uuid)
                
                # Rename the physical file
                os.rename(old_path, new_path)
                
                # Update manifest
                file_meta["uuid"] = new_uuid
                changes_made = True
                
    if changes_made:
        manifest["last_shuffled"] = datetime.utcnow().isoformat()
        write_manifest(manifest, vk, data_dir)

def crypto_shred_dir(data_dir: str):
    """Panic Purge: Overwrites all files with random bytes 1 time, then unlinks."""
    if not os.path.exists(data_dir):
        return
        
    for root, dirs, files in os.walk(data_dir, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                # Get file size
                size = os.path.getsize(file_path)
                # Overwrite with random bytes
                with open(file_path, "r+b") as f:
                    chunk = 1024 * 1024 # 1MB
                    for _ in range(0, size, chunk):
                        write_len = min(chunk, size - f.tell())
                        f.write(os.urandom(write_len))
                # Delete
                os.remove(file_path)
            except Exception:
                pass
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except Exception:
                pass
