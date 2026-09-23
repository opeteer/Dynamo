import os
import uuid
import uuid as uuid_lib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Response, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings
from pydantic import BaseModel
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import crypto_utils

class Settings(BaseSettings):
    DATA_DIR: str = "/app/data"
    SHUFFLE_INTERVAL_HOURS: int = 6
    SESSION_TIMEOUT_MINUTES: int = 15
    MAX_UPLOAD_SIZE_MB: int = 1024

    class Config:
        env_file = ".env"

settings = Settings()
app = FastAPI(title="Dynamo Vault")

# Handle Reverse Proxy Headers
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# In-memory Sessions
# token -> {"vk": bytes, "last_active": datetime}
SESSIONS: Dict[str, Dict[str, Any]] = {}

def get_current_vk(request: Request) -> bytes:
    """Dependency to extract VK from active session."""
    token = request.cookies.get("session_token")
    if not token or token not in SESSIONS:
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    session = SESSIONS[token]
    
    # Check timeout
    timeout_delta = timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
    if datetime.utcnow() - session["last_active"] > timeout_delta:
        del SESSIONS[token]
        raise HTTPException(status_code=401, detail="Session expired")
        
    session["last_active"] = datetime.utcnow()
    return session["vk"]

# --- Scheduler ---
scheduler = AsyncIOScheduler()

def auto_shuffle_task():
    """Background task to run shuffling."""
    print("[Dynamo] Running scheduled dynamic shuffle...")
    # Get any active VK if present, or if we need to shuffle while locked?
    # Actually, we can't fully shuffle (re-encrypt manifest) if vault is locked and VK is not in RAM.
    # We could just skip if locked, or we could require an encrypted offline key. 
    # For now, we only shuffle if an active session exists (or we iterate and find one).
    active_vk = None
    for token, session in SESSIONS.items():
        active_vk = session["vk"]
        break
        
    if active_vk:
        crypto_utils.execute_shuffle(settings.DATA_DIR, active_vk)
        print("[Dynamo] Shuffle complete.")
    else:
        print("[Dynamo] Vault locked, skipping shuffle.")

@app.on_event("startup")
async def startup_event():
    os.makedirs(settings.DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(settings.DATA_DIR, crypto_utils.FILES_DIR), exist_ok=True)
    scheduler.add_job(auto_shuffle_task, 'interval', hours=settings.SHUFFLE_INTERVAL_HOURS)
    scheduler.start()

@app.on_event("shutdown")
async def shutdown_event():
    SESSIONS.clear()
    scheduler.shutdown()

# --- Models ---
class PasswordAuth(BaseModel):
    password: str

# --- Endpoints ---
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    # Attempt to load templates/index.html
    html_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dynamo Template Not Found</h1>")

@app.get("/api/status")
async def get_status(request: Request):
    salt_path = os.path.join(settings.DATA_DIR, crypto_utils.SALT_FILE)
    initialized = os.path.exists(salt_path)
    
    token = request.cookies.get("session_token")
    unlocked = token in SESSIONS
    
    # Check if session is expired
    if unlocked:
        session = SESSIONS[token]
        if datetime.utcnow() - session["last_active"] > timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES):
            del SESSIONS[token]
            unlocked = False

    return {
        "initialized": initialized,
        "unlocked": unlocked
    }

@app.post("/api/init")
async def init_vault(auth: PasswordAuth, response: Response):
    success = crypto_utils.init_vault(auth.password, settings.DATA_DIR)
    if not success:
        raise HTTPException(status_code=400, detail="Vault already initialized")
    return {"status": "ok"}

@app.post("/api/unlock")
async def unlock_vault(auth: PasswordAuth, response: Response):
    vk = crypto_utils.unlock_vault(auth.password, settings.DATA_DIR)
    if not vk:
        raise HTTPException(status_code=401, detail="Invalid password or corrupted vault")
        
    token = str(uuid.uuid4())
    SESSIONS[token] = {
        "vk": vk,
        "last_active": datetime.utcnow()
    }
    
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.SESSION_TIMEOUT_MINUTES * 60
    )
    return {"status": "ok"}

@app.post("/api/lock")
async def lock_vault(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token and token in SESSIONS:
        del SESSIONS[token]
    response.delete_cookie("session_token")
    return {"status": "ok"}

@app.get("/api/files")
async def list_files(vk: bytes = Depends(get_current_vk)):
    manifest = crypto_utils.read_manifest(vk, settings.DATA_DIR)
    # Hide physical UUIDs from frontend
    safe_files = {}
    for fid, fmeta in manifest.get("files", {}).items():
        safe_meta = fmeta.copy()
        safe_meta.pop("uuid", None)
        safe_files[fid] = safe_meta
        
    return {
        "files": safe_files,
        "folders": manifest.get("folders", {})
    }

@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    vk: bytes = Depends(get_current_vk)
):
    manifest = crypto_utils.read_manifest(vk, settings.DATA_DIR)
    
    physical_uuid = str(uuid.uuid4())
    virtual_id = str(uuid.uuid4())
    
    dest_path = os.path.join(settings.DATA_DIR, crypto_utils.FILES_DIR, physical_uuid)
    
    # Stream generator to chunk encrypt
    def file_stream():
        while True:
            chunk = file.file.read(crypto_utils.CHUNK_SIZE)
            if not chunk:
                break
            yield chunk

    total_size = crypto_utils.encrypt_stream(vk, file_stream(), dest_path)
    
    manifest["files"][virtual_id] = {
        "name": file.filename,
        "size": total_size,
        "type": file.content_type,
        "uuid": physical_uuid,
        "created_at": datetime.utcnow().isoformat()
    }
    
    crypto_utils.write_manifest(manifest, vk, settings.DATA_DIR)
    return {"id": virtual_id, "size": total_size}

@app.get("/api/files/download/{file_id}")
async def download_file(file_id: str, vk: bytes = Depends(get_current_vk)):
    manifest = crypto_utils.read_manifest(vk, settings.DATA_DIR)
    file_meta = manifest["files"].get(file_id)
    if not file_meta:
        raise HTTPException(status_code=404, detail="File not found")
        
    physical_uuid = file_meta.get("uuid")
    src_path = os.path.join(settings.DATA_DIR, crypto_utils.FILES_DIR, physical_uuid)
    
    if not os.path.exists(src_path):
        raise HTTPException(status_code=404, detail="Physical file missing")

    headers = {
        "Content-Disposition": f'attachment; filename="{file_meta["name"]}"'
    }
    
    # We yield the decrypted stream directly
    return StreamingResponse(
        crypto_utils.decrypt_stream(vk, src_path),
        media_type=file_meta.get("type", "application/octet-stream"),
        headers=headers
    )

@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str, vk: bytes = Depends(get_current_vk)):
    manifest = crypto_utils.read_manifest(vk, settings.DATA_DIR)
    file_meta = manifest["files"].get(file_id)
    if not file_meta:
        raise HTTPException(status_code=404, detail="File not found")
        
    physical_uuid = file_meta.get("uuid")
    src_path = os.path.join(settings.DATA_DIR, crypto_utils.FILES_DIR, physical_uuid)
    
    # Delete physically
    if os.path.exists(src_path):
        os.remove(src_path)
        
    # Remove from manifest
    del manifest["files"][file_id]
    crypto_utils.write_manifest(manifest, vk, settings.DATA_DIR)
    
    return {"status": "ok"}

@app.post("/api/shuffle")
async def trigger_shuffle(vk: bytes = Depends(get_current_vk)):
    crypto_utils.execute_shuffle(settings.DATA_DIR, vk)
    return {"status": "ok"}

@app.post("/api/purge")
async def trigger_purge(request: Request, response: Response):
    # Panic Purge does NOT require active session to trigger (depends on security model).
    # But for safety in a web UI, let's require it OR you can trigger it locked.
    # We'll allow it if locked or unlocked, but if unlocked we clear sessions.
    SESSIONS.clear()
    response.delete_cookie("session_token")
    
    crypto_utils.crypto_shred_dir(settings.DATA_DIR)
    return {"status": "purged"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8031, reload=True)
