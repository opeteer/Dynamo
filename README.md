<div align="center">
  
# 🛡️ Dynamo Vault

**High-Security, Dynamic Shuffling, Self-Hosted Encrypted Storage Vault**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

---

**Dynamo** is a stealthy, high-security vault application designed to be self-hosted on a private Linux server or exposed via a reverse proxy/IP tunnel. It provides an impenetrable at-rest encrypted storage system with periodic background shuffling and a "Panic Purge" mechanism.

## ✨ Key Features

- 🔐 **Zero-Knowledge In-Memory Architecture**: Your Master Password is used to derive a Master Encryption Key (MEK) via **Argon2id**. Vault Keys reside *only in RAM* during active sessions and are never written to disk in plaintext.
- 🔄 **Dynamic Path Shuffling**: A background scheduler periodically rotates physical UUID filenames and re-encrypts the storage manifest, preventing physical access patterns from being analyzed over time.
- 🌊 **On-the-Fly Streaming Crypto**: Uses chunked **AES-256-GCM** encryption. Files are stream-encrypted during upload and stream-decrypted during download, allowing you to handle massive multi-gigabyte files with virtually zero RAM overhead.
- 💀 **Panic Purge (Crypto-Shredding)**: A highly prominent "Danger Zone" feature that instantly shreds your vault keys from memory, and overwrites all physical encrypted files with random bytes before deleting them permanently.
- 🖥️ **Cyber-Bunker UI**: A sleek, dark-themed Single-Page Application (SPA) utilizing Tailwind CSS and Alpine.js, giving you a smooth and responsive file management experience.

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Cryptography:** `cryptography` (AES-256-GCM), `argon2-cffi`
- **Task Scheduling:** APScheduler (AsyncIOScheduler)
- **Frontend:** HTML5, Tailwind CSS, Alpine.js, Lucide Icons
- **Deployment:** Docker, Docker Compose

## 🚀 Quick Start

The easiest way to deploy Dynamo Vault is via Docker.

### Prerequisites
- Docker & Docker Compose installed on your server.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/opeteer/Dynamo.git
   cd Dynamo
   ```

2. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env to adjust shuffling intervals or upload limits if needed
   ```

3. **Deploy with Docker Compose:**
   ```bash
   docker-compose up --build -d
   ```

4. **Access the Vault:**
   Open your browser and navigate to `http://localhost:8031` (or your server's IP/domain).
   Upon your first visit, you will be prompted to initialize your vault with a strong Master Password.

## ⚙️ Configuration Variables

Customize the `.env` file to suit your security posture:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `/app/data` | Path to store the encrypted vault files |
| `SHUFFLE_INTERVAL_HOURS` | `6` | How often the background dynamic shuffling runs |
| `SESSION_TIMEOUT_MINUTES`| `15` | Inactivity timeout before the vault automatically locks |
| `MAX_UPLOAD_SIZE_MB` | `1024` | Backend limit for individual file uploads |

## 👨‍💻 Author

Built with ❤️ and paranoia by **[opeteer](https://github.com/opeteer)**.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<div align="center">
  <i>Stay Secure. Stay Stealthy.</i>
</div>
