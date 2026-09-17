# SentinelAI FastAPI Backend (Phase 3A)

FastAPI backend service for SentinelAI email security analysis. Phase 3A implements a local development foundation providing controlled demo security analysis for the SentinelAI Gmail Chrome Extension.

---

## Technical Overview

- **Framework**: Python / FastAPI / Uvicorn / Pydantic v2
- **Host**: `127.0.0.1` (Localhost binding only for security)
- **Port**: `8000`
- **Analysis Mode**: Controlled Demo Mode (`mode: "demo"`)

---

## CORS Decision & Local Security

The backend configures CORS using `CORSMiddleware` with explicit local origin permissions:
- Local HTTP origins: `http://127.0.0.1:3000`, `http://localhost:3000`, `http://127.0.0.1:8000`, `http://localhost:8000`
- Chrome Extension origin regex: `^chrome-extension://.*$`

**Rationale**: Chrome extensions make cross-origin HTTP requests using custom `chrome-extension://<EXTENSION_ID>` origin headers. Using a target regex pattern permits extension calls during local development without opening wildcard (`*`) access in production.

---

## Setup & Running Instructions (Windows PowerShell)

Follow these steps to run the backend locally:

1. Open a terminal.
2. Navigate to the backend folder:
   ```powershell
   cd C:\Users\Tavish\Desktop\cyclops\backend
   ```
3. Create a Python virtual environment:
   ```powershell
   python -m venv .venv
   ```
4. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
5. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
6. Start the backend server:
   ```powershell
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
7. Verify health endpoint in browser:
   [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
8. Open interactive API documentation:
   [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
9. Reload the Chrome extension in `chrome://extensions`.
10. Refresh Gmail in Chrome.
11. Open any email.
12. Confirm the SentinelAI panel displays the backend scan response with the **"Backend Demo"** badge.

---

## Running Tests

Run pytest to verify endpoint status and Pydantic validation rules:
```powershell
pytest
```
Or verify Python bytecode compilation:
```powershell
python -m compileall app
```

---

## Endpoints Summary

- **GET `/health`**: Returns service status `{ "status": "ok", "service": "sentinelai-backend", "mode": "demo" }`
- **POST `/scan-email`**: Accepts JSON payload with sender, subject, body, links, attachments. Returns structured threat score, risk level, findings array, recommendation, and attachment results.
