from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.schemas import EmailScanRequest, EmailScanResponse
from app.scanner import analyze_demo_email

app = FastAPI(
    title="SentinelAI Backend",
    description="FastAPI Backend for SentinelAI Email Security Analysis (Phase 3A)",
    version="0.1.0",
)

# Configure CORS for local development and Chrome Extensions
allowed_origins = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Clean validation error response without exposing stack traces."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "The request body failed schema validation.",
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Generic error handler to prevent stack traces leaking to client."""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An error occurred while processing the scan request.",
        },
    )


@app.get("/health", tags=["Health"])
async def health_check():
    """Health status endpoint."""
    return {
        "status": "ok",
        "service": "sentinelai-backend",
        "mode": "demo",
    }


@app.post("/scan-email", response_model=EmailScanResponse, tags=["Scanner"])
async def scan_email(request: EmailScanRequest = EmailScanRequest()):
    """
    Perform security analysis on provided email metadata/body.
    Returns controlled demo scan response for Phase 3A.
    """
    return analyze_demo_email(request)
