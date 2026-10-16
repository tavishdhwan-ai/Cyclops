from fastapi import FastAPI, Request, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.schemas import (
    EmailScanRequest,
    EmailScanResponse,
    UrlScanRequest,
    DocumentScanResponse,
    DocumentScanPayload,
)
from app.scanner import analyze_demo_email


app = FastAPI(
    title="SentinelAI Backend",
    description="FastAPI Backend for SentinelAI Email Security Analysis",
    version="0.1.0",
)

# Configure CORS to allow Chrome Extensions and local development endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Clean validation error response for invalid URLs or unsupported schemes."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "Bad Request",
            "message": str(exc),
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
    Returns deterministic rule-based scan response.
    """
    return analyze_demo_email(request)


@app.post("/scan-url", tags=["Scanner"])
async def scan_url_endpoint(request: UrlScanRequest):
    """
    Perform comprehensive, SSRF-protected website URL security analysis.
    Safely inspects domain age, DNS, redirect hops, static HTML, and external intelligence.
    """
    from app.scanner.url_pipeline import orchestrate_url_scan
    return await orchestrate_url_scan(request.url)


@app.post("/scan-document", response_model=DocumentScanResponse, tags=["Document Scanner"])
async def scan_document_upload(
    file: UploadFile = File(..., description="Document file to safely analyze")
):
    """
    Perform comprehensive 9-feature static security analysis on an uploaded document file.
    Inspects macros, embedded scripts, HTML phishing, hyperlinks, exploits, forms, and hidden text.
    Renders safe static preview without executing active content.
    """
    from app.scanner.doc_pipeline import orchestrate_document_scan
    file_bytes = await file.read()
    filename = file.filename or "uploaded_document.bin"
    return orchestrate_document_scan(file_bytes, filename)


@app.post("/scan-document-json", response_model=DocumentScanResponse, tags=["Document Scanner"])
async def scan_document_json(payload: DocumentScanPayload):
    """
    Perform comprehensive 9-feature static security analysis via JSON payload.
    Supports base64 file bytes or pre-configured test fixtures.
    """
    import base64
    from app.scanner.doc_pipeline import orchestrate_document_scan
    from app.scanner.presets import get_fixture_bytes

    if payload.file_content_base64:
        try:
            file_bytes = base64.b64decode(payload.file_content_base64)
        except Exception:
            raise ValueError("Invalid base64 encoding in file_content_base64.")
    else:
        # Load synthetic benign test fixture corresponding to requested preset or filename
        file_bytes = get_fixture_bytes(payload.preset or payload.file_name)

    return orchestrate_document_scan(file_bytes, payload.file_name)

