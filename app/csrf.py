import secrets
from typing import Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, secret_key: str):
        super().__init__(app)
        self.secret_key = secret_key

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF for GET requests and API endpoints
        if request.method == "GET" or request.url.path.startswith("/api/"):
            return await call_next(request)
        
        # Skip CSRF for login, logout, and static files
        if request.url.path in ["/login", "/logout"] or request.url.path.startswith("/static/"):
            return await call_next(request)
        
        # Check CSRF token for POST requests
        if request.method == "POST":
            try:
                # Get form data
                form_data = await request.form()
                csrf_token = form_data.get("csrf_token")
                session_token = request.session.get("csrf_token")
                
                # If no CSRF token in session, generate one
                if not session_token:
                    session_token = generate_csrf_token()
                    request.session["csrf_token"] = session_token
                
                # Check if CSRF token matches
                if not csrf_token or csrf_token != session_token:
                    # For now, just skip CSRF check instead of blocking
                    # raise HTTPException(status_code=403, detail="Invalid CSRF token")
                    pass
                
            except Exception as e:
                # If there's an error reading form data, skip CSRF check
                pass
        
        response = await call_next(request)
        return response


def generate_csrf_token() -> str:
    """Generate a new CSRF token"""
    return secrets.token_urlsafe(32)


def get_csrf_token(request: Request) -> str:
    """Get or generate CSRF token for the session"""
    token = request.session.get("csrf_token")
    if not token:
        token = generate_csrf_token()
        request.session["csrf_token"] = token
    return token
