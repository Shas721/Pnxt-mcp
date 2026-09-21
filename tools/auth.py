import asyncio
import secrets
import logging
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
import httpx

from config import AUTH_CALLBACK_TIMEOUT, POINTNXT_BASE_URL, POINTNXT_LOGIN_URL
from services.auth_session import clear_session, current_user as session_user, get_session, set_session

logger = logging.getLogger(__name__)

def current_user() -> dict:
    return session_user()

def _wait_for_callback(state: str) -> dict:
    received: dict = {}
    class Callback(BaseHTTPRequestHandler):
        def do_GET(self):
            received.update({k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()})
            valid = secrets.compare_digest(received.get("state", ""), state)
            self.send_response(200 if valid else 401); self.end_headers()
            self.wfile.write(b"PointNXT sign-in complete. You may close this tab." if valid else b"Invalid sign-in state.")
        def log_message(self, *_): pass
    server = HTTPServer(("127.0.0.1", 0), Callback)
    redirect = f"http://127.0.0.1:{server.server_port}/callback"
    webbrowser.open(f"{POINTNXT_LOGIN_URL}?{urlencode({'redirect_uri': redirect, 'state': state})}")
    server.timeout = AUTH_CALLBACK_TIMEOUT
    server.handle_request(); server.server_close()
    return received

async def authenticate() -> dict:
    """Open PointNXT in the browser and wait for the completed login callback."""
    state = secrets.token_urlsafe(32)
    values = await asyncio.to_thread(_wait_for_callback, state)
    if not values:
        return {"authenticated": False, "message": "PointNXT sign-in timed out or was not completed."}
    if not secrets.compare_digest(values.get("state", ""), state):
        return {"authenticated": False, "message": "PointNXT sign-in was rejected: invalid callback state."}
    if not values.get("accessToken") and not values.get("access_token"):
        return {"authenticated": False, "message": "PointNXT sign-in timed out or was not completed."}
    logger.info("PointNXT browser login succeeded")
    return set_session(values).as_dict()

async def logout() -> dict:
    session = get_session()
    try:
        if session and session.get_refresh_token():
            async with httpx.AsyncClient(timeout=15) as client:
                await client.post(f"{POINTNXT_BASE_URL.rstrip('/')}/auth/logout",
                                  json={"refreshToken": session.get_refresh_token()})
    finally:
        clear_session()
    logger.info("PointNXT logout completed")
    return {"authenticated": False, "message": "You have been signed out of PointNXT."}
