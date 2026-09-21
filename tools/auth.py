import asyncio
import secrets
import logging
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
import httpx

from config import (AUTH_CALLBACK_TIMEOUT, DEV_MODE, POINTNXT_AUTH_CALLBACK_URL,
                    POINTNXT_BASE_URL, POINTNXT_LOGIN_URL)
from services.auth_session import clear_session, current_user as session_user, get_session, set_session

logger = logging.getLogger(__name__)
_pending: dict[str, tuple[threading.Event, dict]] = {}
_pending_lock = threading.Lock()

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
    existing = get_session()
    if existing and existing.is_authenticated():
        logger.info("PointNXT authentication session loaded")
        return existing.as_dict()
    logger.info("PointNXT authentication started")
    state = secrets.token_urlsafe(32)
    if DEV_MODE:
        values = await asyncio.to_thread(_wait_for_callback, state)
    else:
        if not POINTNXT_AUTH_CALLBACK_URL.startswith("https://"):
            return {"authenticated": False, "message": "PointNXT public authentication callback is not configured."}
        event, values = threading.Event(), {}
        with _pending_lock:
            _pending[state] = (event, values)
        login_url = f"{POINTNXT_LOGIN_URL}?{urlencode({'redirect_uri': POINTNXT_AUTH_CALLBACK_URL, 'state': state})}"
        logger.info("PointNXT login URL generated")
        return {"authenticated": False, "message": "Open the login URL to sign in to PointNXT.", "login_url": login_url}
    if not values:
        return {"authenticated": False, "message": "PointNXT sign-in timed out or was not completed."}
    if not secrets.compare_digest(values.get("state", ""), state):
        return {"authenticated": False, "message": "PointNXT sign-in was rejected: invalid callback state."}
    if not values.get("accessToken") and not values.get("access_token"):
        return {"authenticated": False, "message": "PointNXT sign-in timed out or was not completed."}
    logger.info("PointNXT browser login succeeded")
    return set_session(values).as_dict()

async def auth_callback(request):
    """Receive the public browser callback and wake the waiting authenticate call."""
    from starlette.responses import JSONResponse
    values = dict(request.query_params)
    state = values.get("state", "")
    logger.info("PointNXT authentication callback received")
    with _pending_lock:
        pending = _pending.get(state)
    if not state or pending is None:
        logger.warning("PointNXT authentication callback state validation failed")
        return JSONResponse({"authenticated": False, "message": "Invalid or expired authentication state."}, status_code=401)
    event, result = pending
    result.update(values)
    logger.info("PointNXT authentication callback state validation passed")
    if not values.get("accessToken") and not values.get("access_token") and values.get("code"):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.post(
                    f"{POINTNXT_BASE_URL.rstrip('/')}/auth/login",
                    json={"code": values["code"], "redirectUri": POINTNXT_AUTH_CALLBACK_URL},
                )
                response.raise_for_status()
            values = response.json().get("data", response.json())
            result.clear(); result.update(values)
        except (httpx.HTTPError, ValueError, KeyError):
            return JSONResponse({"authenticated": False, "message": "PointNXT sign-in could not be completed."}, status_code=401)
    if not values.get("accessToken") and not values.get("access_token"):
        return JSONResponse({"authenticated": False, "message": "PointNXT sign-in response did not include an access token."}, status_code=401)
    set_session(values)
    logger.info("PointNXT browser login succeeded")
    logger.info("PointNXT authentication session stored successfully")
    with _pending_lock:
        _pending.pop(state, None)
    event.set()
    return JSONResponse({"message": "PointNXT sign-in received. You may close this window."})

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
