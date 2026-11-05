import json
import logging
import os
import secrets
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Flask, abort, redirect, request, session

app = Flask(__name__)

# Keep all credentials in the Codespaces environment, never in Git.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CLIENT_ID = os.environ.get("UPSTOX_CLIENT_ID")
CLIENT_SECRET = os.environ.get("UPSTOX_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("UPSTOX_REDIRECT_URI")
TOKEN_FILE = Path(os.environ.get("UPSTOX_TOKEN_FILE", ".upstox_token.json"))

if not app.secret_key:
    raise RuntimeError("Set FLASK_SECRET_KEY in the Codespaces environment.")
if not CLIENT_ID or not REDIRECT_URI:
    raise RuntimeError("Set UPSTOX_CLIENT_ID and UPSTOX_REDIRECT_URI in the Codespaces environment.")

# Never log callback query strings: they contain the single-use authorization code.
logging.getLogger("werkzeug").disabled = True

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

@app.get("/")
def health():
    return "Upstox OAuth callback server is running."

@app.get("/login")
def start_login():
    state = secrets.token_urlsafe(32)
    session.clear()
    session["upstox_oauth_state"] = state

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }
    authorization_url = (
        "https://api.upstox.com/v2/login/authorization/dialog?"
        + urlencode(params)
    )
    return redirect(authorization_url)

def save_token_securely(token_data):
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".upstox-token-", dir=str(TOKEN_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as token_file:
            json.dump(token_data, token_file)
            token_file.write("\n")
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, TOKEN_FILE)
        os.chmod(TOKEN_FILE, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

@app.get("/callback")
def oauth_callback():
    expected_state = session.pop("upstox_oauth_state", None)
    returned_state = request.args.get("state", "")

    if not expected_state or not returned_state or not secrets.compare_digest(
        returned_state, expected_state
    ):
        abort(400, description="OAuth state check failed. Start again at /login.")

    if request.args.get("error"):
        return "Upstox authorization was not completed. Start again at /login.", 400

    authorization_code = request.args.get("code")
    if not authorization_code:
        return "No authorization code was returned. Start again at /login.", 400

    if not CLIENT_SECRET:
        return (
            "Authorization received, but UPSTOX_CLIENT_SECRET is not configured. "
            "Set it in the Codespaces environment, then start login again."
        ), 500

    # Exchange the single-use code immediately. Do not log the code or token.
    payload = urlencode({
        "code": authorization_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }).encode("utf-8")
    token_request = Request(
        "https://api.upstox.com/v2/login/authorization/token",
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urlopen(token_request, timeout=20) as response:
            token_data = json.loads(response.read().decode("utf-8"))
        if not token_data.get("access_token"):
            return "Upstox did not return an access token. Check server configuration and try a fresh login.", 502
        save_token_securely(token_data)
        app.config["UPSTOX_ACCESS_TOKEN"] = token_data["access_token"]
    except HTTPError as exc:
        # Do not echo response bodies; they may contain sensitive diagnostics.
        logging.error("Upstox token exchange failed with HTTP status %s", exc.code)
        return "Upstox token exchange failed. Check the API credentials and redirect URI, then start a fresh login.", 502
    except (URLError, TimeoutError, ValueError, OSError):
        logging.exception("Upstox token exchange or secure token storage failed.")
        return "Could not complete token exchange or save the token securely. Check the Codespaces server logs.", 502

    return "Upstox authentication and access-token exchange completed successfully. The token was saved locally and was not displayed."

@app.get("/status")
def status():
    if TOKEN_FILE.is_file() or app.config.get("UPSTOX_ACCESS_TOKEN"):
        return "An Upstox access token is saved locally."
    return "No Upstox access token has been saved yet.", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
