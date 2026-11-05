import logging
import os
import secrets
from urllib.parse import urlencode

from flask import Flask, abort, redirect, request, session

app = Flask(__name__)

# Required environment variables; never commit their values.
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
CLIENT_ID = os.environ.get("UPSTOX_CLIENT_ID")
REDIRECT_URI = os.environ.get("UPSTOX_REDIRECT_URI")

if not app.secret_key:
    raise RuntimeError("Set FLASK_SECRET_KEY in the Codespaces environment.")
if not CLIENT_ID or not REDIRECT_URI:
    raise RuntimeError("Set UPSTOX_CLIENT_ID and UPSTOX_REDIRECT_URI in the Codespaces environment.")

# The callback URL contains a one-time authorization code. Avoid logging request
# URLs so that the code is not written to the Codespaces terminal.
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
    # Generate a new unpredictable state for every authorization attempt.
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

@app.get("/callback")
def oauth_callback():
    expected_state = session.pop("upstox_oauth_state", None)
    returned_state = request.args.get("state", "")

    if not expected_state or not returned_state or not secrets.compare_digest(
        returned_state, expected_state
    ):
        abort(400, description="OAuth state check failed. Start again at /login.")

    if request.args.get("error"):
        # Do not echo arbitrary query-string values into the page.
        return "Upstox authorization was not completed. Start again at /login.", 400

    authorization_code = request.args.get("code")
    if not authorization_code:
        return "No authorization code was returned. Start again at /login.", 400

    # Temporary in-memory storage for this development session only.
    # Never print or display this one-time code.
    app.config["UPSTOX_AUTHORIZATION_CODE"] = authorization_code

    return (
        "Upstox authorization response received successfully. "
        "The one-time code was kept server-side. You can return to Codespaces."
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
