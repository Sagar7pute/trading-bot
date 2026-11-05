import os
from flask import Flask, request, abort

app = Flask(__name__)

# Set this in the Codespaces environment before starting the server.
# Use a fresh, unpredictable value for each OAuth authorization attempt.
EXPECTED_STATE = os.environ.get("UPSTOX_OAUTH_STATE")

@app.get("/")
def health():
    return "Upstox OAuth callback server is running."

@app.get("/callback")
def oauth_callback():
    if not EXPECTED_STATE:
        abort(503, description="OAuth state is not configured on the server.")

    returned_state = request.args.get("state", "")
    if not returned_state or returned_state != EXPECTED_STATE:
        abort(400, description="Invalid OAuth state. Authorization was not accepted.")

    authorization_code = request.args.get("code")
    if not authorization_code:
        error = request.args.get("error", "No authorization code was returned.")
        return f"Upstox authorization was not completed: {error}", 400

    # Do not print, log, or display the authorization code.
    # The next step will exchange it securely for an access token.
    app.config["UPSTOX_AUTHORIZATION_CODE"] = authorization_code
    return (
        "Upstox authorization response received. "
        "Keep this Codespace running; you can close this browser tab."
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
