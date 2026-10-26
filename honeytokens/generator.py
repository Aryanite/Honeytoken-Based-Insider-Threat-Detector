import secrets
import json
import os
from datetime import datetime

TOKEN_FILE = os.path.join(
    os.path.dirname(__file__),
    "tokens.json"
)


def generate_honey_token():
    token_id = secrets.token_hex(16)

    token = {
        "token_id": token_id,
        "token_type": "URL",
        "created_at": datetime.now().isoformat(),
        "status": "ACTIVE",
        "trigger_url": f"/beacon/{token_id}"
    }

    # Load existing tokens
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as file:
                tokens = json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            tokens = []
    else:
        tokens = []

    tokens.append(token)

    with open(TOKEN_FILE, "w", encoding="utf-8") as file:
        json.dump(tokens, file, indent=4)

    return token


if __name__ == "__main__":
    token = generate_honey_token()
    print("CyberGuard Honey Token Created")
    print("------------------------------")
    print("Token ID   :", token["token_id"])
    print("Created At :", token["created_at"])
    print("Status     :", token["status"])
    print("Trigger URL:", token["trigger_url"])