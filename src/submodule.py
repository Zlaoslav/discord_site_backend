# submodule.py
import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.parse

CLIENT_ID = "1409084528588488727"
REDIRECT_URI = "https://pollpi.slavi.workers.dev/callback"
FRONTEND_URL = "https://zlaoslav.github.io/discord_site_frontend/"

ALLOWED_ORIGINS = [
    "https://zlaoslav.github.io",
    "https://pollpi.slavi.workers.dev",
    "http://localhost:5173",
]

PERMISSION_BITS = {
    "ADMINISTRATOR": 0x00000008,
    "MANAGE_GUILD": 0x00000020,
    "MANAGE_ROLES": 0x10000000,
}


def parse_cookies(header: str | None) -> dict:
    if not header:
        return {}
    out = {}
    for part in header.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
        else:
            out[part.strip()] = ""
    return out


def cors_headers(origin: str) -> dict:
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    }


def json_response(body_obj, status=200, origin: str | None = None):
    body = json.dumps(body_obj)
    headers = {"Content-Type": "application/json"}
    if origin:
        headers.update(cors_headers(origin))
    # Response is created by caller (import Response from workers)
    return body, status, headers


def base64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def base64url_encode_text(s: str) -> str:
    return base64url_encode(s.encode())


def base64url_decode_text(s: str) -> str:
    pad = (-len(s)) % 4
    s_padded = s + ("=" * pad)
    return base64.urlsafe_b64decode(s_padded.encode()).decode()


def hmac_sha256(key: str, msg: str) -> bytes:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest()


def sign_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b = base64url_encode_text(json.dumps(header, separators=(",", ":")))
    body_b = base64url_encode_text(json.dumps(payload, separators=(",", ":")))
    data = f"{header_b}.{body_b}"
    sig = hmac_sha256(secret, data)
    sig_b = base64url_encode(sig)
    return f"{data}.{sig_b}"


def verify_jwt(token: str | None, secret: str) -> dict | None:
    try:
        if not token:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        data = f"{h}.{p}"
        expected_sig = base64url_encode(hmac_sha256(secret, data))
        if not hmac.compare_digest(expected_sig, s):
            return None
        payload_json = base64url_decode_text(p)
        payload = json.loads(payload_json)
        if "exp" in payload and int(time.time()) > int(payload["exp"]):
            return None
        return payload
    except Exception:
        return None
