# db_service.py
import os
import json
import hmac
import hashlib
import asyncio
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
import asyncpg
from urllib.parse import urlparse, parse_qs

app = Fastapi = FastAPI()

DB_DSN = os.environ.get("DB_DSN")  # ожидается "postgresql://user:pass@host:port/dbname"
SERVICE_SECRET = os.environ.get("SERVICE_SECRET", "")

if not DB_DSN:
    raise RuntimeError("DB_DSN env required")

# helper: convert common jdbc:postgresql://... to postgresql://...
def normalize_dsn(dsn: str) -> str:
    if dsn.startswith("jdbc:"):
        # very basic conversion for jdbc:postgresql
        # jdbc:postgresql://host:5432/dbname?user=u&password=p
        no_jdbc = dsn[len("jdbc:"):]
        parsed = urlparse(no_jdbc)
        q = parse_qs(parsed.query)
        user = q.get("user", [None])[0]
        password = q.get("password", [None])[0]
        auth = ""
        if user:
            auth = user
            if password:
                auth += ":" + password
            auth += "@"
        host = parsed.hostname or ""
        port = (":" + str(parsed.port)) if parsed.port else ""
        path = parsed.path or ""
        return f"postgresql://{auth}{host}{port}{path}"
    return dsn

DB_DSN = normalize_dsn(DB_DSN)

# postgres table:
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS oauth_tokens (
    user_id TEXT PRIMARY KEY,
    token_json JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
"""

pool: Optional[asyncpg.pool.Pool] = None

async def get_pool():
    global pool
    if pool is None:
        pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=1, max_size=10)
        # ensure table exists
        async with pool.acquire() as conn:
            await conn.execute(CREATE_TABLE_SQL)
    return pool

def verify_hmac(secret: str, body: bytes, signature: str) -> bool:
    if not signature:
        return False
    try:
        sig_bytes = bytes.fromhex(signature)
    except Exception:
        return False
    mac = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return hmac.compare_digest(mac, sig_bytes)

def make_hmac_hex(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    return mac.hex()

class TokenPayload(BaseModel):
    user_id: str
    token_json: dict

@app.on_event("startup")
async def startup():
    await get_pool()

@app.post("/token")
async def store_token(request: Request, x_service_sign: Optional[str] = Header(None)):
    body = await request.body()
    if not verify_hmac(SERVICE_SECRET, body, x_service_sign or ""):
        raise HTTPException(status_code=401, detail="Invalid signature")
    data = await request.json()
    payload = TokenPayload(**data)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO oauth_tokens (user_id, token_json) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET token_json = EXCLUDED.token_json, created_at = now()",
            payload.user_id, json.dumps(payload.token_json)
        )
    return {"ok": True}

@app.get("/token/{user_id}")
async def get_token(user_id: str, x_service_sign: Optional[str] = Header(None)):
    # for GET we'll sign empty body (or use the path) — require header anyway
    # verify signature on string "GET:{user_id}" to avoid needing body
    expected_mac = hmac.new(SERVICE_SECRET.encode(), f"GET:{user_id}".encode(), hashlib.sha256).digest().hex()
    if not x_service_sign or not hmac.compare_digest(bytes.fromhex(x_service_sign), bytes.fromhex(expected_mac)):
        raise HTTPException(status_code=401, detail="Invalid signature")

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT token_json FROM oauth_tokens WHERE user_id = $1", user_id)
        if not row:
            raise HTTPException(status_code=404, detail="Not found")
        return {"token_json": row["token_json"]}

if __name__ == "__main__":
    uvicorn.run("db_service:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
