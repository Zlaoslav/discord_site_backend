# entry.py
from workers import Response, WorkerEntrypoint, fetch # pyright: ignore[reportMissingImports]
from submodule import (
    CLIENT_ID,
    REDIRECT_URI,
    FRONTEND_URL,
    ALLOWED_ORIGINS,
    PERMISSION_BITS,
    parse_cookies,
    cors_headers,
    json_response,
    sign_jwt,
    verify_jwt,
)
import secrets
import urllib.parse
import time
import os
import json
import hashlib
import hmac
# import DB helper
from database import SupabaseDB
from urllib.parse import urlparse, parse_qs, urlencode

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # ===== ENV (read from worker env or fallback to os.environ) =====
        try:
            CLIENT_SECRET = getattr(self.env, "DISCORD_CLIENT_SECRET", None)
            BOT_TOKEN = getattr(self.env, "BOT_TOKEN", None)
            JWT_SECRET = getattr(self.env, "JWT_SECRET", None)
            BOT_ID = getattr(self.env, "BOT_ID", None)
            SUPABASE_URL = getattr(self.env, "SUPABASE_URL", None)
            SUPABASE_SERVICE_KEY = getattr(self.env, "SUPABASE_SERVICE_KEY", None)
        except Exception:
            CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
            BOT_TOKEN = os.environ.get("BOT_TOKEN")
            JWT_SECRET = os.environ.get("JWT_SECRET")
            BOT_ID = os.environ.get("BOT_ID")
            SUPABASE_URL = os.environ.get("SUPABASE_URL")
            SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

        if not CLIENT_SECRET or not BOT_TOKEN or not JWT_SECRET:
            return Response("Server misconfigured: missing secrets", status=500)

        # init DB client if Supabase secrets available
        db = None
        use_kv_fallback = False
        if SUPABASE_URL and SUPABASE_SERVICE_KEY:
            try:
                # SupabaseDB implementation may accept env or url/key; pass what you need
                db = SupabaseDB(self.env)
            except Exception as e:
                print("Supabase init failed, will fallback to KV if available:", e)
                db = None
                use_kv_fallback = True
        else:
            # no supabase configured -> we'll use KV fallback
            use_kv_fallback = True

        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path
        origin = request.headers.get("Origin")
        allowed_origin = origin if origin in ALLOWED_ORIGINS else None
        # origin for CORS headers fallback (use FRONTEND_URL if origin not allowed)
        origin_for_cors = allowed_origin or FRONTEND_URL

        # OPTIONS preflight
        if request.method == "OPTIONS":
            headers = cors_headers(origin_for_cors)
            return Response(None, status=204, headers=headers)

        # helper: KV (fallback only)
        async def _kv_put(key, value):
            try:
                kv = getattr(self.env, "OAUTH_TOKENS", None)
                if kv:
                    await kv.put(key, value)
                    return True, "OAUTH_TOKENS"
            except Exception as e:
                print("KV put failed:", e)
            return False, None

        async def _kv_get(key):
            try:
                kv = getattr(self.env, "OAUTH_TOKENS", None)
                if kv:
                    val = await kv.get(key)
                    if val:
                        return val, "OAUTH_TOKENS"
            except Exception as e:
                print("KV get failed:", e)
            return None, None

        async def _db_store_token(user_id: str, token_json_obj: dict) -> bool:
            # low-level store to SUPABASE REST endpoint; ensures expires_at is set
            if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
                return False
            # normalize token and compute expires_at if possible
            token_copy = dict(token_json_obj)
            try:
                expires_in = int(token_copy.get("expires_in", 0) or 0)
            except Exception:
                expires_in = 0
            if expires_in and not token_copy.get("expires_at"):
                token_copy["expires_at"] = int(time.time()) + expires_in
            payload = {"user_id": user_id, "token_json": token_copy}
            body_bytes = json.dumps(payload).encode()
            try:
                sig_hex = hmac.new(SUPABASE_SERVICE_KEY.encode(), body_bytes, hashlib.sha256).hexdigest()
            except Exception as e:
                print("SUPABASE_SERVICE_KEY invalid:", e)
                return False
            try:
                resp = await fetch(
                    f"{SUPABASE_URL.rstrip('/')}/token",
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Service-Sign": sig_hex},
                    body=body_bytes,
                )
                try:
                    await resp.text()
                except Exception:
                    pass
                if resp.status == 200:
                    return True
                print("Supabase store returned status", resp.status)
                return False
            except Exception as e:
                print("db store fetch failed:", e)
                return False

        async def _db_get_token(user_id: str):
            # low-level get from SUPABASE REST endpoint; returns token_json dict or None
            if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
                return None
            msg = f"GET:{user_id}".encode()
            try:
                sig_hex = hmac.new(SUPABASE_SERVICE_KEY.encode(), msg, hashlib.sha256).hexdigest()
            except Exception as e:
                print("SUPABASE_SERVICE_KEY invalid:", e)
                return None
            try:
                resp = await fetch(
                    f"{SUPABASE_URL.rstrip('/')}/token/{urllib.parse.quote(user_id)}",
                    method="GET",
                    headers={"X-Service-Sign": sig_hex},
                )
            except Exception as e:
                print("db get fetch failed:", e)
                return None
            # if non-200, read body then return None
            if resp.status != 200:
                try:
                    txt = await resp.text()
                    print("Supabase get non-200:", resp.status, txt)
                except Exception:
                    pass
                return None
            try:
                j = await resp.json()
            except Exception as e:
                print("Failed to parse DB response JSON:", e)
                try:
                    await resp.text()
                except Exception:
                    pass
                return None
            # normalize: possible shapes:
            # 1) {"token_json": {...}}
            # 2) {"data": [{ "token_json": {...} }]} or {"data": {...}}
            # 3) direct token object
            if isinstance(j, dict):
                if "token_json" in j and isinstance(j["token_json"], (dict, str)):
                    return j["token_json"]
                if "data" in j:
                    data = j["data"]
                    if isinstance(data, list) and data:
                        first = data[0]
                        if isinstance(first, dict) and "token_json" in first:
                            return first["token_json"]
                        return first
                    if isinstance(data, dict):
                        if "token_json" in data:
                            return data["token_json"]
                        return data
            # fallback: return whatever we got
            return j

        async def _refresh_user_token(user_id: str, stored_token: dict):
            # try to refresh using refresh_token; returns new token_json dict or None
            refresh = stored_token.get("refresh_token")
            if not refresh:
                return None
            body = urllib.parse.urlencode({
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": refresh,
            }).encode()
            try:
                resp = await fetch(
                    "https://discord.com/api/oauth2/token",
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=body,
                )
            except Exception as e:
                print("Refresh token request failed:", e)
                return None
            if not resp.ok:
                try:
                    txt = await resp.text()
                except Exception:
                    txt = ""
                print("Refresh token failed:", resp.status, txt)
                try:
                    await resp.body.cancel()
                except Exception:
                    pass
                return None
            try:
                new_tok = await resp.json()
            except Exception as e:
                print("Failed to parse refresh response:", e)
                return None
            # compute expires_at
            try:
                expires_in = int(new_tok.get("expires_in", 0) or 0)
            except Exception:
                expires_in = 0
            if expires_in and not new_tok.get("expires_at"):
                new_tok["expires_at"] = int(time.time()) + expires_in
            # keep refresh_token if provider didn't return new one
            if not new_tok.get("refresh_token") and stored_token.get("refresh_token"):
                new_tok["refresh_token"] = stored_token.get("refresh_token")
            # persist updated token
            try:
                ok, where = await store_token(user_id, new_tok)
                if ok:
                    return new_tok
            except Exception as e:
                print("Failed to persist refreshed token:", e)
            return new_tok

        async def store_token(user_id, token_json):
            # prefer wrapper 'db' if available
            if db:
                try:
                    ok = await db.save_token(user_id, token_json)
                    if ok:
                        return True, "supabase_wrapper"
                except Exception as e:
                    print("Supabase wrapper save_token failed:", e)
            # try low-level REST store
            try:
                ok = await _db_store_token(user_id, token_json)
                if ok:
                    return True, "supabase_rest"
            except Exception as e:
                print("Low-level db store failed:", e)
            # KV fallback
            try:
                kv_ok, kv_name = await _kv_put(f"user:{user_id}", json.dumps(token_json))
                if kv_ok:
                    return True, kv_name
            except Exception as e:
                print("KV fallback put failed:", e)
            return False, None

        async def get_stored_token(user_id):
            # prefer wrapper
            stored = None
            if db:
                try:
                    rec = await db.get_token(user_id)
                    if rec:
                        stored = rec
                except Exception as e:
                    print("Supabase wrapper get_token failed:", e)
                    stored = None
            # low-level REST
            if stored is None:
                try:
                    low = await _db_get_token(user_id)
                    if low:
                        stored = low
                except Exception as e:
                    print("Low-level db get failed:", e)
                    stored = None
            # KV fallback
            if stored is None:
                try:
                    kv_val, kv_name = await _kv_get(f"user:{user_id}")
                    if kv_val:
                        try:
                            stored = json.loads(kv_val)
                        except Exception:
                            stored = kv_val
                except Exception as e:
                    print("KV fallback read failed:", e)
                    stored = None
            if not stored:
                return None
            # Normalize: if stored is dict-like or JSON string already loaded
            if isinstance(stored, str):
                try:
                    token_json = json.loads(stored)
                except Exception:
                    return None
            elif isinstance(stored, dict):
                # In some DB shapes token is under "token_json"
                if "token_json" in stored and isinstance(stored["token_json"], (dict, str)):
                    token_json = stored["token_json"] if isinstance(stored["token_json"], dict) else json.loads(stored["token_json"])
                else:
                    token_json = stored
            else:
                # unknown shape
                return None
            # check expiry and refresh if needed
            try:
                exp = int(token_json.get("expires_at") or 0)
            except Exception:
                exp = 0
            now_ts = int(time.time())
            if exp and exp <= now_ts:
                # expired -> try refresh
                refreshed = await _refresh_user_token(user_id, token_json)
                if refreshed:
                    return refreshed
                # if refresh failed, return existing token (caller will likely reject)
                return token_json
            return token_json

        try:
            # ===== root =====
            if request.method == "GET" and path == "/":
                headers = cors_headers(origin_for_cors)
                headers["Content-Type"] = "application/json"
                return Response(json.dumps({"ok": True, "message": "Worker running"}), status=200, headers=headers)

            # ===== /login =====
            if path == "/login":
                state = secrets.token_hex(16)
                params = {
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": "identify email guilds",
                    "state": state,
                }
                authorize_url = "https://discord.com/api/oauth2/authorize?" + urllib.parse.urlencode(params)
                headers = {
                    "Location": authorize_url,
                    "Set-Cookie": f"oauth_state={state}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=300"
                }
                headers.update(cors_headers(origin_for_cors))
                return Response(None, status=302, headers=headers)

            # ===== /callback =====
            if path == "/callback":
                        parsed = urllib.parse.urlparse(request.url)
                        qs = urllib.parse.parse_qs(parsed.query)
                        code = qs.get("code", [None])[0]
                        state = qs.get("state", [None])[0]
                        cookies = parse_cookies(request.headers.get("Cookie"))
                        if not code or cookies.get("oauth_state") != state:
                            return Response("Invalid state or code", status=400)

                        form_data = urllib.parse.urlencode({
                            "client_id": CLIENT_ID,
                            "client_secret": CLIENT_SECRET,
                            "grant_type": "authorization_code",
                            "code": code,
                            "redirect_uri": REDIRECT_URI,
                        }).encode()

                        try:
                            token_resp = await fetch(
                                "https://discord.com/api/oauth2/token",
                                method="POST",
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                                body=form_data
                            )
                        except Exception as e:
                            print("Token exchange fetch exception:", e)
                            body, status, headers = json_response({"error": "Token exchange request failed"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        if not token_resp.ok:
                            try:
                                t = await token_resp.text()
                            except Exception:
                                t = "<failed to read body>"
                            print("Token exchange failed:", t)
                            try:
                                await token_resp.body.cancel()
                            except Exception:
                                pass
                            body, status, headers = json_response({"error": "Token exchange failed", "details": t}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        try:
                            token_json = await token_resp.json()
                        except Exception as e:
                            print("Failed to parse token response JSON:", e)
                            body, status, headers = json_response({"error": "Invalid token response"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        try:
                            user_resp = await fetch(
                                "https://discord.com/api/users/@me",
                                headers={"Authorization": f"Bearer {token_json.get('access_token')}"}
                            )
                        except Exception as e:
                            print("User fetch request failed:", e)
                            body, status, headers = json_response({"error": "Failed to fetch user"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        if not user_resp.ok:
                            try:
                                t = await user_resp.text()
                            except Exception:
                                t = "<failed to read user body>"
                            print("Failed to fetch user:", t)
                            try:
                                await user_resp.body.cancel()
                            except Exception:
                                pass
                            body, status, headers = json_response({"error": "User fetch failed"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        try:
                            user = await user_resp.json()
                        except Exception as e:
                            print("Failed to parse user JSON:", e)
                            body, status, headers = json_response({"error": "Invalid user response"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        # store token safely via unified helper (prefers supabase wrapper -> rest -> kv)
                        saved_ok = False
                        saved_name = None
                        try:
                            user_id = user.get("id")
                            if user_id:
                                res = await store_token(user_id, token_json)
                                if isinstance(res, tuple):
                                    saved_ok = bool(res[0])
                                    saved_name = res[1] if len(res) > 1 else None
                                else:
                                    saved_ok = bool(res)
                        except Exception as e:
                            print("DB store exception:", e)
                            saved_ok = False

                        if not saved_ok:
                            try:
                                kv_ok, kv_name = await _kv_put(f"user:{user['id']}", json.dumps(token_json))
                                if kv_ok:
                                    saved_ok = True
                                    saved_name = kv_name
                                    print("Token saved in KV binding (fallback):", kv_name)
                            except Exception as e:
                                print("KV fallback put failed:", e)

                        debug_cookie = "oauth_saved=yes; Path=/; Max-Age=60; SameSite=None; Secure" if saved_ok else "oauth_saved=no; Path=/; Max-Age=60; SameSite=None; Secure"
                        if not saved_ok:
                            print("Token storage failed for DB and KV")

                        now = int(time.time())
                        jwt = sign_jwt({
                            "sub": user["id"],
                            "username": user.get("username"),
                            "discriminator": user.get("discriminator"),
                            "avatar": user.get("avatar"),
                            "iat": now,
                            "exp": now + 86400,
                        }, JWT_SECRET)

                        redirect_to = FRONTEND_URL + "#token=" + urllib.parse.quote(jwt, safe='')
                        session_cookie = f"session={jwt}; Domain=pollpi.slavi.workers.dev; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=86400"

                        headers = {
                            "Location": redirect_to,
                            "Set-Cookie": session_cookie,
                            "X-OAuth-Saved": debug_cookie
                        }
                        if allowed_origin:
                            headers.update(cors_headers(allowed_origin))

                        return Response(None, status=302, headers=headers)
            
            # ===== /me =====
            if path == "/me":
                auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
                payload = None
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                    payload = verify_jwt(token, JWT_SECRET)
                if not payload:
                    cookies = parse_cookies(request.headers.get("Cookie"))
                    token = cookies.get("session")
                    if token:
                        payload = verify_jwt(token, JWT_SECRET)
                if not payload:
                    body, status, headers = json_response({"logged": False}, 200, origin_for_cors)
                    return Response(body, status=status, headers=headers)
                body, status, headers = json_response({"logged": True, "user": payload}, 200, origin_for_cors)
                return Response(body, status=status, headers=headers)

            # ===== /guilds =====
            if path == "/guilds":
                        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
                        payload = None
                        if auth_header and auth_header.startswith("Bearer "):
                            token = auth_header[7:].strip()
                            payload = verify_jwt(token, JWT_SECRET)
                        if not payload:
                            cookies = parse_cookies(request.headers.get("Cookie"))
                            token = cookies.get("session")
                            if token:
                                payload = verify_jwt(token, JWT_SECRET)
                        if not payload:
                            body, status, headers = json_response({"error": "Not authenticated"}, 401, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        user_id = payload["sub"]

                        token_json = await get_stored_token(user_id)
                        if not token_json:
                            body, status, headers = json_response({"error": "No oauth tokens stored"}, 403, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        user_access_token = token_json.get("access_token")
                        if not user_access_token:
                            body, status, headers = json_response({"error": "Stored token missing access_token"}, 403, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        # 1️⃣ Гильдии пользователя
                        user_resp = await fetch(
                            "https://discord.com/api/users/@me/guilds",
                            headers={"Authorization": f"Bearer {user_access_token}"}
                        )
                        if not user_resp.ok:
                            t = await user_resp.text()
                            body, status, headers = json_response({"error": "Failed to fetch user guilds", "details": t}, 500, allowed_origin)
                            return Response(body, status=status, headers=headers)
                        user_guilds = await user_resp.json()

                        # 2️⃣ Гильдии бота
                        bot_resp = await fetch(
                            "https://discord.com/api/users/@me/guilds",
                            headers={"Authorization": f"Bot {BOT_TOKEN}"}
                        )

                        bot_guild_ids = set()
                        if bot_resp.ok:
                            bot_guilds = await bot_resp.json()
                            bot_guild_ids = {g["id"] for g in bot_guilds}
                        else:
                            await bot_resp.body.cancel()

                        admin_bit = PERMISSION_BITS["ADMINISTRATOR"]
                        out = []

                        for g in user_guilds:
                            perms = int(g.get("permissions", 0))
                            if (perms & admin_bit) == 0:
                                continue

                            g_id = g.get("id")
                            icon = g.get("icon")

                            icon_url = None
                            if icon:
                                icon_url = f"https://cdn.discordapp.com/icons/{g_id}/{icon}.png"

                            member_count = None

                            # Получаем approximate_member_count только если бот в гильдии
                            if g_id in bot_guild_ids:
                                guild_resp = await fetch(
                                    f"https://discord.com/api/guilds/{g_id}?with_counts=true",
                                    headers={"Authorization": f"Bot {BOT_TOKEN}"}
                                )

                                if guild_resp.ok:
                                    guild_data = await guild_resp.json()
                                    member_count = guild_data.get("approximate_member_count")
                                else:
                                    await guild_resp.body.cancel()

                            out.append({
                                "id": g_id,
                                "name": g.get("name"),
                                "isAdmin": True,
                                "botPresent": g_id in bot_guild_ids,
                                "icon": icon,
                                "iconUrl": icon_url,
                                "memberCount": member_count
                            })

                        body, status, headers = json_response({"guilds": out}, 200, allowed_origin)
                        return Response(body, status=status, headers=headers)
      

            # ===== /action =====
            if path == "/action":
                if request.method != "POST":
                    body, status, headers = json_response({"error": "Method not allowed"}, 405, origin_for_cors)
                    return Response(body, status=status, headers=headers)

                auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
                payload = None
                if auth_header and auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                    payload = verify_jwt(token, JWT_SECRET)
                if not payload:
                    cookies = parse_cookies(request.headers.get("Cookie"))
                    token = cookies.get("session")
                    if token:
                        payload = verify_jwt(token, JWT_SECRET)
                if not payload:
                    body, status, headers = json_response({"error": "Not authenticated"}, 401, origin_for_cors)
                    return Response(body, status=status, headers=headers)

                try:
                    body_json = await request.json()
                except Exception:
                    body, status, headers = json_response({"error": "Invalid JSON"}, 400, origin_for_cors)
                    return Response(body, status=status, headers=headers)
                guild_id = body_json.get("guildId")
                required = body_json.get("required")
                if not guild_id or not required or required not in PERMISSION_BITS:
                    body, status, headers = json_response({"error": "Invalid request"}, 400, origin_for_cors)
                    return Response(body, status=status, headers=headers)

                member_resp = await fetch(
                    f"https://discord.com/api/guilds/{guild_id}/members/{payload['sub']}",
                    headers={"Authorization": f"Bot {BOT_TOKEN}"}
                )
                if not member_resp.ok:
                    body, status, headers = json_response({"error": "User not member or bot missing perms"}, 403, origin_for_cors)
                    return Response(body, status=status, headers=headers)
                member = await member_resp.json()

                roles_resp = await fetch(
                    f"https://discord.com/api/guilds/{guild_id}/roles",
                    headers={"Authorization": f"Bot {BOT_TOKEN}"}
                )
                if not roles_resp.ok:
                    body, status, headers = json_response({"error": "Failed to fetch roles"}, 500, origin_for_cors)
                    return Response(body, status=status, headers=headers)
                roles = await roles_resp.json()

                perms = 0
                for role_id in member.get("roles", []):
                    r = next((x for x in roles if x.get("id") == role_id), None)
                    if r:
                        perms |= int(r.get("permissions", 0))

                admin_bit = PERMISSION_BITS["ADMINISTRATOR"]
                required_bit = PERMISSION_BITS[required]
                if (perms & admin_bit) == 0 and (perms & required_bit) == 0:
                    body, status, headers = json_response({"error": "Forbidden"}, 403, origin_for_cors)
                    return Response(body, status=status, headers=headers)

                body, status, headers = json_response({"ok": True}, 200, origin_for_cors)
                return Response(body, status=status, headers=headers)

            # logout and other routes...
            if path == "/logout":
                headers = {"Location": FRONTEND_URL}
                headers["Set-Cookie"] = "session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
                headers.update(cors_headers(origin_for_cors))
                return Response(None, status=302, headers=headers)

            # fallback not found
            body, status, headers = json_response({"error": "Not Found"}, 404, origin_for_cors)
            return Response(body, status=status, headers=headers)

        except Exception as e:
            print("Worker crash:", getattr(e, "stack", e))
            body, status, headers = json_response({"error": "Internal server error"}, 500, origin_for_cors)
            return Response(body, status=status, headers=headers)
