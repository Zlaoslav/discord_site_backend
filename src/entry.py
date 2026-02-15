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

        CLIENT_SECRET = self.env.DISCORD_CLIENT_SECRET
        BOT_TOKEN = self.env.BOT_TOKEN
        JWT_SECRET = self.env.JWT_SECRET
        BOT_ID = self.env, "BOT_ID"
        SUPABASE_URL = self.env, "SUPABASE_URL"
        SUPABASE_SERVICE_KEY = self.env, "SUPABASE_SERVICE_KEY"

        if not CLIENT_SECRET or not BOT_TOKEN or not JWT_SECRET:
            return Response("Server misconfigured: missing secrets", status=500)

        # init DB client if Supabase secrets available
        db = None
        use_kv_fallback = False
        if SUPABASE_URL and SUPABASE_SERVICE_KEY:
            try:
                db = SupabaseDB(self.env)
            except Exception as e:
                print("Supabase init failed, will fallback to KV if available:", e)
                db = None
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
            if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
                return False
            body_bytes = json.dumps({"user_id": user_id, "token_json": token_json_obj}).encode()
            sig_hex = hmac.new(SUPABASE_SERVICE_KEY.encode(), body_bytes, hashlib.sha256).hexdigest()
            try:
                resp = await fetch(
                    f"{SUPABASE_URL.rstrip('/')}/token",
                    method="POST",
                    headers={"Content-Type": "application/json", "X-Service-Sign": sig_hex},
                    body=body_bytes,
                )
                # обязательно читать тело или отменять
                await resp.text()
                return resp.status == 200
            except Exception as e:
                print("db store fetch failed:", e)
                return False

        # === helper: DB get ===
        async def _db_get_token(user_id: str):
            if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
                return None
            msg = f"GET:{user_id}".encode()
            sig_hex = hmac.new(SUPABASE_SERVICE_KEY.encode(), msg, hashlib.sha256).hexdigest()
            try:
                resp = await fetch(
                    f"{SUPABASE_URL.rstrip('/')}/token/{urllib.parse.quote(user_id)}",
                    method="GET",
                    headers={"X-Service-Sign": sig_hex},
                )
                if resp.status == 200:
                    j = await resp.json()
                    return j.get("token_json")
                else:
                    await resp.text()  # читаем тело, чтобы не было stalled response
                    return None
            except Exception as e:
                print("db get fetch failed:", e)
                return None
        # helper: store token (tries Supabase, then KV)
        async def store_token(user_id, token_json):
            if db:
                ok = await db.save_token(user_id, token_json)
                if ok:
                    return True, "supabase"
            # fallback to KV
            kv_ok, kv_name = await _kv_put(f"user:{user_id}", json.dumps(token_json))
            if kv_ok:
                return True, kv_name
            return False, None

        # helper: get token (Supabase then KV)
        async def get_stored_token(user_id):
            if db:
                try:
                    rec = await db.get_token(user_id)
                    if rec:
                        # make shape compatible with token_json used earlier
                        return {
                            "access_token": rec.get("access_token"),
                            "refresh_token": rec.get("refresh_token")
                        }
                except Exception as e:
                    print("Supabase get_token failed:", e)
            # KV fallback
            kv_val, kv_name = await _kv_get(f"user:{user_id}")
            if kv_val:
                return json.loads(kv_val)
            return None

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
                            await token_resp.body.cancel()
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
                            await user_resp.body.cancel()
                            body, status, headers = json_response({"error": "User fetch failed"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        try:
                            user = await user_resp.json()
                        except Exception as e:
                            print("Failed to parse user JSON:", e)
                            body, status, headers = json_response({"error": "Invalid user response"}, 502, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        # store token safely
                        saved_ok = False
                        saved_name = None
                        try:
                            user_id = user.get("id")
                            if user_id:
                                saved_ok = await _db_store_token(user_id, token_json)
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

                        stored = None
                        try:
                            stored = await _db_get_token(user_id)
                        except Exception as e:
                            print("DB read failed:", e)
                            stored = None

                        if not stored:
                            try:
                                kv_stored, kv_name = await _kv_get(f"user:{user_id}")
                                if kv_stored:
                                    stored = kv_stored
                            except Exception as e:
                                print("KV fallback read failed:", e)

                        if not stored:
                            body, status, headers = json_response(
                                {"error": "No oauth tokens stored", "reason": "no_oauth_tokens", "hint": "Re-authorize or ensure DB service accessible"},
                                403,
                                allowed_origin
                            )
                            return Response(body, status=status, headers=headers)

                        try:
                            if isinstance(stored, str):
                                token_json = json.loads(stored)
                            else:
                                token_json = stored
                        except Exception as e:
                            print("Failed to parse stored token JSON:", e)
                            body, status, headers = json_response({"error": "Invalid stored token"}, 500, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        user_access_token = token_json.get("access_token")
                        if not user_access_token:
                            body, status, headers = json_response({"error": "Stored token missing access_token"}, 403, allowed_origin)
                            return Response(body, status=status, headers=headers)

                        guilds_resp = await fetch(
                            "https://discord.com/api/users/@me/guilds",
                            headers={"Authorization": f"Bearer {user_access_token}"}
                        )
                        if not guilds_resp.ok:
                            try:
                                t = await guilds_resp.text()
                            except Exception:
                                t = ""
                            print("Failed to fetch user guilds:", t)
                            await guilds_resp.body.cancel()
                            body, status, headers = json_response({"error": "Failed to fetch user guilds", "details": t, "hint": "token_maybe_expired"}, 500, allowed_origin)
                            return Response(body, status=status, headers=headers)
                        guilds = await guilds_resp.json()

                        out = []
                        admin_bit = PERMISSION_BITS["ADMINISTRATOR"]

                        import asyncio
                        bot_tasks = []
                        for g in guilds:
                            g_id = g.get("id")
                            if CLIENT_ID:
                                url = f"https://discord.com/api/guilds/{g_id}/members/{CLIENT_ID}"
                                bot_tasks.append(fetch(url, headers={"Authorization": f"Bot {BOT_TOKEN}"}))
                            else:
                                bot_tasks.append(None)

                        bot_responses = await asyncio.gather(*[t for t in bot_tasks if t is not None], return_exceptions=True)
                        bot_index = 0

                        for g in guilds:
                            g_id = g.get("id")
                            perms = int(g.get("permissions", 0))
                            is_admin = (perms & admin_bit) != 0
                            bot_present = False

                            if CLIENT_ID:
                                resp = bot_responses[bot_index]
                                bot_index += 1
                                try:
                                    if resp.ok:
                                        await resp.json()
                                        bot_present = True
                                    else:
                                        await resp.body.cancel()
                                except Exception:
                                    bot_present = False

                            out.append({
                                "id": g_id,
                                "name": g.get("name"),
                                "permissions": perms,
                                "isAdmin": is_admin,
                                "botPresent": bot_present
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
