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

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # ===== ENV =====
        try:
            CLIENT_SECRET = self.env.DISCORD_CLIENT_SECRET
            BOT_TOKEN = self.env.BOT_TOKEN
            JWT_SECRET = self.env.JWT_SECRET
            BOT_ID = self.env.BOT_ID
        except Exception:
            CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
            BOT_TOKEN = os.environ.get("BOT_TOKEN")
            JWT_SECRET = os.environ.get("JWT_SECRET")
            BOT_ID = os.environ.get("BOT_ID")

        if not CLIENT_SECRET or not BOT_TOKEN or not JWT_SECRET:
            return Response("Server misconfigured: missing secrets", status=500)

        origin = request.headers.get("Origin")
        allowed_origin = origin if origin in ALLOWED_ORIGINS else None

        # OPTIONS preflight
        if request.method == "OPTIONS":
            if not allowed_origin:
                return Response(None, status=204)
            return Response(None, status=204, headers=cors_headers(allowed_origin))

        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path

        # helper: list of KV binding names to try
        def _kv_names():
            # порядок: предпочтительный биндинг сначала
            return ["OAUTH_TOKENS", "OAUTH_KV", "TOKEN_STORE"]

        async def _kv_put(key, value):
            # try put into available kv bindings
            for name in _kv_names():
                try:
                    kv = getattr(self.env, name, None)
                except Exception:
                    kv = None
                if kv is not None:
                    try:
                        await kv.put(key, value)
                        # verify immediately (some runtimes accept put but may fail)
                        got = await kv.get(key)
                        if got:
                            return True, name
                    except Exception as e:
                        print(f"KV put failed for {name}: {e}")
                        continue
            return False, None

        async def _kv_get(key):
            for name in _kv_names():
                try:
                    kv = getattr(self.env, name, None)
                except Exception:
                    kv = None
                if kv is not None:
                    try:
                        got = await kv.get(key)
                        if got:
                            return got, name
                    except Exception as e:
                        print(f"KV get failed for {name}: {e}")
                        continue
            return None, None

        try:
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

                headers = {"Location": authorize_url}
                headers["Set-Cookie"] = f"oauth_state={state}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=300"
                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))
                return Response(None, status=302, headers=headers)

            # ===== /callback =====
            if path == "/callback":
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
                })

                try:
                    token_resp = await fetch(
                        "https://discord.com/api/oauth2/token",
                        method="POST",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=form_data.encode()
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
                    body, status, headers = json_response({"error": "Token exchange failed", "details": t}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                try:
                    token_json = await token_resp.json()
                except Exception as e:
                    print("Failed to parse token response JSON:", e)
                    body, status, headers = json_response({"error": "Invalid token response"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                # fetch user
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
                    body, status, headers = json_response({"error": "User fetch failed"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                try:
                    user = await user_resp.json()
                except Exception as e:
                    print("Failed to parse user JSON:", e)
                    body, status, headers = json_response({"error": "Invalid user response"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                # --- try to store tokens in KV under several possible names ---
                saved_ok, saved_name = await _kv_put(f"user:{user['id']}", json.dumps(token_json))
                if not saved_ok:
                    # set a non-HttpOnly cookie for debug (short lived) so frontend can see failure
                    debug_cookie = "oauth_saved=no; Path=/; Max-Age=60; SameSite=None; Secure"
                    print("KV store failed for all configured bindings")
                else:
                    debug_cookie = "oauth_saved=yes; Path=/; Max-Age=60; SameSite=None; Secure"
                    print("Token saved in KV binding:", saved_name)

                # create jwt
                now = int(time.time())
                jwt = sign_jwt({
                    "sub": user["id"],
                    "username": user.get("username"),
                    "discriminator": user.get("discriminator"),
                    "avatar": user.get("avatar"),
                    "iat": now,
                    "exp": now + 86400,
                }, JWT_SECRET)

                # respond: set session cookie + debug cookie (non-HttpOnly) + redirect fragment for backward compat
                redirect_to = FRONTEND_URL + "#token=" + urllib.parse.quote(jwt, safe='')
                # session cookie HttpOnly
                session_cookie = f"session={jwt}; Domain=pollpi.slavi.workers.dev; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=86400"
                headers = {
                    "Location": redirect_to,
                    "Set-Cookie": session_cookie,
                    # debug cookie (not HttpOnly) so frontend JS can read oauth_saved
                    "Set-OAuth-Saved": debug_cookie  # we'll also push this as a separate header because some runtimes clobber multiple Set-Cookie keys in dict
                }
                # Note: some runtimes don't allow two Set-Cookie keys in dict. To be robust, we'll also return oauth_saved in body if CORS allowed (for debug).
                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))

                # Cloudflare Python runtime sometimes doesn't accept two Set-Cookie via dict.
                # So return response with both headers; if runtime discards second Set-Cookie header,
                # frontend can still read 'oauth_saved' from response body (below) because we return JSON on 200,
                # but here we must redirect, so frontend should check debug Cookie or query backend /me for success.
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
                    body, status, headers = json_response({"logged": False}, 200, allowed_origin)
                    return Response(body, status=status, headers=headers)
                body, status, headers = json_response({"logged": True, "user": payload}, 200, allowed_origin)
                return Response(body, status=status, headers=headers)

            # ===== /guilds =====
            if path == "/guilds":
                # authenticate same as /me
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

                # try read KV (multiple bindings)
                stored, used_kv = await _kv_get(f"user:{user_id}")
                if not stored:
                    # helpful response with hint, not opaque 403
                    body, status, headers = json_response(
                        {"error": "No oauth tokens stored", "reason": "no_oauth_tokens", "hint": "Re-authorize or ensure worker KV binding OAUTH_TOKENS exists"},
                        403,
                        allowed_origin
                    )
                    return Response(body, status=status, headers=headers)

                try:
                    token_json = json.loads(stored)
                except Exception as e:
                    print("Failed to parse stored token JSON:", e)
                    body, status, headers = json_response({"error": "Invalid stored token"}, 500, allowed_origin)
                    return Response(body, status=status, headers=headers)

                user_access_token = token_json.get("access_token")
                if not user_access_token:
                    body, status, headers = json_response({"error": "Stored token missing access_token"}, 403, allowed_origin)
                    return Response(body, status=status, headers=headers)

                # get user's guilds using user's access_token
                guilds_resp = await fetch("https://discord.com/api/users/@me/guilds", headers={"Authorization": f"Bearer {user_access_token}"})
                if not guilds_resp.ok:
                    # possibly expired token -> hint to reauthorize
                    try:
                        t = await guilds_resp.text()
                    except Exception:
                        t = ""
                    print("Failed to fetch user guilds:", t)
                    body, status, headers = json_response({"error": "Failed to fetch user guilds", "details": t, "hint": "token_maybe_expired"}, 500, allowed_origin)
                    return Response(body, status=status, headers=headers)
                guilds = await guilds_resp.json()

                out = []
                admin_bit = PERMISSION_BITS["ADMINISTRATOR"]
                for g in guilds:
                    g_id = g.get("id")
                    perms = int(g.get("permissions", 0))
                    is_admin = (perms & admin_bit) != 0
                    bot_present = False
                    if BOT_ID:
                        bot_check = await fetch(f"https://discord.com/api/guilds/{g_id}/members/{BOT_ID}", headers={"Authorization": f"Bot {BOT_TOKEN}"})
                        bot_present = bot_check.ok
                    out.append({
                        "id": g_id,
                        "name": g.get("name"),
                        "permissions": perms,
                        "isAdmin": is_admin,
                        "botPresent": bot_present
                    })

                body, status, headers = json_response({"guilds": out}, 200, allowed_origin)
                return Response(body, status=status, headers=headers)

            # other endpoints unchanged...
            if path == "/action":
                if request.method != "POST":
                    body, status, headers = json_response({"error": "Method not allowed"}, 405, allowed_origin)
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
                    body, status, headers = json_response({"error": "Not authenticated"}, 401, allowed_origin)
                    return Response(body, status=status, headers=headers)

                try:
                    body_json = await request.json()
                except Exception:
                    body, status, headers = json_response({"error": "Invalid JSON"}, 400, allowed_origin)
                    return Response(body, status=status, headers=headers)
                guild_id = body_json.get("guildId")
                required = body_json.get("required")
                if not guild_id or not required or required not in PERMISSION_BITS:
                    body, status, headers = json_response({"error": "Invalid request"}, 400, allowed_origin)
                    return Response(body, status=status, headers=headers)

                member_resp = await fetch(f"https://discord.com/api/guilds/{guild_id}/members/{payload['sub']}", headers={"Authorization": f"Bot {BOT_TOKEN}"})
                if not member_resp.ok:
                    body, status, headers = json_response({"error": "User not member or bot missing perms"}, 403, allowed_origin)
                    return Response(body, status=status, headers=headers)
                member = await member_resp.json()

                roles_resp = await fetch(f"https://discord.com/api/guilds/{guild_id}/roles", headers={"Authorization": f"Bot {BOT_TOKEN}"})
                if not roles_resp.ok:
                    body, status, headers = json_response({"error": "Failed to fetch roles"}, 500, allowed_origin)
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
                    body, status, headers = json_response({"error": "Forbidden"}, 403, allowed_origin)
                    return Response(body, status=status, headers=headers)

                body, status, headers = json_response({"ok": True}, 200, allowed_origin)
                return Response(body, status=status, headers=headers)

            # logout and other routes...
            if path == "/logout":
                headers = {"Location": FRONTEND_URL}
                headers["Set-Cookie"] = "session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))
                return Response(None, status=302, headers=headers)

            # fallback not found
            return Response("Not Found", status=404)

        except Exception as e:
            print("Worker crash:", getattr(e, "stack", e))
            body, status, headers = json_response({"error": "Internal server error"}, 500, allowed_origin)
            return Response(body, status=status, headers=headers)
