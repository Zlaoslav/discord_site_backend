# entry.py
from workers import Response, WorkerEntrypoint, fetch  # pyright: ignore[reportMissingImports] # runtime-provided
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

# NOTE: this class must be the WorkerEntrypoint subclass your runtime expects

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # env: try to read from self.env (common pattern), fallback to empty dict
        CLIENT_SECRET = self.env.DISCORD_CLIENT_SECRET
        BOT_TOKEN = self.env.BOT_TOKEN
        JWT_SECRET = self.env.JWT_SECRET



        if not CLIENT_SECRET or not BOT_TOKEN or not JWT_SECRET:
            return Response("Server misconfigured: missing secrets", status=500)

        # origin + CORS
        origin = request.headers.get("Origin")
        allowed_origin = origin if origin in ALLOWED_ORIGINS else None

        # OPTIONS preflight
        if request.method == "OPTIONS":
            if not allowed_origin:
                return Response(None, status=204)
            return Response(None, status=204, headers=cors_headers(allowed_origin))

        # path parsing
        # request.url is an absolute URL string
        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path

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
                # set oauth_state cookie
                headers["Set-Cookie"] = f"oauth_state={state}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=300"
                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))
                return Response(None, status=302, headers=headers)

            # ===== /callback =====
            if path == "/callback":
                q = parsed.query
                qs = urllib.parse.parse_qs(q)
                code = qs.get("code", [None])[0]
                state = qs.get("state", [None])[0]
                cookies = parse_cookies(request.headers.get("Cookie"))
                if not code or cookies.get("oauth_state") != state:
                    return Response("Invalid state or code", status=400)

                # exchange code -> token
                body = urllib.parse.urlencode({
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                })
                token_resp = await fetch("https://discord.com/api/oauth2/token", {
                    "method": "POST",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": body,
                })
                if not token_resp.ok:
                    t = await token_resp.text()
                    print("Token exchange failed:", t)
                    return Response("Token exchange failed", status=500)
                token_json = await token_resp.json()

                user_resp = await fetch("https://discord.com/api/users/@me", {"headers": {"Authorization": f"Bearer {token_json['access_token']}"}})
                if not user_resp.ok:
                    t = await user_resp.text()
                    print("Failed to fetch user:", t)
                    return Response("User fetch failed", status=500)
                user = await user_resp.json()

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
                headers = {"Location": redirect_to}
                headers["Set-Cookie"] = "oauth_state=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
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
                    body, status, headers = json_response({"logged": False}, 200, allowed_origin)
                    return Response(body, status=status, headers=headers)
                body, status, headers = json_response({"logged": True, "user": payload}, 200, allowed_origin)
                return Response(body, status=status, headers=headers)

            # ===== /action =====
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

                member_resp = await fetch(f"https://discord.com/api/guilds/{guild_id}/members/{payload['sub']}", {"headers": {"Authorization": f"Bot {BOT_TOKEN}"}})
                if not member_resp.ok:
                    body, status, headers = json_response({"error": "User not member or bot missing perms"}, 403, allowed_origin)
                    return Response(body, status=status, headers=headers)
                member = await member_resp.json()

                roles_resp = await fetch(f"https://discord.com/api/guilds/{guild_id}/roles", {"headers": {"Authorization": f"Bot {BOT_TOKEN}"}})
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

            # ===== /logout =====
            if path == "/logout":
                headers = {"Location": FRONTEND_URL}
                headers["Set-Cookie"] = "session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))
                return Response(None, status=302, headers=headers)

            # not found
            return Response("Not Found", status=404)

        except Exception as e:
            # crash handling
            print("Worker crash:", getattr(e, "stack", e))
            body, status, headers = json_response({"error": "Internal server error"}, 500, allowed_origin)
            return Response(body, status=status, headers=headers)
