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
import os
import json
# NOTE: this class must be the WorkerEntrypoint subclass your runtime expects

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        # env: try to read from self.env (common pattern), fallback to empty dict
        try:
            CLIENT_SECRET = self.env.DISCORD_CLIENT_SECRET
            BOT_TOKEN = self.env.BOT_TOKEN
            JWT_SECRET = self.env.JWT_SECRET
        except Exception:
            CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
            BOT_TOKEN = os.environ.get("BOT_TOKEN")
            JWT_SECRET = os.environ.get("JWT_SECRET")


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
                try:
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
                except Exception as e:
					# network / runtime error
                    print("Token exchange request failed:", e)
                    body, status, headers = json_response({"error": "Token exchange request failed"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                if not token_resp.ok:
					# discord returned an error (invalid code, etc.)
                    try:
                        t = await token_resp.text()
                    except Exception:
                        t = "<failed to read body>"
                    print("Token exchange failed:", t)
                    body, status, headers = json_response({"error": "Token exchange failed"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

                try:
                    token_json = await token_resp.json()
                except Exception as e:
                    print("Failed to parse token response JSON:", e)
                    body, status, headers = json_response({"error": "Invalid token response"}, 502, allowed_origin)
                    return Response(body, status=status, headers=headers)

				# fetch user info using the user access token
                try:
                    user_resp = await fetch("https://discord.com/api/users/@me", {"headers": {"Authorization": f"Bearer {token_json.get('access_token')}"}})
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

				# --- Сохранение токенов в KV ---
				# Ожидается, что в wrangler.toml/dashboard у тебя привязан Workers KV с именем OAUTH_TOKENS
				# Ключ используем user:{id}. Строка хранится как json.dumps(token_json).
                try:
                    user_id = user.get("id")
                    if user_id and getattr(self, "env", None) and getattr(self.env, "OAUTH_TOKENS", None):
						# сохраним токен (в простом виде). Для продакшна — шифруй перед сохранением.
                        await self.env.OAUTH_TOKENS.put(f"user:{user_id}", json.dumps(token_json))
                    else:
						# KV не настроен — логируем, но не падаем
                        print("OAUTH_TOKENS KV not available; skipping token store")
                except Exception as e:
					# не критично — всё ещё можно продолжить, но логируем
                    print("Failed to store oauth tokens in KV:", e)

				# --- формируем jwt и ставим session cookie ---
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
				# удаляем oauth_state и ставим короткую сессию session (HttpOnly)
                headers["Set-Cookie"] = "oauth_state=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0"
				# прикрепим cookie сессии (HttpOnly) — на будущее клиент может использовать её вместо Bearer header
				# Тут Max-Age выставлен на 1 день; при необходимости сделать короче/использовать refresh - добавь логику refresh.
                headers["Set-Cookie"] += "; "  # просто чтобы отступ был корректен в одном header — ниже мы формируем второй Set-Cookie если нужно
				# NOTE: некоторые рантаймы позволяют только один Set-Cookie header; лучше отправлять как список, но библиотека Response может принимать dict.
				# Для простоты — будем ставить session в отдельном заголовке (поддержка может зависеть от runtime).
				# Попробуй так (если Response поддерживает множественные заголовки, замени на list):
                headers["Set-Cookie-Session"] = f"session={jwt}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=86400"

                if allowed_origin:
                    headers.update(cors_headers(allowed_origin))

				# Если хочется сразу вернуть access/refresh на фронтенд (не рекомендовано) — можно отправить в теле,
				# но мы предпочитаем хранить на сервере и отдать только JWT.
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

            if path == "/guilds":
                # аутентификация JWT (как в /me)
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

                # --- получить сохранённый access_token пользователя из KV ---
                # предположим: self.env.OAUTH_TOKENS.get returns stored JSON (string)
                try:
                    stored = await self.env.OAUTH_TOKENS.get(f"user:{user_id}")
                    if not stored:
                        # нет токена — попроси клиента переавторизоваться
                        body, status, headers = json_response({"error": "No oauth tokens stored, reauthorize"}, 403, allowed_origin)
                        return Response(body, status=status, headers=headers)
                    token_json = json.loads(stored)
                    user_access_token = token_json.get("access_token")
                    # TODO: проверить срок жизни и refresh если нужно (refresh_token flow)
                except Exception:
                    body, status, headers = json_response({"error": "Token storage unavailable"}, 500, allowed_origin)
                    return Response(body, status=status, headers=headers)

                # --- запрос списка гильдий от имени пользователя ---
                guilds_resp = await fetch("https://discord.com/api/users/@me/guilds", {
                    "headers": {"Authorization": f"Bearer {user_access_token}"}
                })
                if not guilds_resp.ok:
                    # возможен expired token -> попытаться refresh, но это отдельно
                    body, status, headers = json_response({"error": "Failed to fetch user guilds"}, 500, allowed_origin)
                    return Response(body, status=status, headers=headers)
                guilds = await guilds_resp.json()

                out = []
                admin_bit = PERMISSION_BITS["ADMINISTRATOR"]
                for g in guilds:
                    g_id = g.get("id")
                    perms = int(g.get("permissions", 0))
                    is_admin = (perms & admin_bit) != 0
                    # проверить наличие бота
                    bot_present = False
                    bot_check = await fetch(f"https://discord.com/api/guilds/{g_id}/members/{CLIENT_ID}", {
                        "headers": {"Authorization": f"Bot {BOT_TOKEN}"}
                    })
                    if bot_check.ok:
                        bot_present = True
                    # формируем запись
                    out.append({
                        "id": g_id,
                        "name": g.get("name"),
                        "permissions": perms,
                        "isAdmin": is_admin,
                        "botPresent": bot_present
                    })

                body, status, headers = json_response({"guilds": out}, 200, allowed_origin)
                return Response(body, status=status, headers=headers)
            if path == "/test":
                resp = await fetch("https://example.com")
                print("Example status:", resp.status)
                body, status, headers = json_response({"test": "ok"}, status, allowed_origin)
                return Response(body, status=status, headers=headers)


            # not found
            return Response("Not Found", status=404)
        
        except Exception as e:
            # crash handling
            print("Worker crash:", getattr(e, "stack", e))
            body, status, headers = json_response({"error": "Internal server error"}, 500, allowed_origin)
            return Response(body, status=status, headers=headers)
