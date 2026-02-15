# database.py
import os
import json
import urllib.parse
from workers import fetch  # pyright: ignore[reportMissingImports]
class SupabaseDB:
    def __init__(self, env=None):
        # env may be a worker env with attributes, or None -> fallback to os.environ
        if env is not None:
            self.url = getattr(env, "SUPABASE_URL", None) or os.environ.get("SUPABASE_URL")
            self.key = getattr(env, "SUPABASE_SERVICE_KEY", None) or os.environ.get("SUPABASE_SERVICE_KEY")
        else:
            self.url = os.environ.get("SUPABASE_URL")
            self.key = os.environ.get("SUPABASE_SERVICE_KEY")

        if not self.url or not self.key:
            raise RuntimeError("Supabase config missing (SUPABASE_URL / SUPABASE_SERVICE_KEY)")

        # base REST endpoint for table `oauth_tokens`
        self.base = self.url.rstrip("/") + "/rest/v1/oauth_tokens"

    async def save_token(self, user_id: str, token_json: dict) -> bool:
        """
        Insert or update token for user_id.
        Uses Prefer: resolution=merge-duplicates to upsert by primary key user_id.
        """
        payload = {
            "user_id": user_id,
            "access_token": token_json.get("access_token"),
            "refresh_token": token_json.get("refresh_token"),
            # optionally store other fields if needed, e.g. expires_at etc.
        }
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            # merge duplicates = upsert on primary key
            "Prefer": "resolution=merge-duplicates,return=representation"
        }
        try:
            resp = await fetch(self.base, method="POST", headers=headers, body=json.dumps(payload))
            return 200 <= resp.status < 300
        except Exception as e:
            print("Supabase save_token fetch failed:", e)
            return False

    async def get_token(self, user_id: str):
        """
        Fetch token row by user_id. Returns dict or None.
        """
        qs = f"?user_id=eq.{urllib.parse.quote(str(user_id))}&select=*"
        url = self.base + qs
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}"
        }
        try:
            resp = await fetch(url, headers=headers)
            if not resp.ok:
                try:
                    txt = await resp.text()
                    print("Supabase get_token non-ok:", resp.status, txt)
                except Exception:
                    pass
                return None
            data = await resp.json()
            if not isinstance(data, list) or len(data) == 0:
                return None
            # return first row as dict
            return data[0]
        except Exception as e:
            print("Supabase get_token fetch failed:", e)
            return None
