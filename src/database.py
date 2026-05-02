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

    async def record_view(self, page: str = "/") -> bool:
        """
        Insert a page view row into `page_views` table. Expects a table `page_views`
        with at least columns: `page` (text) and `created_at` (timestamp default now()).
        """
        url = self.url.rstrip("/") + "/rest/v1/page_views"
        payload = {"page": page}
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            # return representation not strictly required, but useful for debugging
            "Prefer": "return=representation"
        }
        try:
            resp = await fetch(url, method="POST", headers=headers, body=json.dumps(payload))
            return 200 <= resp.status < 300
        except Exception as e:
            print("Supabase record_view failed:", e)
            return False

    async def count_views(self, since_iso: str = None, page: str = None):
        """
        Count page_views rows optionally filtered by `created_at >= since_iso` and/or `page`.
        Uses PostgREST's `Prefer: count=exact` and reads `Content-Range` header when available.
        Returns integer count or None on error.
        """
        qs_parts = []
        if page:
            qs_parts.append(f"page=eq.{urllib.parse.quote(page)}")
        if since_iso:
            qs_parts.append(f"created_at=gte.{urllib.parse.quote(since_iso)}")
        qs = "?select=id"
        if qs_parts:
            qs += "&" + "&".join(qs_parts)
        url = self.url.rstrip("/") + "/rest/v1/page_views" + qs
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            # ask PostgREST for an exact count
            "Prefer": "count=exact"
        }
        try:
            resp = await fetch(url, headers=headers)
            if not resp.ok:
                try:
                    txt = await resp.text()
                    print("Supabase count_views non-ok:", resp.status, txt)
                except Exception:
                    pass
                return None
            # PostgREST sets Content-Range like "0-9/123" when Prefer: count=exact
            cr = resp.headers.get("content-range") or resp.headers.get("Content-Range")
            if cr:
                parts = cr.split("/")
                if len(parts) == 2:
                    try:
                        return int(parts[1])
                    except Exception:
                        pass
            # fallback: count returned items
            try:
                data = await resp.json()
                if isinstance(data, list):
                    return len(data)
            except Exception:
                pass
            return 0
        except Exception as e:
            print("Supabase count_views fetch failed:", e)
            return None

    async def increment_counters(self, page: str = "/"):
        """
        Call RPC function `increment_page_counters` to atomically increment
        day/month/year/all_time counters for `page` and return the new values.
        Returns a dict like {"day_count":.., "month_count":.., "year_count":.., "all_time_count":..}
        or None on error.
        """
        url = self.url.rstrip("/") + "/rest/v1/rpc/increment_page_counters"
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
        }
        body = json.dumps({"p_page": page})
        try:
            resp = await fetch(url, method="POST", headers=headers, body=body)
            if not resp.ok:
                try:
                    txt = await resp.text()
                    print("Supabase increment_counters non-ok:", resp.status, txt)
                except Exception:
                    pass
                return None
            try:
                data = await resp.json()
            except Exception as e:
                print("Supabase increment_counters parse failed:", e)
                return None
            # PostgREST returns an array for setof/returns table types
            rec = None
            if isinstance(data, list) and data:
                rec = data[0]
            elif isinstance(data, dict):
                rec = data
            if not rec:
                return None
            # Normalize numeric values
            try:
                return {
                    "last_day": int(rec.get("day_count") or rec.get("day_count") or 0),
                    "last_month": int(rec.get("month_count") or 0),
                    "last_year": int(rec.get("year_count") or 0),
                    "all_time": int(rec.get("all_time_count") or 0),
                }
            except Exception:
                return {
                    "last_day": rec.get("day_count"),
                    "last_month": rec.get("month_count"),
                    "last_year": rec.get("year_count"),
                    "all_time": rec.get("all_time_count"),
                }
        except Exception as e:
            print("Supabase increment_counters fetch failed:", e)
            return None
