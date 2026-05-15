import os
import json
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

class DBManager:
    def __init__(self):
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")

        self.client: Client = create_client(url, key)

    def register_profile(self, username: str, public_key: int) -> None:
        data = {"username": username, "public_key_h": str(public_key)}
        self.client.table("eve_profiles").upsert(data).execute()

