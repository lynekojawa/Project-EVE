import os
import logging
from dotenv import load_dotenv
from supabase import create_client, Client
from postgrest.exceptions import APIError

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DBManager:
    def __init__(self):
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_KEY")

        self.client: Client = create_client(url, key)

    def register_profile(self, username: str, public_key: int) -> tuple:
        try:
            data = {"username": username, "public_key_h": str(public_key)}
            self.client.table("eve_profiles").insert(data).execute()
            logger.info(f"Successfully registered user: {username}")
            return True, "Success"

        except APIError as e:

            if e.code == '23505':
                logger.warning(f"Registration failed: Username '{username}' already exists.")
                return False, "Username already exists"

            logger.error(f"Database error during registration: {e}")

            return False, "Database error"

    def upload_message(self, sender: str, recipient: str, ciphertext: str, encrypted_key_json: str) -> bool:
        try:
            data = {
                "sender": sender,
                "recipient": recipient,
                "ciphertext": ciphertext,
                "encrypted_key_json": encrypted_key_json
            }
            self.client.table("eve_messages").insert(data).execute()
            logger.info(f"Message sent from {sender} to {recipient}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload message: {e}")
            return False

    def fetch_messages(self, recipient: str)-> list:
        try:
            result = self.client.table("eve_messages")\
                        .select("*")\
                        .eq("recipient", recipient)\
                        .order("created_at", desc=False)\
                        .execute()
            return result.data
        except Exception as e:
            logger.error(f"Failed to fetch message: {e}")
            return []

    def fetch_profile(self, username: str) -> dict:
        try:
            result = self.client.table("eve_profiles")\
                        .select("*")\
                        .eq("username", username)\
                        .execute()
            return result.data[0] if result.data else None
        except Exception as e:
            logger.error(f"Failed to fetch profile: {e}")
            return None


if __name__ == "__main__":
    db = DBManager()

    # Test registration
    success = db.register_profile("Alice", 12345)
    print(f"Registration: {success}")

    # Test message upload
    success = db.upload_message("Alice", "Bob", "Olssv", '{"c1": 1, "c2": 2}')
    print(f"Message upload: {success}")

    # Test fetch
    messages = db.fetch_messages("Bob")
    print(f"Messages: {messages}")

    # Test profile fetch
    profile = db.fetch_profile("Alice")
    print(f"Profile: {profile}")