"""
Project EVE v2.1 - Phase 3: Database & Dual-Client Security Architecture
Implement zero-trust database routing with standard client separation and
 an isolated service for Eve's adversary telemetry console.
"""

import os
import logging
from typing import List, Dict, Tuple, Optional, Any
from dotenv import load_dotenv
from supabase import create_client, Client
from postgrest.exceptions import APIError

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DBManager:
    """
    Manages database transactions for Project EVE
    Enforces dual-client isolation between standard user operations and adversary telemetry.
    """
    def __init__(self):
        url: Optional[str] = os.getenv("SUPABASE_URL")
        anon_key: Optional[str] = os.getenv("SUPABASE_KEY")
        service_role_key: Optional[str] = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

        if not url or not anon_key:
            logger.error("SUPABASE_URL and SUPABASE_KEY missing from environment variables")
            raise ValueError("Supabase environment configuration missing")

        self.client: Client = create_client(url, anon_key)
        self._admin_client: Optional[Client] = None
        if service_role_key:
            self._admin_client = create_client(url, service_role_key)
            logger.info("Service-Role Client initialized for adversary emulation.")
        else:
            logger.warning(
                "SUPABASE_SERVICE_ROLE_KEY not configured."
                "Adversary console will operate using standard client permissions."
            )

    def register_profile(self, username: str, public_key: str) -> Tuple[bool, str]:
        """
        Registers a new user and stores their ElGamal public key in the public directory.
        """
        try:
            profile_data = {
                "username": username,
                "public_key": public_key
            }
            self.client.table("eve_profiles").insert(profile_data).execute()
            logger.info(f"Imperial Citizen Registered: {username}")
            return True, "Success"

        except APIError as e:
            if '23505' in str(e):
                return False, "Username already exists"

            logger.error(f"Database error during registration: {e}")
            return False, "Database error"
        except Exception as ex:
            logger.error(f"Unexpected error during registration: {ex}")
            return False, "Registration error"

    def fetch_profile(self, username: str) -> Optional[Dict[str, Any]]:
        """Fetches a user's public profile from the directory."""
        try:
            result = self.client.table("eve_profiles") \
                .select("*") \
                .eq("username", username) \
                .single()\
                .execute()
            return result.data if result.data else None
        except Exception as e:
            logger.error(f"Failed to fetch profile for {username}: {e}")
            return None

    def login_user(self, username: str, public_key: str) -> bool:
        """Logs in using username and public key to activate RLS session."""
        try:
            result = self.client.table("eve_profiles") \
                .select("public_key") \
                .eq("username", username) \
                .single() \
                .execute()
            if result.data:
                return result.data["public_key"] == public_key
            return False
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False

    def upload_message(self, sender: str, recipient: str, ciphertext: str, encrypted_key_json: str) -> bool:
        """Uploads an encrypted wire-protocol packet and key-payload"""
        try:
            data = {
                "sender": sender,
                "recipient": recipient,
                "ciphertext": ciphertext,
                "encrypted_key_json": encrypted_key_json
            }
            self.client.table("eve_messages").insert(data).execute()
            logger.info(f"Wire packet uploaded: {sender} -> {recipient}")
            return True
        except Exception as e:
            logger.error(f"Failed to upload wire packet: {e}")
            return False

    def fetch_messages(self, username: str) -> List[Dict[str, Any]]:
        """Fetches inbox messages addressed to the authenticated recipient"""
        try:
            result = self.client.table("eve_messages")\
                        .select("*")\
                        .eq("recipient", username)\
                        .order("created_at", desc=False)\
                        .execute()
            return result.data if result.data else []
        except Exception as e:
            logger.error(f"Failed to fetch inbox messages for {username}:{e}")
            return []

    def delete_message(self, message_id: str)-> bool:
        """Permanently purges an encrypted message row from cloud storage."""
        try:
            result = self.client.table("eve_messages").delete().eq("id", message_id).execute()
            if result.data:
                logger.info(f"Purged message ID: {message_id}")
                return True
            else:
                logger.warning(f"Delete attempted but no row found or RLS blocked: {message_id}")
                return False
        except Exception as e:
            logger.error(f"Database error during message purge: {e}")
            return False

    def fetch_targeted_messages(self, username: str) -> List[Dict[str, Any]]:
        """
        Adversarial Telemetry Vector: Taps raw cloud traffic targeting a specific user.
        Uses the isolated service-role client to simulate a cloud-level datastore breach.
        """
        active_client = self._admin_client if self._admin_client is not None else self.client
        try:
            response = active_client.table("eve_messages") \
                .select("*") \
                .or_(f"sender.eq.{username},recipient.eq.{username}") \
                .order("created_at", desc=True) \
                .execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error intercepting traffic for {username}: {e}")
            return []








