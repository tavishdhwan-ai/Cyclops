"""
Sentinel AI WhatsApp Messaging Provider Abstraction.
Supports Twilio WhatsApp and Meta WhatsApp Business Cloud Platform.
Enforces that unconfigured credentials report an explicit integration-required state
without faking successful delivery.
"""
import os
import re
import logging
from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel
import httpx

logger = logging.getLogger("sentinel.whatsapp")


class WhatsAppSendResult(BaseModel):
    success: boolean = False  # Note: Pydantic accepts bool
    success: bool = False
    provider: str
    is_configured: bool = True
    message_id: Optional[str] = None
    status: str = "pending"  # "sent", "delivered", "unconfigured", "failed"
    error: Optional[str] = None


class WhatsAppProvider(ABC):
    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True only when required provider API keys are present."""
        pass

    @abstractmethod
    async def send_verification_link(
        self,
        phone_number: str,
        verification_url: str,
        transaction_id: str,
    ) -> WhatsAppSendResult:
        """Sends single-use verification link to normalized E.164 phone number."""
        pass


class TwilioWhatsAppProvider(WhatsAppProvider):
    def __init__(self):
        self.account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
        self.auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
        self.from_number = os.getenv("TWILIO_WHATSAPP_NUMBER", "").strip()

    def is_configured(self) -> bool:
        return bool(
            self.account_sid
            and self.auth_token
            and self.from_number
            and not self.account_sid.startswith("your-")
        )

    async def send_verification_link(
        self,
        phone_number: str,
        verification_url: str,
        transaction_id: str,
    ) -> WhatsAppSendResult:
        if not self.is_configured():
            return WhatsAppSendResult(
                success=False,
                provider="twilio",
                is_configured=False,
                status="unconfigured",
                error="Twilio WhatsApp credentials (TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER) are not configured.",
            )

        # Normalize Twilio WhatsApp address format
        from_formatted = (
            self.from_number
            if self.from_number.startswith("whatsapp:")
            else f"whatsapp:{self.from_number}"
        )
        to_formatted = (
            phone_number
            if phone_number.startswith("whatsapp:")
            else f"whatsapp:{phone_number}"
        )

        message_body = (
            f"Sentinel AI Security Verification\n\n"
            f"Tap the secure link below on your mobile device to complete biometric authentication:\n"
            f"{verification_url}\n\n"
            f"This link expires in 10 minutes and can only be used once. If you did not request this, ignore this message."
        )

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    auth=(self.account_sid, self.auth_token),
                    data={
                        "From": from_formatted,
                        "To": to_formatted,
                        "Body": message_body,
                    },
                )

                if response.status_code in (200, 201):
                    data = response.json()
                    logger.info(
                        "WhatsApp verification dispatched via Twilio for tx: %s",
                        transaction_id,
                    )
                    return WhatsAppSendResult(
                        success=True,
                        provider="twilio",
                        is_configured=True,
                        message_id=data.get("sid"),
                        status="sent",
                    )
                else:
                    error_msg = f"Twilio API Error ({response.status_code}): {response.text}"
                    logger.error("Failed to send WhatsApp message via Twilio: %s", error_msg)
                    return WhatsAppSendResult(
                        success=False,
                        provider="twilio",
                        is_configured=True,
                        status="failed",
                        error=error_msg,
                    )
        except Exception as e:
            logger.error("Twilio request exception: %s", str(e))
            return WhatsAppSendResult(
                success=False,
                provider="twilio",
                is_configured=True,
                status="failed",
                error=f"Network error contacting Twilio: {str(e)}",
            )


class MetaWhatsAppProvider(WhatsAppProvider):
    def __init__(self):
        self.api_token = os.getenv("WHATSAPP_API_TOKEN", "").strip()
        self.phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
        self.template_name = os.getenv("WHATSAPP_TEMPLATE_NAME", "sentinel_auth_verify").strip()

    def is_configured(self) -> bool:
        return bool(
            self.api_token
            and self.phone_number_id
            and not self.api_token.startswith("your-")
        )

    async def send_verification_link(
        self,
        phone_number: str,
        verification_url: str,
        transaction_id: str,
    ) -> WhatsAppSendResult:
        if not self.is_configured():
            return WhatsAppSendResult(
                success=False,
                provider="meta",
                is_configured=False,
                status="unconfigured",
                error="Meta WhatsApp Cloud API credentials (WHATSAPP_API_TOKEN, WHATSAPP_PHONE_NUMBER_ID) are not configured.",
            )

        clean_recipient = re.sub(r"[^\d]", "", phone_number)
        url = f"https://graph.facebook.com/v19.0/{self.phone_number_id}/messages"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "messaging_product": "whatsapp",
            "to": clean_recipient,
            "type": "text",
            "text": {
                "preview_url": True,
                "body": (
                    f"Sentinel AI Security Verification\n\n"
                    f"Tap to verify your mobile device:\n{verification_url}\n\n"
                    f"Expires in 10 minutes. Single-use."
                ),
            },
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code in (200, 201):
                    data = response.json()
                    msg_id = (
                        data.get("messages", [{}])[0].get("id")
                        if "messages" in data
                        else None
                    )
                    return WhatsAppSendResult(
                        success=True,
                        provider="meta",
                        is_configured=True,
                        message_id=msg_id,
                        status="sent",
                    )
                else:
                    return WhatsAppSendResult(
                        success=False,
                        provider="meta",
                        is_configured=True,
                        status="failed",
                        error=f"Meta WhatsApp API Error ({response.status_code}): {response.text}",
                    )
        except Exception as e:
            return WhatsAppSendResult(
                success=False,
                provider="meta",
                is_configured=True,
                status="failed",
                error=f"Network error contacting Meta API: {str(e)}",
            )


def get_whatsapp_provider() -> WhatsAppProvider:
    """
    Selects configured WhatsApp provider based on environment variables.
    Defaults to Twilio if TWILIO_ACCOUNT_SID is set, otherwise Meta, or unconfigured fallback.
    """
    twilio = TwilioWhatsAppProvider()
    if twilio.is_configured():
        return twilio

    meta = MetaWhatsAppProvider()
    if meta.is_configured():
        return meta

    # Return Twilio instance as default unconfigured provider
    return twilio
