"""
Sentinel AI Standards-Based Web Push Notification Service.
Implements zero-budget, free browser Web Push using VAPID and RFC 8291/RFC 8292.
Zero cost, no external paid SMS or WhatsApp provider needed.
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
from pywebpush import webpush, WebPushException
from app.database import (
    get_push_subscriptions_for_user,
    delete_push_subscription,
)

logger = logging.getLogger("sentinel.push")

VAPID_PUBLIC_KEY = os.getenv(
    "VAPID_PUBLIC_KEY",
    "BLpvWXZ9b2EdlwKkT45YskrYQItuYYqTF1UwiIQaqSy-h3TaOHRvOHaAQRCuZX8YCjwNj8wIKnR8Wvo8V6c8SSQ",
)
VAPID_PRIVATE_KEY = os.getenv(
    "VAPID_PRIVATE_KEY",
    "-5UaI7XJF4aI1KmX-Yo79vAFGZneSlwjP9ODGrqa38M",
)
VAPID_CLAIM_EMAIL = os.getenv(
    "VAPID_CLAIM_EMAIL",
    "mailto:security@sentinel.ai",
)


def get_vapid_public_key() -> str:
    """Returns the VAPID public key for frontend push subscription registration."""
    return VAPID_PUBLIC_KEY


def send_web_push(subscription_info: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sends a single Web Push notification to a target browser subscription.
    Handles expired subscriptions (HTTP 410/404) by purging from database.
    """
    endpoint = subscription_info.get("endpoint")
    if not endpoint:
        return {"success": False, "error": "Missing subscription endpoint"}

    vapid_claims = {"sub": VAPID_CLAIM_EMAIL}

    try:
        response = webpush(
            subscription_info=subscription_info,
            data=json.dumps(payload),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims=vapid_claims,
            timeout=10,
        )
        logger.info(f"Web Push sent successfully to endpoint: {endpoint[:32]}... status: {response.status_code}")
        return {
            "success": True,
            "status_code": response.status_code,
            "endpoint": endpoint,
        }
    except WebPushException as ex:
        logger.warning(f"WebPushException for endpoint {endpoint[:32]}: {ex}")
        status_code = getattr(ex.response, "status_code", None) if ex.response else None
        # Purge inactive / expired subscriptions
        if status_code in (404, 410):
            logger.info(f"Push subscription expired/unregistered ({status_code}). Removing {endpoint[:32]}...")
            try:
                delete_push_subscription(endpoint)
            except Exception as e:
                logger.error(f"Error purging expired push subscription: {e}")
        return {
            "success": False,
            "error": str(ex),
            "status_code": status_code,
            "endpoint": endpoint,
        }
    except Exception as ex:
        logger.error(f"Unexpected error sending Web Push: {ex}")
        return {
            "success": False,
            "error": str(ex),
            "endpoint": endpoint,
        }


def dispatch_push_to_user(user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dispatches a push notification to all registered push-enabled mobile browsers for a user.
    """
    subscriptions = get_push_subscriptions_for_user(user_id)
    if not subscriptions:
        logger.info(f"No push subscriptions found for user {user_id}.")
        return {
            "sent": 0,
            "total": 0,
            "configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
            "status": "no_registered_devices",
            "message": "No registered push subscriptions found for user.",
        }

    sent_count = 0
    errors: List[str] = []

    for sub in subscriptions:
        sub_info = {
            "endpoint": sub["endpoint"],
            "keys": {
                "p256dh": sub["p256dh"],
                "auth": sub["auth"],
            },
        }
        res = send_web_push(sub_info, payload)
        if res.get("success"):
            sent_count += 1
        else:
            errors.append(res.get("error", "Unknown delivery error"))

    return {
        "sent": sent_count,
        "total": len(subscriptions),
        "configured": True,
        "status": "delivered" if sent_count > 0 else "failed",
        "errors": errors,
    }
