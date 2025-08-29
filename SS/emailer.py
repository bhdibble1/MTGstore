# SS/emailer.py
import os
import requests

RESEND_ENDPOINT = "https://api.resend.com/emails"

def send_email(to, subject: str, html: str, from_email: str | None = None, from_name: str | None = None, reply_to: str | None = None) -> bool:
    """
    Send an HTML email via Resend using only `requests`.
    - `to` can be a string or list of strings
    - `from_email` MUST be on your verified domain (e.g., orders@send.yourdomain.com)
    - set env: RESEND_API_KEY, FROM_EMAIL, FROM_NAME (optional)
    """
    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        print("⚠️ RESEND_API_KEY not set; skipping email.")
        return False

    from_email = from_email or os.environ.get("FROM_EMAIL")
    if not from_email:
        print("⚠️ FROM_EMAIL not set; skipping email.")
        return False

    from_name = from_name or os.environ.get("FROM_NAME", "5 Star Mint")
    from_field = f"{from_name} <{from_email}>"

    # Resend accepts a string or a list; normalize to list for safety
    to_list = to if isinstance(to, list) else [to]

    payload = {
        "from": from_field,
        "to": to_list,
        "subject": subject,
        "html": html,
    }
    if reply_to:
        payload["reply_to"] = reply_to  # optional

    try:
        resp = requests.post(
            RESEND_ENDPOINT,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )
        print("📨 Resend response:", resp.status_code, resp.text[:500])
        return resp.ok
    except requests.RequestException as e:
        print("❌ Resend request failed:", e)
        return False
