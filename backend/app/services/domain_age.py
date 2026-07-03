import socket
from datetime import datetime, timezone

import whois

# python-whois issues raw socket connections with no built-in timeout;
# cap it so a slow/unresponsive WHOIS server can't hang a request.
socket.setdefaulttimeout(6)

NEW_DOMAIN_THRESHOLD_DAYS = 30


def _first(value):
    return value[0] if isinstance(value, list) else value


def check_domain_age(hostname: str) -> dict:
    """WHOIS lookup for domain registration age.

    Returns dict: age_days (int|None), is_new (bool), status_text (str).
    Flags domains registered less than NEW_DOMAIN_THRESHOLD_DAYS days ago,
    since short-lived infrastructure is a strong phishing signal.
    """
    try:
        record = whois.whois(hostname)
        created = _first(record.creation_date)

        if not created:
            return {"age_days": None, "is_new": False, "status_text": "Unknown (no WHOIS creation date found)"}

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - created).days
        is_new = age_days < NEW_DOMAIN_THRESHOLD_DAYS
        status_text = f"{age_days} days old (registered {created.date().isoformat()})"
        return {"age_days": age_days, "is_new": is_new, "status_text": status_text}
    except Exception:
        return {"age_days": None, "is_new": False, "status_text": "Unknown (WHOIS lookup failed)"}
