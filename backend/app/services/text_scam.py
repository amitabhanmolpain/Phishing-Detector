import re

SCAM_KEYWORD_CATEGORIES = [
    {
        "name": "KYC / account threat",
        "weight": 2,
        "keywords": [
            "kyc",
            "account blocked",
            "account suspended",
            "account will be blocked",
            "pan card",
            "verify your account",
            "update your kyc",
            "account update",
            "card blocked",
            "account deactivated",
        ],
    },
    {
        "name": "OTP / credential request",
        "weight": 2,
        "keywords": ["otp", "one time password", "cvv", "share your otp", "verify otp", "confirm otp"],
    },
    {
        "name": "lottery / prize scam",
        "weight": 1.5,
        "keywords": [
            "lottery",
            "you have won",
            "winner",
            "prize",
            "lucky draw",
            "cashback",
            "crore",
            "lakh",
            "gift card",
            "claim your reward",
        ],
    },
    {
        "name": "urgency / pressure tactics",
        "weight": 1,
        "keywords": [
            "urgent",
            "immediately",
            "act now",
            "final notice",
            "within 24 hours",
            "action required",
            "click here",
            "expire today",
            "last warning",
        ],
    },
    {
        "name": "job / money-making scam",
        "weight": 1.5,
        "keywords": [
            "work from home",
            "earn money",
            "part time job",
            "part-time job",
            "daily payout",
            "telegram task",
            "investment opportunity",
            "double your money",
        ],
    },
]

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def check_text_for_scam_patterns(text: str) -> dict:
    """Score a message for common scam phrasing.

    Returns dict: score (float), matched_keywords (list[str]),
    matched_categories (list[str]).
    """
    clean_text = text.lower()
    score = 0.0
    matched_keywords: list[str] = []
    matched_categories: list[str] = []

    for category in SCAM_KEYWORD_CATEGORIES:
        hits = [kw for kw in category["keywords"] if kw in clean_text]
        if hits:
            matched_categories.append(category["name"])
            matched_keywords.extend(hits)
            score += len(hits) * category["weight"]

    return {"score": score, "matched_keywords": matched_keywords, "matched_categories": matched_categories}
