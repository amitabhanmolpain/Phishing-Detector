DANGEROUS_THRESHOLD = 6
SUSPICIOUS_THRESHOLD = 2

VERDICT_SCORE = {"Safe": 0, "Suspicious": SUSPICIOUS_THRESHOLD, "Dangerous": DANGEROUS_THRESHOLD}


def _score_to_verdict(score: float) -> str:
    if score >= DANGEROUS_THRESHOLD:
        return "Dangerous"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def build_url_verdict(safe_browsing: dict, domain_age: dict, typosquat: dict, is_http: bool) -> dict:
    score = 0.0
    reasons: list[str] = []

    if safe_browsing["flagged"]:
        score += 6
        reasons.append(f"it is flagged by Google Safe Browsing ({', '.join(safe_browsing['threats'])})")

    if typosquat["is_impersonation"]:
        score += 5
        reasons.append(f"it mimics {typosquat['matched_brand']} but does not match its official domain")

    if domain_age["age_days"] is not None and domain_age["is_new"]:
        score += 3
        reasons.append(f"the domain was registered only {domain_age['age_days']} days ago")
    elif domain_age["age_days"] is None:
        score += 1
        reasons.append("the domain's age could not be verified")

    if is_http:
        score += 1
        reasons.append("the connection is not encrypted (HTTP)")

    verdict = _score_to_verdict(score)
    if reasons:
        reason = f"This link is {verdict.lower()} because " + " and ".join(reasons) + "."
    else:
        reason = "This link appears safe: no known threats, an established domain, and no signs of brand impersonation."

    return {"verdict": verdict, "reason": reason, "score": score}


def build_text_verdict(text_result: dict, url_verdicts: list[dict]) -> dict:
    score = text_result["score"]
    reasons: list[str] = []

    if text_result["matched_categories"]:
        reasons.append(f"it contains language typical of {', '.join(text_result['matched_categories'])}")

    if url_verdicts:
        worst = max(url_verdicts, key=lambda v: VERDICT_SCORE[v["verdict"]])
        if worst["verdict"] != "Safe":
            score += worst["score"]
            reasons.append(f"it includes a link that is {worst['verdict'].lower()}")
        else:
            reasons.append("it includes a link")

    verdict = _score_to_verdict(score)
    if reasons:
        reason = f"This message is {verdict.lower()} because " + " and ".join(reasons) + "."
    else:
        reason = "This message does not contain any known scam keywords or suspicious links."

    return {"verdict": verdict, "reason": reason, "score": score}
