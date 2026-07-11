import ssl
import socket
from urllib.parse import urlparse
import ipaddress


def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(),
            server_hostname=domain
        ) as s:
            s.settimeout(5)
            s.connect((domain, 443))

            cert = s.getpeercert()

            issuer = dict(x[0] for x in cert['issuer'])
            issued_by = issuer.get('organizationName', 'Unknown')

            expiry = cert['notAfter']

            return {
                "valid": True,
                "issuer": issued_by,
                "expiry": expiry
            }

    except:
        return {
            "valid": False,
            "issuer": "Unknown",
            "expiry": "Unknown"
        }


def analyze_url(url):
    score = 0
    reasons = []

    # Get domain
    domain = urlparse(url).netloc

    if domain.startswith("www."):
        domain = domain[4:]

    # Get IP address
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unknown"

    # Get SSL information
    ssl_info = get_ssl_info(domain)

    # HTTPS Check
    if not url.startswith("https://"):
        score += 20
        reasons.append("Website does not use HTTPS.")

    # URL Length Check
    if len(url) > 75:
        score += 20
        reasons.append("URL is unusually long.")

    # IP Address Check
    try:
        ipaddress.ip_address(domain)
        score += 30
        reasons.append("URL uses an IP address.")
    except:
        pass

    # Suspicious Words
    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "bank",
        "account"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains suspicious word: {word}")

    # URL Shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    for site in shorteners:
        if site in url.lower():
            score += 20
            reasons.append("URL uses a URL shortener.")
            break

    # @ Symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains '@' symbol.")

    # Too many subdomains
    parts = domain.split(".")
    if len(parts) > 3:
        score += 15
        reasons.append("URL contains many subdomains.")

    # Punycode detection
    if "xn--" in domain:
        score += 25
        reasons.append("Punycode domain detected.")

    # Hyphenated domain
    if "-" in domain:
        score += 10
        reasons.append("Domain contains hyphens.")

    # Limit score to 100
    score = min(score, 100)

    # Verdict
    if score >= 70:
        verdict = "High Risk"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "domain": domain,
        "ip": ip,
        "ssl_valid": ssl_info["valid"],
        "ssl_issuer": ssl_info["issuer"],
        "ssl_expiry": ssl_info["expiry"]
    }
