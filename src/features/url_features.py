import re
import ipaddress
from urllib.parse import urlparse

import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "billing",
    "payment",
    "authenticate",
]
def normalize_url(url):
    url = str(url).strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url

def is_ip_address(hostname):
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_url_features(url):
    url = normalize_url(url)

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain

    features = {}

    # Basic lengths
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # Character counts
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["digit_count"] = sum(c.isdigit() for c in url)

    features["special_char_count"] = sum(
        not c.isalnum() for c in url
    )

    # Structure
    features["subdomain_count"] = (
        len(subdomain.split("."))
        if subdomain
        else 0
    )

    features["contains_ip"] = is_ip_address(hostname)

    features["uses_https"] = int(
        parsed.scheme.lower() == "https"
    )

    features["contains_at"] = int("@" in url)

    features["contains_double_slash"] = int(
        "//" in parsed.path
    )

    # Suspicious keywords
    url_lower = url.lower()

    features["suspicious_keyword_count"] = sum(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    return features


if __name__ == "__main__":

    test_url = "https://www.google.com"

    result = extract_url_features(test_url)

    for key, value in result.items():
      print(f"{key}: {value}")
