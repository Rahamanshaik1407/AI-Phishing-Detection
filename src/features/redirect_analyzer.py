"""
Redirect Chain Analyzer

This module follows HTTP redirects and records every URL
visited before reaching the final destination.

Example:

URL A
  ↓ 301
URL B
  ↓ 302
URL C
  ↓ 301
URL D

The complete chain can later become a feature for our
phishing risk engine.

SSRF Security:
Uses safe_fetcher to validate destination IP and prevent DNS rebinding
at every redirect hop.
"""

from urllib.parse import urljoin
from src.features.domain_intelligence import normalize_url
from src.features.safe_fetcher import safe_get, REQUEST_TIMEOUT, MAX_REDIRECTS_DEFAULT

MAX_REDIRECTS = MAX_REDIRECTS_DEFAULT


def analyze_redirect_chain(url: str, timeout: int = REQUEST_TIMEOUT) -> dict:
    """
    Follow redirects safely and return information about the chain.

    Returns:
        A dictionary containing:
        - original URL
        - final URL
        - number of redirects
        - complete redirect chain
        - HTTP status codes
        - whether the request failed or was blocked by SSRF protections
    """
    # Normalize the URL before making the request.
    url = normalize_url(url)

    redirect_chain = []
    status_codes = []
    current_url = url

    try:
        for _ in range(MAX_REDIRECTS):
            # Use safe_fetcher to protect against SSRF and DNS rebinding
            fetch_result = safe_get(current_url, timeout=timeout)

            # Store the URL that was requested
            redirect_chain.append(current_url)

            if not fetch_result.get("success"):
                is_blocked = fetch_result.get("blocked", False)
                error_msg = fetch_result.get("reason") or fetch_result.get("error", "Request failed")
                return {
                    "success": False,
                    "blocked": is_blocked,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": max(0, len(redirect_chain) - 1),
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False,
                    "error": error_msg
                }

            status_code = fetch_result.get("status_code", 0)
            status_codes.append(status_code)

            # Check whether the response is a redirect
            if status_code not in (301, 302, 303, 307, 308):
                return {
                    "success": True,
                    "blocked": False,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False
                }

            # Get the destination from Location header
            headers = fetch_result.get("headers", {})
            next_url = headers.get("Location") or headers.get("location")

            if not next_url:
                return {
                    "success": True,
                    "blocked": False,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False
                }

            # Convert relative redirects into absolute URLs
            next_url = urljoin(current_url, next_url)

            # Detect immediate redirect loop
            if next_url in redirect_chain:
                redirect_chain.append(next_url)
                return {
                    "success": True,
                    "blocked": False,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False,
                    "loop_detected": True
                }

            current_url = next_url

        # Max redirects safety limit reached
        return {
            "success": False,
            "blocked": True,
            "original_url": url,
            "final_url": current_url,
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain,
            "status_codes": status_codes,
            "max_redirects_reached": True,
            "error": f"Exceeded maximum redirects limit of {MAX_REDIRECTS}"
        }

    except Exception as error:
        return {
            "success": False,
            "blocked": False,
            "original_url": url,
            "final_url": current_url,
            "redirect_count": max(0, len(redirect_chain) - 1),
            "redirect_chain": redirect_chain,
            "status_codes": status_codes,
            "max_redirects_reached": False,
            "error": str(error)
        }


def main():
    """
    Test the redirect analyzer.
    """
    test_urls = [
        "http://google.com",
        "https://example.com"
    ]

    for test_url in test_urls:
        print("\n" + "=" * 60)
        print("Testing:", test_url)
        result = analyze_redirect_chain(test_url)
        print("\nOriginal URL:", result.get("original_url"))
        print("Final URL:", result.get("final_url"))
        print("Redirect count:", result.get("redirect_count"))
        print("Status codes:", result.get("status_codes"))
        print("Chain:", result.get("redirect_chain"))


if __name__ == "__main__":
    main()
