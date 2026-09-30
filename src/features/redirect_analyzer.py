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
"""

import requests
from urllib.parse import urlparse

from src.features.domain_intelligence import normalize_url


# Maximum number of redirects we allow.
# This prevents infinite redirect loops.
MAX_REDIRECTS = 10

# Maximum time to wait for a server response.
REQUEST_TIMEOUT = 10


def analyze_redirect_chain(url):
    """
    Follow redirects and return information about the chain.

    Returns:
        A dictionary containing:
        - original URL
        - final URL
        - number of redirects
        - complete redirect chain
        - HTTP status codes
        - whether the request failed
    """

    # Normalize the URL before making the request.
    url = normalize_url(url)

    redirect_chain = []
    status_codes = []

    current_url = url

    try:

        # Disable automatic redirect following.
        # We want to inspect every redirect ourselves.
        for _ in range(MAX_REDIRECTS):

            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,

                # Use a normal browser-like User-Agent.
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 "
                        "Chrome/145.0 Safari/537.36"
                    )
                }
            )

            # Store the URL that was actually requested.
            redirect_chain.append(current_url)

            # Store the HTTP response status.
            status_codes.append(response.status_code)

            # Check whether the response is a redirect.
            if response.status_code not in (
                301,
                302,
                303,
                307,
                308
            ):
                # We reached the final destination.
                return {
                    "success": True,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False
                }

            # Get the destination from the Location header.
            next_url = response.headers.get("Location")

            # Some malformed redirects may not contain Location.
            if not next_url:
                return {
                    "success": True,
                    "original_url": url,
                    "final_url": current_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "status_codes": status_codes,
                    "max_redirects_reached": False
                }

            # Convert relative redirects into absolute URLs.
            next_url = requests.compat.urljoin(
                current_url,
                next_url
            )

            current_url = next_url

        # We reached the safety limit.
        return {
            "success": False,
            "original_url": url,
            "final_url": current_url,
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain,
            "status_codes": status_codes,
            "max_redirects_reached": True
        }

    except requests.RequestException as error:

        # Network failures are recorded rather than crashing
        # the entire phishing-analysis pipeline.
        return {
            "success": False,
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
    Test the redirect analyzer using a few URLs.
    """

    test_urls = [
        "http://google.com",
        "https://example.com"
    ]

    for url in test_urls:

        print("\n" + "=" * 60)
        print("Testing:", url)

        result = analyze_redirect_chain(url)

        print("\nOriginal URL:")
        print(result["original_url"])

        print("\nFinal URL:")
        print(result["final_url"])

        print("\nRedirect count:")
        print(result["redirect_count"])

        print("\nStatus codes:")
        print(result["status_codes"])

        print("\nRedirect chain:")

        for index, redirect_url in enumerate(
            result["redirect_chain"]
        ):
            print(f"{index}: {redirect_url}")


if __name__ == "__main__":
    main()
