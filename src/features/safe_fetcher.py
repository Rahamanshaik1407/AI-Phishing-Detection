"""
SSRF-safe HTTP fetching utilities.

This module validates destination IP addresses before making
HTTP requests.

The goal is to prevent the analyzer from accessing internal
or local services when a user submits a URL.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests


REQUEST_TIMEOUT = 10
MAX_RESPONSE_SIZE = 2 * 1024 * 1024


def is_private_or_unsafe_ip(ip):
    """
    Determine whether an IP address should not be accessed.

    We block:
    - private addresses
    - loopback
    - link-local
    - multicast
    - reserved
    - unspecified addresses
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    except ValueError:
        return True


def resolve_hostname(hostname):
    """
    Resolve a hostname into IP addresses.

    This lets us inspect where the hostname actually points
    before making an HTTP request.
    """

    addresses = set()

    try:

        results = socket.getaddrinfo(
            hostname,
            None
        )

        for result in results:

            ip = result[4][0]

            addresses.add(ip)

    except socket.gaierror:

        return []

    return sorted(addresses)


def validate_url(url):
    """
    Validate a URL before making a network request.

    Returns a dictionary describing whether the destination
    is considered safe for the analyzer.
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:

        return {
            "safe": False,
            "reason": "Only HTTP and HTTPS are allowed"
        }

    if not parsed.hostname:

        return {
            "safe": False,
            "reason": "Missing hostname"
        }

    hostname = parsed.hostname

    addresses = resolve_hostname(hostname)

    if not addresses:

        return {
            "safe": False,
            "reason": "Hostname could not be resolved"
        }

    unsafe_addresses = []

    for ip in addresses:

        if is_private_or_unsafe_ip(ip):
            unsafe_addresses.append(ip)

    if unsafe_addresses:

        return {
            "safe": False,
            "reason": "Destination resolves to restricted IP",
            "resolved_ips": addresses,
            "blocked_ips": unsafe_addresses
        }

    return {
        "safe": True,
        "hostname": hostname,
        "resolved_ips": addresses
    }


def safe_get(url):
    """
    Perform an HTTP GET only after validating the destination.

    The response is limited to MAX_RESPONSE_SIZE bytes.
    """

    validation = validate_url(url)

    if not validation["safe"]:

        return {
            "success": False,
            "blocked": True,
            "validation": validation
        }

    try:

        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={
                "User-Agent":
                "AI-Phishing-Detection-Analyzer/1.0"
            },
            stream=True
        )

        content = response.raw.read(
            MAX_RESPONSE_SIZE + 1
        )

        if len(content) > MAX_RESPONSE_SIZE:

            response.close()

            return {
                "success": False,
                "blocked": True,
                "reason": "Response exceeds size limit"
            }

        response._content = content

        response.close()

        return {
            "success": True,
            "blocked": False,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content": content
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "blocked": False,
            "error": str(error)
        }


if __name__ == "__main__":

    tests = [
        "https://example.com",
        "http://127.0.0.1",
        "http://192.168.1.1"
    ]

    for test_url in tests:

        print("\nURL:", test_url)

        result = validate_url(test_url)

        print(result)
