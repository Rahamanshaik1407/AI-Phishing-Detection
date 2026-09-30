"""
Domain Intelligence Module

Purpose:
    Extract domain-level intelligence from a URL.

Current capabilities:
    1. Extract hostname
    2. Extract registrable domain
    3. Extract subdomain
    4. Extract TLD
    5. Detect whether hostname is an IP address
    6. Resolve DNS records to IP addresses
    7. Identify IPv4 / IPv6 addresses
    8. Calculate basic domain characteristics

This module is intentionally passive.
It does NOT perform:
    - Port scanning
    - Vulnerability scanning
    - Exploitation
    - Brute forcing
"""


import socket
import ipaddress
from urllib.parse import urlparse

import tldextract


# ================================================================
# Configuration
# ================================================================

# Number of DNS addresses to retain in the result.
MAX_DNS_RESULTS = 20


# ================================================================
# URL normalization
# ================================================================

def normalize_url(url):
    """
    Normalize a URL before parsing.

    Why:
        Many URLs in our dataset do not contain http:// or https://.

    Example:
        example.com/login
        ->
        http://example.com/login
    """

    # Convert input to string and remove surrounding whitespace.
    url = str(url).strip()

    # Return empty string if no URL was supplied.
    if not url:
        return ""

    # Add a default scheme when one is missing.
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


# ================================================================
# Hostname extraction
# ================================================================

def extract_hostname(url):
    """
    Extract the hostname from a URL.

    Example:
        https://login.example.com/account
        ->
        login.example.com
    """

    # Normalize the URL before parsing.
    normalized_url = normalize_url(url)

    # Parse the URL.
    parsed = urlparse(normalized_url)

    # Return hostname in lowercase.
    return (parsed.hostname or "").lower()


# ================================================================
# IP address detection
# ================================================================

def detect_ip_address(hostname):
    """
    Determine whether a hostname is an IPv4 or IPv6 address.

    Returns:
        Tuple:
            (is_ip, ip_version)

    Examples:
        192.168.1.1 -> (True, 4)
        2001:db8::1 -> (True, 6)
        example.com -> (False, None)
    """

    try:
        # Try to interpret the hostname as an IP address.
        ip = ipaddress.ip_address(hostname)

        # Return the IP version.
        return True, ip.version

    except ValueError:
        # Hostname is not an IP address.
        return False, None


# ================================================================
# Domain parsing
# ================================================================

def parse_domain(hostname):
    """
    Extract subdomain, registrable domain, and TLD.

    Example:
        login.secure.example.com

        subdomain:
            login.secure

        registrable domain:
            example.com

        TLD:
            com
    """

    # tldextract separates:
    #   subdomain
    #   domain
    #   suffix
    extracted = tldextract.extract(hostname)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # Construct the registrable domain.
    if domain and suffix:
        registrable_domain = f"{domain}.{suffix}"
    else:
        registrable_domain = domain

    return {
        "subdomain": subdomain,
        "domain": domain,
        "tld": suffix,
        "registrable_domain": registrable_domain
    }


# ================================================================
# DNS resolution
# ================================================================

def resolve_dns(hostname):
    """
    Resolve a hostname to IP addresses.

    This performs normal DNS resolution only.

    Returns:
        Dictionary containing IPv4 and IPv6 addresses.
    """

    ipv4_addresses = set()
    ipv6_addresses = set()

    # Do not attempt DNS resolution for an empty hostname.
    if not hostname:
        return {
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "dns_resolution_success": False
        }

    try:
        # getaddrinfo retrieves available address records.
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        # Process every returned DNS result.
        for result in results:

            address_family = result[0]
            address = result[4][0]

            if address_family == socket.AF_INET:
                ipv4_addresses.add(address)

            elif address_family == socket.AF_INET6:
                ipv6_addresses.add(address)

    except socket.gaierror:
        # DNS resolution failed.
        return {
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "dns_resolution_success": False
        }

    # Limit results so one hostname cannot create
    # an unexpectedly large result.
    ipv4_list = sorted(ipv4_addresses)[:MAX_DNS_RESULTS]
    ipv6_list = sorted(ipv6_addresses)[:MAX_DNS_RESULTS]

    return {
        "ipv4_addresses": ipv4_list,
        "ipv6_addresses": ipv6_list,
        "dns_resolution_success": bool(
            ipv4_list or ipv6_list
        )
    }


# ================================================================
# Basic domain characteristics
# ================================================================

def calculate_domain_characteristics(
    hostname,
    registrable_domain,
    subdomain
):
    """
    Calculate basic structural characteristics of a domain.

    These features can later be supplied to our ML/risk engine.
    """

    # Count the number of dots in the hostname.
    dot_count = hostname.count(".")

    # Count hostname characters.
    hostname_length = len(hostname)

    # Count subdomain labels.
    if subdomain:
        subdomain_count = len(
            subdomain.split(".")
        )
    else:
        subdomain_count = 0

    # Count hyphens in the hostname.
    hyphen_count = hostname.count("-")

    # Count numeric characters.
    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    # Determine whether the hostname contains
    # suspiciously long subdomain structure.
    long_subdomain = len(subdomain) >= 30

    # Determine whether the registrable domain
    # itself contains a hyphen.
    domain_has_hyphen = "-" in registrable_domain

    return {
        "hostname_length": hostname_length,
        "hostname_dot_count": dot_count,
        "subdomain_count": subdomain_count,
        "hostname_hyphen_count": hyphen_count,
        "hostname_digit_count": digit_count,
        "long_subdomain": long_subdomain,
        "domain_has_hyphen": domain_has_hyphen
    }


# ================================================================
# Main domain intelligence function
# ================================================================

def analyze_domain(url):
    """
    Perform complete domain intelligence analysis for one URL.

    Returns:
        Dictionary containing all extracted domain intelligence.
    """

    # Extract hostname from URL.
    hostname = extract_hostname(url)

    # Detect whether hostname itself is an IP address.
    is_ip, ip_version = detect_ip_address(hostname)

    # If hostname is a normal domain, parse its domain structure.
    if not is_ip:
        domain_info = parse_domain(hostname)

        subdomain = domain_info["subdomain"]
        registrable_domain = domain_info["registrable_domain"]
        tld = domain_info["tld"]
        domain = domain_info["domain"]

        # Calculate structural characteristics.
        characteristics = calculate_domain_characteristics(
            hostname,
            registrable_domain,
            subdomain
        )

        # Perform DNS resolution.
        dns_info = resolve_dns(hostname)

    else:
        # IP-based URL does not have normal domain components.
        domain = ""
        tld = ""
        subdomain = ""
        registrable_domain = ""

        characteristics = {
            "hostname_length": len(hostname),
            "hostname_dot_count": hostname.count("."),
            "subdomain_count": 0,
            "hostname_hyphen_count": hostname.count("-"),
            "hostname_digit_count": sum(
                character.isdigit()
                for character in hostname
            ),
            "long_subdomain": False,
            "domain_has_hyphen": False
        }

        # The hostname is already an IP address,
        # so DNS resolution is unnecessary.
        dns_info = {
            "ipv4_addresses": [hostname]
            if ip_version == 4 else [],
            "ipv6_addresses": [hostname]
            if ip_version == 6 else [],
            "dns_resolution_success": True
        }

    # Combine all intelligence into one dictionary.
    result = {
        "url": url,
        "hostname": hostname,
        "is_ip_address": is_ip,
        "ip_version": ip_version,
        "domain": domain,
        "registrable_domain": registrable_domain,
        "subdomain": subdomain,
        "tld": tld,
    }

    # Add structural characteristics.
    result.update(characteristics)

    # Add DNS information.
    result.update(dns_info)

    return result


# ================================================================
# Command-line testing
# ================================================================

def main():
    """
    Test the domain intelligence module using sample URLs.

    This allows us to verify the module before integrating it
    into the larger phishing detection pipeline.
    """

    test_urls = [
        "https://www.google.com",
        "https://login.example.com/account",
        "http://paypal.com.example.net/login",
        "http://192.168.1.10/login",
        "https://login.secure.account.example.co.uk",
    ]

    print("=" * 70)
    print("DOMAIN INTELLIGENCE TEST")
    print("=" * 70)

    # Analyze every test URL.
    for url in test_urls:

        print("\nURL:")
        print(url)

        result = analyze_domain(url)

        print("\nDomain intelligence:")

        for key, value in result.items():
            print(f"{key}: {value}")

        print("-" * 70)


# ================================================================
# Program entry point
# ================================================================

if __name__ == "__main__":
    main()
