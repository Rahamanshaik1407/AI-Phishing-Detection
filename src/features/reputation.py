"""
VirusTotal Threat Intelligence Module

Supports:

1. URL reputation lookup
2. File hash reputation lookup

IMPORTANT:
VirusTotal is an enrichment source.
Its result must NOT be treated as the only
phishing/malware decision.
"""

import os
import base64
import hashlib

import requests
from dotenv import load_dotenv


# Load variables from .env.
load_dotenv()


# Read the API key without hard-coding it in source code.
VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)

# VirusTotal API base URL.
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_headers():
    """
    Create HTTP headers required by VirusTotal.

    Returns:
        Dictionary containing the API key.
    """

    return {
        "x-apikey": VIRUSTOTAL_API_KEY
    }


def encode_url_for_virustotal(url):
    """
    Convert a URL into VirusTotal's URL identifier.

    VirusTotal uses URL-safe Base64 without '=' padding.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded.rstrip("=")


def get_url_reputation(url):
    """
    Look up a URL in VirusTotal.

    Returns vendor analysis statistics.
    """

    if not VIRUSTOTAL_API_KEY:
        return {
            "success": False,
            "error": "VIRUSTOTAL_API_KEY not configured"
        }

    url_id = encode_url_for_virustotal(url)

    endpoint = (
        f"{VT_BASE_URL}/urls/{url_id}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15
        )

        # A 404 can mean VirusTotal has no existing
        # analysis for the requested URL.
        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "type": "url",
                "url": url
            }

        response.raise_for_status()

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "success": True,
            "found": True,
            "type": "url",
            "url": url,

            "malicious": stats.get(
                "malicious", 0
            ),

            "suspicious": stats.get(
                "suspicious", 0
            ),

            "harmless": stats.get(
                "harmless", 0
            ),

            "undetected": stats.get(
                "undetected", 0
            ),

            "timeout": stats.get(
                "timeout", 0
            ),

            "reputation": attributes.get(
                "reputation"
            )
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "type": "url",
            "error": str(error)
        }


def calculate_sha256(file_path):
    """
    Calculate SHA-256 for a file.

    The file is read in chunks so large files
    do not need to be loaded completely into memory.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_reputation(file_path):
    """
    Calculate a file's SHA-256 hash and query
    VirusTotal for an existing analysis.

    IMPORTANT:
    This function does NOT upload the file.

    It only searches VirusTotal using the hash.
    """

    if not VIRUSTOTAL_API_KEY:
        return {
            "success": False,
            "error": "VIRUSTOTAL_API_KEY not configured"
        }

    # Calculate the file's cryptographic hash.
    sha256 = calculate_sha256(
        file_path
    )

    endpoint = (
        f"{VT_BASE_URL}/files/{sha256}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15
        )

        # File hash is unknown to VirusTotal.
        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "type": "file",
                "sha256": sha256
            }

        response.raise_for_status()

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "success": True,
            "found": True,
            "type": "file",
            "sha256": sha256,

            "malicious": stats.get(
                "malicious", 0
            ),

            "suspicious": stats.get(
                "suspicious", 0
            ),

            "harmless": stats.get(
                "harmless", 0
            ),

            "undetected": stats.get(
                "undetected", 0
            ),

            "timeout": stats.get(
                "timeout", 0
            ),

            "reputation": attributes.get(
                "reputation"
            ),

            "file_type": attributes.get(
                "type_description"
            ),

            "file_size": attributes.get(
                "size"
            )
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "type": "file",
            "sha256": sha256,
            "error": str(error)
        }


def main():
    """
    Test both URL and file reputation lookup.
    """

    test_url = "https://example.com"

    print("\n========== URL REPUTATION ==========")

    url_result = get_url_reputation(
        test_url
    )

    print(url_result)

    # Change this to a harmless local test file.
    test_file = "data/raw/test_attachment.pdf"

    if os.path.exists(test_file):

        print(
            "\n========== FILE REPUTATION =========="
        )

        file_result = get_file_reputation(
            test_file
        )

        print(file_result)

    else:

        print(
            "\nTest attachment not found."
        )


if __name__ == "__main__":
    main()
