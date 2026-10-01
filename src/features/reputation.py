"""
VirusTotal Threat Intelligence Module

Supports:
1. URL reputation lookup
2. File hash reputation lookup (MD5, SHA-1, SHA-256)
3. Local file hash reputation lookup

IMPORTANT:
- VirusTotal is an enrichment source. Its result must NOT be treated
  as the sole phishing/malware decision.
- VirusTotal queries MUST remain strictly server-side.
- The VIRUSTOTAL_API_KEY must never be sent to the client/browser.
"""

import os
import re
import base64
import hashlib
import requests
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# Read the API key from environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API base URL
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Hash validation regexes
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def get_headers():
    """
    Create HTTP headers required by VirusTotal.

    Returns:
        Dictionary containing the API key.
    """
    return {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY", "")
    }


def is_valid_hash(hash_value: str) -> bool:
    """
    Validate that an input string is an MD5, SHA-1, or SHA-256 hash.
    """
    if not isinstance(hash_value, str):
        return False
    cleaned = hash_value.strip()
    return bool(
        MD5_REGEX.match(cleaned)
        or SHA1_REGEX.match(cleaned)
        or SHA256_REGEX.match(cleaned)
    )


def encode_url_for_virustotal(url: str) -> str:
    """
    Convert a URL into VirusTotal's URL identifier.
    VirusTotal uses URL-safe Base64 without '=' padding.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def get_url_reputation(url: str) -> dict:
    """
    Look up a URL in VirusTotal.
    Returns vendor analysis statistics.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "success": False,
            "type": "url",
            "url": url,
            "error": "VIRUSTOTAL_API_KEY not configured"
        }

    url_id = encode_url_for_virustotal(url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15
        )

        # 404 indicates VirusTotal has no existing record for this URL
        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "type": "url",
                "url": url,
                "message": "URL not observed in VirusTotal database"
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "success": True,
            "found": True,
            "type": "url",
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {})
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "type": "url",
            "url": url,
            "error": str(error)
        }


def get_hash_reputation(hash_value: str) -> dict:
    """
    Query VirusTotal directly by cryptographic hash (MD5, SHA-1, or SHA-256).

    IMPORTANT:
    Does NOT upload files. Only performs threat intelligence lookup on the hash.
    A hash not found in VirusTotal must NOT automatically be considered clean.
    """
    if not isinstance(hash_value, str):
        return {
            "success": False,
            "type": "hash",
            "error": "Hash value must be a string"
        }

    cleaned_hash = hash_value.strip().lower()

    if not is_valid_hash(cleaned_hash):
        return {
            "success": False,
            "type": "hash",
            "hash": cleaned_hash,
            "error": "Invalid hash format (must be MD5, SHA-1, or SHA-256 hexadecimal)"
        }

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "success": False,
            "type": "hash",
            "hash": cleaned_hash,
            "error": "VIRUSTOTAL_API_KEY not configured"
        }

    endpoint = f"{VT_BASE_URL}/files/{cleaned_hash}"

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=15
        )

        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
                "type": "hash",
                "hash": cleaned_hash,
                "message": "Hash not observed in VirusTotal threat feed (Unknown Status)"
            }

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "success": True,
            "found": True,
            "type": "hash",
            "hash": cleaned_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "meaningful_name": attributes.get("meaningful_name"),
            "tags": attributes.get("tags", [])
        }

    except requests.RequestException as error:
        return {
            "success": False,
            "type": "hash",
            "hash": cleaned_hash,
            "error": str(error)
        }


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA-256 for a file in chunks to minimize memory consumption.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def get_file_reputation(file_path: str) -> dict:
    """
    Calculate a local file's SHA-256 hash and query VirusTotal for an existing analysis.

    IMPORTANT:
    Does NOT upload the file. Searches VirusTotal strictly by SHA-256 hash.
    """
    if not os.path.exists(file_path):
        return {
            "success": False,
            "type": "file",
            "error": f"File not found: {file_path}"
        }

    sha256 = calculate_sha256(file_path)
    result = get_hash_reputation(sha256)

    # Set type to 'file' and preserve file path context
    result["type"] = "file"
    result["sha256"] = sha256
    result["file_path"] = file_path
    return result


def main():
    """
    Test URL, hash, and file reputation lookups.
    """
    test_url = "https://example.com"
    print("\n========== URL REPUTATION ==========")
    print(get_url_reputation(test_url))

    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # Example harmless MD5
    print("\n========== HASH REPUTATION ==========")
    print(get_hash_reputation(test_hash))


if __name__ == "__main__":
    main()
