"""
Central URL Analysis Pipeline

Every URL entering the project should eventually pass
through this module.

Sources can include:
- Direct URL submission
- Email URLs
- QR-code URLs
- Attachment URLs
- Redirect destinations

The analyzer combines all available intelligence into
one structured result.
"""

from src.features.url_features import extract_url_features
from src.features.domain_intelligence import analyze_domain
from src.features.brand_intelligence import analyze_brand
from src.features.ip_intelligence import analyze_url_ip
from src.features.reputation import get_url_reputation
from src.features.redirect_analyzer import analyze_redirect_chain


def analyze_url(url):
    """
    Run the complete URL intelligence pipeline.

    Returns:
        A dictionary containing all available URL intelligence.
    """

    result = {
        "url": url
    }

    # -------------------------------------------------
    # 1. Lexical URL analysis
    # -------------------------------------------------

    try:
        result["url_features"] = (
            extract_url_features(url)
        )
    except Exception as error:
        result["url_features"] = {
            "error": str(error)
        }

    # -------------------------------------------------
    # 2. Domain intelligence
    # -------------------------------------------------

    try:
        result["domain_intelligence"] = (
            analyze_domain(url)
        )
    except Exception as error:
        result["domain_intelligence"] = {
            "error": str(error)
        }

    # -------------------------------------------------
    # 3. Brand intelligence
    # -------------------------------------------------

    try:
        result["brand_intelligence"] = (
            analyze_brand(url)
        )
    except Exception as error:
        result["brand_intelligence"] = {
            "error": str(error)
        }

    # -------------------------------------------------
    # 4. IP intelligence
    # -------------------------------------------------

    try:
        result["ip_intelligence"] = (
            analyze_url_ip(url)
        )
    except Exception as error:
        result["ip_intelligence"] = {
            "error": str(error)
        }

    # -------------------------------------------------
    # 5. VirusTotal reputation
    # -------------------------------------------------

    try:
        result["virustotal"] = (
            get_url_reputation(url)
        )
    except Exception as error:
        result["virustotal"] = {
            "error": str(error)
        }

    # -------------------------------------------------
    # 6. Redirect analysis
    # -------------------------------------------------

    try:
        result["redirect_analysis"] = (
            analyze_redirect_chain(url)
        )
    except Exception as error:
        result["redirect_analysis"] = {
            "error": str(error)
        }

    return result


def print_url_analysis(result):
    """
    Print URL intelligence in a human-readable format.

    This is useful during development because we can
    clearly understand what each detector discovered.
    """

    print("\n" + "=" * 70)
    print("                 URL SECURITY ANALYSIS")
    print("=" * 70)

    print("\n[URL]")
    print(result["url"])

    print("\n[URL FEATURES]")
    for key, value in result["url_features"].items():
        print(f"  {key}: {value}")

    print("\n[DOMAIN INTELLIGENCE]")
    for key, value in result[
        "domain_intelligence"
    ].items():
        print(f"  {key}: {value}")

    print("\n[BRAND INTELLIGENCE]")
    for key, value in result[
        "brand_intelligence"
    ].items():
        print(f"  {key}: {value}")

    print("\n[IP INTELLIGENCE]")
    for key, value in result[
        "ip_intelligence"
    ].items():
        print(f"  {key}: {value}")

    print("\n[VIRUSTOTAL]")
    for key, value in result[
        "virustotal"
    ].items():
        print(f"  {key}: {value}")

    print("\n[REDIRECT ANALYSIS]")
    for key, value in result[
        "redirect_analysis"
    ].items():
        print(f"  {key}: {value}")


def main():
    """
    Test the complete URL analysis pipeline.
    """

    test_url = (
        "https://paypal.com.example.net/login"
    )

    result = analyze_url(
        test_url
    )

    print_url_analysis(
        result
    )


if __name__ == "__main__":
    main()
