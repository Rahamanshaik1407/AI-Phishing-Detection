"""
Email Authentication Analysis

Analyzes authentication results found inside an email's headers.

Checks:
- SPF
- DKIM
- DMARC

Important:
These results are signals, not final phishing decisions.
"""

import re


def extract_authentication_results(message):
    """
    Extract the Authentication-Results header.

    This header may contain results such as:

        spf=pass
        dkim=pass
        dmarc=fail

    Returns all Authentication-Results headers.
    """

    return message.get_all(
        "Authentication-Results",
        []
    )


def extract_auth_status(authentication_headers):
    """
    Extract SPF, DKIM and DMARC status from
    Authentication-Results headers.

    Possible values include:
        pass
        fail
        softfail
        neutral
        none
        temperror
        permerror
        unknown
    """

    # Combine multiple authentication headers into one string.
    combined_headers = " ".join(
        str(header)
        for header in authentication_headers
    ).lower()

    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    # Search for SPF result.
    spf_match = re.search(
        r"\bspf\s*=\s*([a-z]+)",
        combined_headers
    )

    if spf_match:
        result["spf"] = spf_match.group(1)

    # Search for DKIM result.
    dkim_match = re.search(
        r"\bdkim\s*=\s*([a-z]+)",
        combined_headers
    )

    if dkim_match:
        result["dkim"] = dkim_match.group(1)

    # Search for DMARC result.
    dmarc_match = re.search(
        r"\bdmarc\s*=\s*([a-z]+)",
        combined_headers
    )

    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1)

    return result


def calculate_authentication_signals(auth_status):
    """
    Convert authentication results into simple
    machine-learning/risk-engine signals.

    These values can later become features.
    """

    return {
        "spf_pass": auth_status["spf"] == "pass",
        "dkim_pass": auth_status["dkim"] == "pass",
        "dmarc_pass": auth_status["dmarc"] == "pass",

        "spf_fail": auth_status["spf"] == "fail",
        "dkim_fail": auth_status["dkim"] == "fail",
        "dmarc_fail": auth_status["dmarc"] == "fail",
    }


def analyze_email_authentication(message):
    """
    Perform complete authentication analysis.
    """

    headers = extract_authentication_results(message)

    status = extract_auth_status(headers)

    signals = calculate_authentication_signals(
        status
    )

    return {
        "authentication_headers": headers,
        "status": status,
        "signals": signals
    }


def main():
    """
    Simple standalone test.

    This creates a simulated Authentication-Results
    header so the module can be tested without
    contacting an external mail server.
    """

    test_headers = [
        "mx.example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; "
        "dmarc=fail header.from=example.com"
    ]

    class FakeMessage:
        """
        Small fake email object used for testing.
        """

        def get_all(self, header_name, default):
            return test_headers

    message = FakeMessage()

    result = analyze_email_authentication(
        message
    )

    print("\nAuthentication Results:")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
