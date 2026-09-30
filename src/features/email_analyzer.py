"""
Email Phishing Analysis Module

This module analyzes an .eml email and extracts important
header-level security signals.

It checks:
- From
- Reply-To
- Return-Path
- To
- Cc
- Subject
- Message-ID
- Received headers
- Display-name vs email address
- From vs Reply-To mismatch

Later we will add:
- SPF
- DKIM
- DMARC
- Hidden URLs
- Attachments
- NLP/BEC analysis
"""


import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


def parse_email_file(file_path):
    """
    Read an .eml file and convert it into an EmailMessage object.

    BytesParser is used because .eml files can contain
    encoded headers and MIME attachments.
    """

    with open(file_path, "rb") as email_file:

        message = BytesParser(
            policy=policy.default
        ).parse(email_file)

    return message


def extract_email_address(header_value):
    """
    Extract the actual email address from a header.

    Example:

        "Microsoft Support <support@example.com>"

    becomes:

        "support@example.com"
    """

    if not header_value:
        return ""

    # parseaddr separates display name and email address.
    _, email_address = parseaddr(header_value)

    return email_address.lower().strip()


def extract_display_name(header_value):
    """
    Extract the display name from an email header.

    Example:

        "Microsoft Support <support@example.com>"

    returns:

        "Microsoft Support"
    """

    if not header_value:
        return ""

    display_name, _ = parseaddr(header_value)

    return display_name.strip()


def analyze_display_name_mismatch(from_header):
    """
    Detect whether the display name contains a brand-like name
    while the actual email address belongs to another domain.

    This is a signal only, not proof of phishing.
    """

    display_name = extract_display_name(from_header)
    email_address = extract_email_address(from_header)

    if not display_name or not email_address:
        return {
            "display_name": display_name,
            "email_address": email_address,
            "possible_mismatch": False
        }

    # Extract domain from the email address.
    email_domain = email_address.split("@")[-1]

    # Check whether the display name contains common
    # organization/security terms.
    suspicious_names = [
        "microsoft",
        "paypal",
        "google",
        "amazon",
        "apple",
        "netflix",
        "bank",
        "security",
        "support",
        "administrator"
    ]

    display_lower = display_name.lower()

    possible_mismatch = any(
        name in display_lower
        and name not in email_domain.lower()
        for name in suspicious_names
    )

    return {
        "display_name": display_name,
        "email_address": email_address,
        "email_domain": email_domain,
        "possible_mismatch": possible_mismatch
    }


def analyze_email_headers(message):
    """
    Extract important email headers and calculate
    basic mismatch signals.
    """

    from_header = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")

    from_email = extract_email_address(from_header)
    reply_email = extract_email_address(reply_to)
    return_email = extract_email_address(return_path)

    # Compare From and Reply-To domains.
    from_domain = (
        from_email.split("@")[-1]
        if "@" in from_email
        else ""
    )

    reply_domain = (
        reply_email.split("@")[-1]
        if "@" in reply_email
        else ""
    )

    reply_to_mismatch = (
        bool(from_domain)
        and bool(reply_domain)
        and from_domain != reply_domain
    )

    result = {
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,

        "to": message.get("To", ""),
        "cc": message.get("Cc", ""),
        "subject": message.get("Subject", ""),

        "message_id": message.get(
            "Message-ID",
            ""
        ),

        "date": message.get(
            "Date",
            ""
        ),

        "from_email": from_email,
        "reply_to_email": reply_email,
        "return_path_email": return_email,

        "from_domain": from_domain,
        "reply_to_domain": reply_domain,

        "reply_to_domain_mismatch": reply_to_mismatch,

        "received_headers": message.get_all(
            "Received",
            []
        )
    }

    # Add display-name analysis.
    result["display_name_analysis"] = (
        analyze_display_name_mismatch(
            from_header
        )
    )

    return result


def extract_email_body(message):
    """
    Extract plain-text and HTML portions of the email body.

    Multipart emails can contain both versions.
    """

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            # Ignore attachments for now.
            if part.get_content_disposition() == "attachment":
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                plain_text += content

            elif content_type == "text/html":
                html_text += content

    else:

        try:
            content = message.get_content()
        except Exception:
            content = ""

        if message.get_content_type() == "text/plain":
            plain_text = content

        elif message.get_content_type() == "text/html":
            html_text = content

    return {
        "plain_text": plain_text,
        "html": html_text
    }


def analyze_email(file_path):
    """
    Run the complete email analysis pipeline.

    This combines:
    1. Email parsing
    2. Header analysis
    3. Body extraction
    """

    message = parse_email_file(file_path)

    headers = analyze_email_headers(message)

    body = extract_email_body(message)

    return {
        "headers": headers,
        "body": body
    }


def main():
    """
    Command-line test.

    Change TEST_EMAIL to the path of your .eml file.
    """

    TEST_EMAIL = "data/raw/test_email.eml"

    result = analyze_email(TEST_EMAIL)

    print("\n========== EMAIL HEADERS ==========")

    for key, value in result["headers"].items():
        print(f"\n{key}: {value}")

    print("\n========== EMAIL BODY ==========")

    print(
        "\nPlain text length:",
        len(result["body"]["plain_text"])
    )

    print(
        "HTML length:",
        len(result["body"]["html"])
    )


if __name__ == "__main__":
    main()
