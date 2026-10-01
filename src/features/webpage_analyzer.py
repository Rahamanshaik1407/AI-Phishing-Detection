"""
Webpage analysis module.

This module fetches a webpage and extracts security-relevant
HTML characteristics.

IMPORTANT:
This is analysis only. It does not submit credentials,
interact with forms, or execute page JavaScript.
"""

import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# Limit the amount of data downloaded from a webpage.
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB

# Prevent the analyzer from following an unlimited number of redirects.
MAX_REDIRECTS = 5

# Network timeout for HTTP requests.
REQUEST_TIMEOUT = 10


def fetch_webpage(url):
    """
    Fetch a webpage using a controlled HTTP request.

    Returns:
        Response object or None if the request fails.

    Security:
        - Uses a timeout.
        - Limits redirects.
        - Uses a response-size limit.
    """

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={
                "User-Agent": "AI-Phishing-Detection-Analyzer/1.0"
            },
            stream=True,
        )

        # Reject very large responses before downloading them.
        content_length = response.headers.get("Content-Length")

        if content_length:

            try:
                if int(content_length) > MAX_RESPONSE_SIZE:
                    response.close()
                    return None
            except ValueError:
                pass

        # Read only the allowed amount of data.
        content = response.raw.read(MAX_RESPONSE_SIZE + 1)

        if len(content) > MAX_RESPONSE_SIZE:
            response.close()
            return None

        response._content = content
        response.close()

        return response

    except requests.RequestException:
        return None


def extract_forms(soup):
    """
    Extract HTML form information.

    Forms are important because phishing pages commonly
    request credentials or other sensitive information.
    """

    forms = []

    for form in soup.find_all("form"):

        action = form.get("action", "")

        method = form.get("method", "get").lower()

        inputs = []

        for input_tag in form.find_all("input"):

            inputs.append({
                "type": input_tag.get("type", "text").lower(),
                "name": input_tag.get("name"),
            })

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def count_password_fields(soup):
    """
    Count password input fields on the webpage.
    """

    count = 0

    for input_tag in soup.find_all("input"):

        input_type = input_tag.get("type", "").lower()

        if input_type == "password":
            count += 1

    return count


def extract_links(soup, base_url):
    """
    Extract links from the webpage.

    Relative URLs are converted to absolute URLs.
    """

    links = []

    for anchor in soup.find_all("a", href=True):

        href = anchor.get("href")

        absolute_url = urljoin(base_url, href)

        links.append({
            "text": anchor.get_text(" ", strip=True),
            "url": absolute_url,
        })

    return links


def extract_external_resources(soup, base_url):
    """
    Identify external resources such as:
    - scripts
    - stylesheets
    - images
    - iframes

    These are signals for further analysis, not proof
    of malicious behavior.
    """

    base_hostname = urlparse(base_url).hostname

    resources = []

    # JavaScript files.
    for script in soup.find_all("script", src=True):

        url = urljoin(base_url, script["src"])

        resources.append({
            "type": "script",
            "url": url,
            "external": urlparse(url).hostname != base_hostname,
        })

    # Stylesheets.
    for link in soup.find_all("link", href=True):

        rel = link.get("rel", [])

        if "stylesheet" in rel:

            url = urljoin(base_url, link["href"])

            resources.append({
                "type": "stylesheet",
                "url": url,
                "external": urlparse(url).hostname != base_hostname,
            })

    # Images.
    for image in soup.find_all("img", src=True):

        url = urljoin(base_url, image["src"])

        resources.append({
            "type": "image",
            "url": url,
            "external": urlparse(url).hostname != base_hostname,
        })

    # Iframes.
    for iframe in soup.find_all("iframe", src=True):

        url = urljoin(base_url, iframe["src"])

        resources.append({
            "type": "iframe",
            "url": url,
            "external": urlparse(url).hostname != base_hostname,
        })

    return resources


def detect_suspicious_html_patterns(html):
    """
    Look for common suspicious HTML patterns.

    These indicators are intentionally broad.
    They should later be combined with other evidence.
    """

    patterns = {
        "javascript_obfuscation": [
            r"eval\s*\(",
            r"atob\s*\(",
            r"fromCharCode\s*\(",
        ],

        "credential_language": [
            r"verify\s+your\s+account",
            r"confirm\s+your\s+identity",
            r"enter\s+your\s+password",
            r"sign\s+in",
            r"login",
        ],
    }

    matches = []

    html_lower = html.lower()

    for category, expressions in patterns.items():

        for expression in expressions:

            if re.search(expression, html_lower):

                matches.append({
                    "category": category,
                    "pattern": expression,
                })

    return matches


def analyze_webpage(url):
    """
    Perform complete webpage analysis.

    Returns structured information that can later be
    combined with URL, domain, reputation and ML signals.
    """

    response = fetch_webpage(url)

    if response is None:

        return {
            "url": url,
            "fetch_success": False,
            "error": "Unable to safely fetch webpage",
        }

    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    # We only parse HTML responses.
    if "html" not in content_type:

        return {
            "url": url,
            "fetch_success": True,
            "is_html": False,
            "status_code": response.status_code,
            "content_type": content_type,
        }

    html = response.text

    soup = BeautifulSoup(html, "html.parser")

    forms = extract_forms(soup)

    password_fields = count_password_fields(soup)

    links = extract_links(soup, url)

    resources = extract_external_resources(
        soup,
        url
    )

    suspicious_patterns = detect_suspicious_html_patterns(
        html
    )

    return {
        "url": url,
        "fetch_success": True,
        "is_html": True,

        "status_code": response.status_code,

        "content_type": content_type,

        "title": (
            soup.title.get_text(strip=True)
            if soup.title
            else None
        ),

        "page_size": len(html),

        "form_count": len(forms),

        "password_field_count": password_fields,

        "forms": forms,

        "link_count": len(links),

        "links": links,

        "resource_count": len(resources),

        "external_resource_count": sum(
            1 for resource in resources
            if resource["external"]
        ),

        "iframe_count": len(
            soup.find_all("iframe")
        ),

        "script_count": len(
            soup.find_all("script")
        ),

        "suspicious_html_patterns": suspicious_patterns,
    }


def print_webpage_analysis(result):
    """
    Print webpage analysis in a readable format.
    """

    print("\n" + "=" * 60)
    print("WEBPAGE ANALYSIS")
    print("=" * 60)

    for key, value in result.items():

        # Avoid printing huge link/resource structures
        # directly to the terminal.
        if key in {"links", "forms"}:
            print(f"\n{key}: {len(value)} item(s)")
        else:
            print(f"\n{key}: {value}")

    print("\n" + "=" * 60)


if __name__ == "__main__":

    # Use a URL you are authorized to analyze.
    TEST_URL = "https://example.com"

    result = analyze_webpage(TEST_URL)

    print_webpage_analysis(result)
