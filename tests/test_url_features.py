from src.features.url_features import extract_url_features


def test_basic_extraction():

    url = "https://example.com/login"

    features = extract_url_features(url)

    assert features["url_length"] > 0
    assert features["uses_https"] == 1


def test_ip_detection():

    url = "http://192.0.2.10/login"

    features = extract_url_features(url)

    assert features["contains_ip"] == 1


def test_keyword_detection():

    url = "https://example.com/login/verify"

    features = extract_url_features(url)

    assert features["suspicious_keyword_count"] >= 2
