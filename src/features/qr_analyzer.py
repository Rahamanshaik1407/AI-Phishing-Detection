"""
QR Phishing Analyzer

Extracts URLs from QR codes.

The decoded URL is NOT analyzed separately.

Instead, it is passed into the existing URL analysis
pipeline so that the same:
- lexical
- domain
- brand
- IP
- reputation
- redirect
features can be applied.
"""

try:
    import cv2
except ImportError:
    cv2 = None  # Optional dependency, QR analysis will be unavailable


def decode_qr_code(image_path):
    """
    Read an image and attempt to decode a QR code.

    Returns:
        Decoded QR content, or None if no QR code is found.
    """

    # Load the image from disk.
    image = cv2.imread(image_path)

    if image is None:
        raise FileNotFoundError(
            f"Could not read image: {image_path}"
        )

    # Create OpenCV's QR detector.
    detector = cv2.QRCodeDetector()

    # Decode the QR code.
    data, points, _ = detector.detectAndDecode(
        image
    )

    if not data:
        return None

    return data


def analyze_qr_code(image_path):
    """
    Decode a QR code and determine whether
    the decoded content looks like a URL.
    """

    data = decode_qr_code(
        image_path
    )

    if not data:
        return {
            "success": False,
            "decoded_data": None,
            "is_url": False
        }

    is_url = data.lower().startswith(
        ("http://", "https://")
    )

    return {
        "success": True,
        "decoded_data": data,
        "is_url": is_url
    }


def main():
    """
    Test QR decoding.

    Change this path to a QR-code image.
    """

    image_path = "data/raw/test_qr.png"

    result = analyze_qr_code(
        image_path
    )

    print("\n========== QR ANALYSIS ==========")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
