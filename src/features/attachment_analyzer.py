"""
Email Attachment Analyzer

Safely performs STATIC analysis of email attachments.

It checks:
- Filename
- Extension
- MIME type
- File size
- Magic/signature bytes
- SHA-256 hash
- Potential macro-enabled Office files
- Suspicious extensions

IMPORTANT:
This module DOES NOT execute attachments.
Dynamic malware analysis will be handled later inside
an isolated sandbox.
"""

import hashlib
import mimetypes
from pathlib import Path


# Extensions that deserve additional inspection.
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".hta",
    ".msi",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
}

# Microsoft Office formats capable of containing VBA macros.
MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
    ".ppsm",
}


def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.

    The file is read in chunks so that large attachments
    do not need to be loaded completely into memory.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            # Read a manageable chunk.
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_signature(file_path):
    """
    Read the first few bytes of a file.

    Magic/signature bytes help determine the actual
    file type instead of trusting only the extension.
    """

    with open(file_path, "rb") as file:
        return file.read(16)


def detect_file_type(file_path):
    """
    Determine basic file information using the filename
    and MIME-type database.
    """

    path = Path(file_path)

    extension = path.suffix.lower()

    mime_type, _ = mimetypes.guess_type(
        path.name
    )

    return {
        "filename": path.name,
        "extension": extension,
        "mime_type": mime_type or "unknown",
    }


def analyze_attachment(file_path):
    """
    Perform complete static attachment analysis.

    No code from the attachment is executed.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    # Get basic file metadata.
    file_info = detect_file_type(
        file_path
    )

    # Determine file size in bytes.
    file_size = path.stat().st_size

    # Calculate cryptographic hash.
    sha256 = calculate_sha256(
        file_path
    )

    # Read magic/signature bytes.
    signature = get_file_signature(
        file_path
    )

    extension = file_info["extension"]

    return {
        "filename": file_info["filename"],
        "extension": extension,
        "mime_type": file_info["mime_type"],
        "size_bytes": file_size,
        "sha256": sha256,

        # Store the signature in hexadecimal form
        # for later file-type identification.
        "magic_bytes": signature.hex(),

        # Flag potentially dangerous extensions.
        "suspicious_extension": (
            extension in SUSPICIOUS_EXTENSIONS
        ),

        # Flag Office files that may contain macros.
        "macro_enabled": (
            extension in MACRO_ENABLED_EXTENSIONS
        ),
    }


def main():
    """
    Test the attachment analyzer.

    Change TEST_FILE to an attachment available
    in your project.
    """

    TEST_FILE = "data/raw/test_attachment.pdf"

    result = analyze_attachment(
        TEST_FILE
    )

    print("\n========== ATTACHMENT ANALYSIS ==========")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
