"""
Streamlit dashboard for the phishing detection platform.
"""

import requests
import streamlit as st


API_URL = "http://127.0.0.1:8000/analyze/url"


st.set_page_config(
    page_title="AI Phishing Detection",
    layout="wide"
)


st.title(
    "AI-Powered Multi-Layer Phishing Detection"
)

st.write(
    "Analyze URLs using multiple security intelligence layers."
)


url = st.text_input(
    "Enter a URL"
)


if st.button("Analyze URL"):

    if not url:

        st.warning(
            "Please enter a URL."
        )

    else:

        try:

            response = requests.post(
                API_URL,
                json={
                    "url": url
                },
                timeout=60
            )

            response.raise_for_status()

            result = response.json()

            risk = result["risk"]

            st.metric(
                "Risk Score",
                risk["risk_score"]
            )

            st.metric(
                "Risk Level",
                risk["risk_level"]
            )

            st.subheader(
                "Security Signals"
            )

            for signal in risk["signals"]:

                st.write(
                    f"**{signal['name']}** — "
                    f"{signal['reason']}"
                )

            st.subheader(
                "Explanation"
            )

            st.json(
                result["explanation"]
            )

        except Exception as error:

            st.error(
                f"Analysis failed: {error}"
            )
