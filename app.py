import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔐"
)

st.title("🔐 Phishing URL Detector")
st.write("Check URLs for suspicious patterns.")

st.warning(
    "This tool checks URL patterns only. "
    "It cannot guarantee that a website is safe."
)


def analyze_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return None, ["Please enter a URL."]

    if any(ord(char) < 32 for char in raw_url):
        return None, ["URL contains invalid characters."]

    if len(raw_url) > 2048:
        return None, ["URL is too long."]

    candidate = raw_url

    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
    except ValueError:
        return None, ["Invalid URL format."]

    if parsed.scheme not in ("http", "https"):
        return None, ["Only HTTP and HTTPS URLs are supported."]

    if not hostname or "." not in hostname:
        return None, ["Enter a valid-looking domain, e.g. example.com."]

    findings = []

    if parsed.username is not None or parsed.password is not None:
        findings.append(
            "The URL contains user information before the hostname."
        )

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        findings.append("The hostname is an IP address.")
    except ValueError:
        pass

    if "xn--" in hostname.lower():
        findings.append("The domain contains a punycode label.")

    if len(hostname) > 50:
        findings.append("The hostname is unusually long.")

    if hostname.count(".") >= 4:
        findings.append("The hostname has many subdomain levels.")

    if len(raw_url) > 100:
        findings.append("The URL is unusually long.")

    if parsed.scheme == "http":
        findings.append("The URL uses HTTP instead of HTTPS.")

    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "password", "signin", "banking"
    ]

    checked_text = (hostname + parsed.path).lower()

    matched = [
        word for word in suspicious_words
        if word in checked_text
    ]

    if matched:
        findings.append(
            "Sensitive-looking words found: " + ", ".join(matched)
        )

    if re.search(r"%[0-9a-fA-F]{2}", raw_url):
        findings.append("The URL contains encoded characters.")

    if not findings:
        findings.append("No configured suspicious patterns detected.")

    return parsed, findings


url = st.text_input(
    "Enter website URL",
    placeholder="https://example.com"
)

if st.button("Analyze URL"):
    parsed, findings = analyze_url(url)

    if parsed is None:
        st.error(findings[0])
    else:
        st.subheader("Analysis Results")

        if any(
            "IP address" in item
            or "user information" in item
            for item in findings
        ):
            st.error("High-priority warning: review this URL carefully.")
        elif findings == ["No configured suspicious patterns detected."]:
            st.info("No configured warning indicators detected.")
        else:
            st.warning("Suspicious indicators found. Review the URL.")

        st.write("**Hostname:**", parsed.hostname)
        st.write("**Protocol:**", parsed.scheme.upper())

        st.write("**Findings:**")

        for finding in findings:
            st.write("- " + finding)

        st.caption(
            "This educational tool uses simple rules, not a verified "
            "phishing database or a trained AI model. False positives "
            "and false negatives are possible."
        )
