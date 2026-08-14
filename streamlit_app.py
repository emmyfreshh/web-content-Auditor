import json
from urllib.parse import urlparse

import requests
import streamlit as st

from auditor_agent import ContentAuditorAgent


def display_result(result):
    st.subheader("Result")

    if result.decision == "accept":
        st.success(f"Safe: {result.decision.upper()}")
    else:
        st.error(f"Risky: {result.decision.upper()}")

    st.metric("Risk Score", f"{result.risk_score:.2f}")
    st.metric("Confidence", f"{result.confidence:.2f}")

    st.write(result.final_rationale)

    with st.expander("Why this decision was made", expanded=True):
        for step in result.steps:
            st.markdown(f"### Step {step.step}: {step.selected_tool}")
            st.write(step.selection_reason)
            st.write(step.result.summary)

            if step.result.details:
                st.json(step.result.details)


st.set_page_config(
    page_title="Web Content Auditor",
    page_icon="🛡️",
    layout="centered",
)

st.title("Web Content Auditor")
st.caption("Check HTML pages, user-submitted text, or API responses for suspicious content.")

input_type = st.radio(
    "Choose input type",
    ["HTML Page", "User Text", "API Response"],
    horizontal=True,
)

if input_type == "HTML Page":
    source_url = st.text_input(
        "Website URL",
        value="https://example.com",
        help="Paste the page you want to inspect.",
    )

    if st.button("Check Website", use_container_width=True):
        parsed = urlparse(source_url)

        if not parsed.scheme or not parsed.netloc:
            st.warning("Please enter a valid website URL, for example: https://example.com")
            st.stop()

        try:
            with st.spinner("Loading page and analyzing content..."):
                response = requests.get(source_url, timeout=10)
                response.raise_for_status()
                content = response.text

                agent = ContentAuditorAgent()
                result = agent.audit(
                    content=content,
                    content_id="html-check",
                    source_url=source_url,
                )

            display_result(result)

        except requests.exceptions.RequestException as exc:
            st.warning("The website could not be reached. Please check the URL and try again.")
            st.caption(f"Details: {exc}")

elif input_type == "User Text":
    content = st.text_area(
        "Paste the text to check",
        height=250,
        value="This is a normal website signup message with contact details.",
        help="This can be a comment, message, form content, or plain user input.",
    )

    if st.button("Check Text", use_container_width=True):
        if not content.strip():
            st.warning("Please enter some text to analyze.")
            st.stop()

        with st.spinner("Analyzing text..."):
            agent = ContentAuditorAgent()
            result = agent.audit(
                content=content,
                content_id="text-check",
                source_url=None,
            )

        display_result(result)

else:
    content = st.text_area(
        "Paste API response JSON or text",
        height=250,
        value='{"status":"ok","message":"welcome","token":"abc123","payload":{"user":"demo"}}',
        help="Paste a JSON response, raw API output, or text returned by a service.",
    )

    if st.button("Check API Response", use_container_width=True):
        if not content.strip():
            st.warning("Please paste a response first.")
            st.stop()

        text_to_check = content

        try:
            parsed = json.loads(content)
            text_to_check = json.dumps(parsed, indent=2)
        except Exception:
            pass

        with st.spinner("Analyzing API response..."):
            agent = ContentAuditorAgent()
            result = agent.audit(
                content=text_to_check,
                content_id="api-check",
                source_url=None,
            )

        display_result(result)