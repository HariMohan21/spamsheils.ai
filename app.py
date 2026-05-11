import streamlit as st
import re
import pandas as pd
from datetime import datetime

from database import (
    create_database,
    save_scan,
    get_scan_history
)

st.set_page_config(
    page_title="SpamShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.main-title {
    font-size: 48px;
    font-weight: 800;
    color: #1f2937;
}
.subtitle {
    font-size: 18px;
    color: #4b5563;
}
.high-risk {
    padding: 20px;
    border-radius: 14px;
    background-color: #fee2e2;
    border-left: 8px solid #dc2626;
}
.medium-risk {
    padding: 20px;
    border-radius: 14px;
    background-color: #fef3c7;
    border-left: 8px solid #f59e0b;
}
.low-risk {
    padding: 20px;
    border-radius: 14px;
    background-color: #dcfce7;
    border-left: 8px solid #16a34a;
}
.reason-box {
    padding: 12px;
    border-radius: 10px;
    background-color: #f3f4f6;
    margin-bottom: 8px;
}
</style>
""", unsafe_allow_html=True)

create_database()


def detect_fraud_email(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    checks = [
        ("Urgency or pressure tactics", [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\b24\s*hours?\b",
            r"\bend of the week\b",
            r"\beod\b",
            r"\bfinal notice\b",
            r"\baction required\b",
            r"\bfailure to\b",
            r"\bpermanent suspension\b",
            r"\blast warning\b",
            r"\btime sensitive\b"
        ], 2),

        ("Account/security verification request", [
            r"\bverify\b.*\b(account|identity|login|password|information)\b",
            r"\bconfirm\b.*\b(account|identity|login|password|information)\b",
            r"\bupdate\b.*\b(account|identity|login|password|information)\b",
            r"\bsuspicious activity\b",
            r"\bunknown ip\b",
            r"\baccount.*restricted\b",
            r"\btemporarily restricted\b",
            r"\bsuspended\b",
            r"\blocked\b"
        ], 3),

        ("Financial/payment fraud indicators", [
            r"\binvoice\b",
            r"\boverdue\b",
            r"\bpayment\b",
            r"\bbanking instructions\b",
            r"\bwire transfer\b",
            r"\baccounts receivable\b",
            r"\bpayroll\b",
            r"\bcompensation\b",
            r"\bvendor\b",
            r"\brefund\b",
            r"\bdirect deposit\b",
            r"\btax refund\b"
        ], 3),

        ("Document signing or cloud-service impersonation", [
            r"\bdocusign\b",
            r"\badobesign\b",
            r"\badobe sign\b",
            r"\bsharepoint\b",
            r"\bonedrive\b",
            r"\bgoogle drive\b",
            r"\bdocument cloud\b",
            r"\bsecure document\b",
            r"\bsignature requested\b",
            r"\breview and sign\b",
            r"\bshared document\b",
            r"\bdownload document\b"
        ], 3),

        ("Link or verification call-to-action", [
            r"\bclick here\b",
            r"\bsecure link\b",
            r"\blogin here\b",
            r"\bcomplete verification\b",
            r"\bconfirm your details\b",
            r"\breview.*document\b",
            r"\bopen attachment\b",
            r"\bdownload now\b"
        ], 3),

        ("Generic greeting", [
            r"\bdear customer\b",
            r"\bdear valued customer\b",
            r"\bdear account holder\b",
            r"\bdear client\b",
            r"\bhello user\b"
        ], 2),

        ("Social engineering wording", [
            r"\bdo not reply\b",
            r"\bautomated message\b",
            r"\bto protect your\b",
            r"\bavoid.*suspension\b",
            r"\bavoid.*interruption\b",
            r"\bensure your records\b",
            r"\bprotect your funds\b",
            r"\bpersonal information\b"
        ], 2),
    ]

    for reason, patterns, points in checks:
        for pattern in patterns:
            if re.search(pattern, text_lower):
                score += points
                reasons.append(reason)
                break

    if re.search(r"\.(zip|exe|js|bat|scr|vbs|msi|rar|iso|html|hta)", text_lower):
        score += 4
        reasons.append("Risky attachment or executable file type detected")

    if re.search(r"from:.*(@.*[-_].*\.)", text_lower):
        score += 2
        reasons.append("Suspicious sender domain pattern detected")

    if re.search(r"\bsecurity[-_]?alert\b|\bverify[-_]?access\b|\baccount[-_]?support\b", text_lower):
        score += 2
        reasons.append("Sender appears to impersonate security support")

    if re.search(r"\$\d+|\b\d+\.\d{2}\b", text_lower):
        score += 2
        reasons.append("Mentions money amount or transaction value")

    all_caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(all_caps_words) >= 2:
        score += 2
        reasons.append("Excessive ALL CAPS wording detected")

    url_count = len(re.findall(r"http[s]?://|www\.", text_lower))
    if url_count >= 1:
        score += 3
        reasons.append("Contains external link or URL")

    reasons = list(dict.fromkeys(reasons))

    if score >= 9:
        result = "High Risk Fraud / Phishing"
        level = "high"
        recommendation = "Do not click links, open attachments, or reply. Verify through the official website or trusted contact."
    elif score >= 5:
        result = "Suspicious Email"
        level = "medium"
        recommendation = "Review carefully before taking action. Confirm sender identity using a trusted channel."
    else:
        result = "Likely Safe"
        level = "low"
        recommendation = "No strong fraud indicators detected, but always verify unexpected messages."

    return result, level, score, reasons, recommendation


st.sidebar.title("🛡️ SpamShield AI")
st.sidebar.write("Real-time email risk analysis tool.")
st.sidebar.divider()

st.sidebar.subheader("Detection Coverage")
st.sidebar.write("✅ Phishing")
st.sidebar.write("✅ Invoice fraud")
st.sidebar.write("✅ Fake document signing")
st.sidebar.write("✅ Dangerous attachments")
st.sidebar.write("✅ Social engineering")
st.sidebar.write("✅ Account verification scams")

st.sidebar.divider()
st.sidebar.caption("Built with Python, Streamlit, Pandas, Regex, and SQLite.")

st.markdown('<div class="main-title">🛡️ SpamShield AI</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="subtitle">Advanced real-time spam, phishing, and fraud email detection system.</div>',
    unsafe_allow_html=True
)

st.divider()

input_col, result_col = st.columns([1.4, 1])

with input_col:
    st.subheader("📩 Email Scanner")

    email_text = st.text_area(
        "Paste email content below:",
        height=360,
        placeholder="Paste suspicious email text here..."
    )

    scan_button = st.button(
        "🔍 Analyze Email",
        type="primary",
        use_container_width=True
    )

with result_col:
    st.subheader("🚦 Risk Analysis Result")

    if scan_button:
        if email_text.strip() == "":
            st.warning("Please paste an email message first.")
        else:
            result, level, score, reasons, recommendation = detect_fraud_email(email_text)

            if level == "high":
                st.markdown(
                    f"""
                    <div class="high-risk">
                        <h3>🚨 {result}</h3>
                        <p><b>Risk Score:</b> {score}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif level == "medium":
                st.markdown(
                    f"""
                    <div class="medium-risk">
                        <h3>⚠️ {result}</h3>
                        <p><b>Risk Score:</b> {score}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    f"""
                    <div class="low-risk">
                        <h3>✅ {result}</h3>
                        <p><b>Risk Score:</b> {score}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            progress_value = min(score / 15, 1.0)
            st.progress(progress_value)

            st.markdown("### Recommendation")
            st.info(recommendation)

            st.markdown("### Detected Warning Signs")

            if reasons:
                for reason in reasons:
                    st.markdown(
                        f'<div class="reason-box">• {reason}</div>',
                        unsafe_allow_html=True
                    )
            else:
                st.success("No strong warning signs detected.")

            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            preview = email_text[:100].replace("\n", " ") + "..."

            save_scan(
                scan_time=scan_time,
                result=result,
                risk_score=score,
                warnings_found=len(reasons),
                preview=preview
            )
    else:
        st.info("Paste an email and click Analyze Email to see results.")

st.divider()

st.subheader("📊 Detection Dashboard")

history_data = get_scan_history()

history_df = pd.DataFrame(
    history_data,
    columns=[
        "Time",
        "Result",
        "Risk Score",
        "Warnings Found",
        "Preview"
    ]
)

total = len(history_df)

if total > 0:
    high = len(history_df[history_df["Result"] == "High Risk Fraud / Phishing"])
    medium = len(history_df[history_df["Result"] == "Suspicious Email"])
    safe = len(history_df[history_df["Result"] == "Likely Safe"])
else:
    high = 0
    medium = 0
    safe = 0

m1, m2, m3, m4 = st.columns(4)

m1.metric("Total Scans", total)
m2.metric("High Risk", high)
m3.metric("Suspicious", medium)
m4.metric("Likely Safe", safe)

if not history_df.empty:
    st.subheader("📜 Scan History")

    st.dataframe(
        history_df,
        use_container_width=True
    )

    csv_data = history_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download Scan History as CSV",
        data=csv_data,
        file_name="spamshield_scan_history.csv",
        mime="text/csv",
        use_container_width=True
    )
else:
    st.info("No scan history yet.")