#  SpamShield AI

SpamShield AI is a real-time spam, phishing, and fraud email detection system built using Python and Streamlit.

The application analyzes pasted email content and assigns a fraud risk score based on suspicious patterns such as phishing attempts, invoice scams, fake document signing requests, dangerous attachments, account verification scams, and social engineering techniques.


##  Features

 Real-time email analysis  
 Fraud risk scoring system  
 Professional UI dashboard  
 Scan history tracking using SQLite database  
 Download scan history as CSV  
 Detection dashboard metrics  
 Phishing and social engineering detection  
 Safe vs suspicious email classification


##  Detection Coverage

SpamShield AI can identify patterns related to:

- Phishing emails
- Fake account verification requests
- Invoice and payment scams
- AdobeSign / DocuSign impersonation
- Dangerous file attachments (`.zip`, `.exe`, `.js`, `.bat`, `.vbs`)
- Social engineering attacks
- Urgency-based fraud attempts
- Suspicious sender/domain behavior


##  Tech Stack

- Python
- Streamlit
- SQLite
- Pandas
- Regular Expressions (Regex)

---

##  Project Structure

```text
spamshield-ai/
│
├── app.py
├── database.py
├── spamshield.db
├── train_model.py
├── spam_model.pkl
├── requirements.txt
├── README.md
│
└── screenshots/
    ├── phishing_detected.png
    └── safe_email.png